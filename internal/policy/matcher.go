package policy

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Conditions is the "when:" block of a rule. It keeps the order the conditions
// were written in so that validation errors and traces are stable.
type Conditions []Condition

// Condition pairs a selector with the matcher that must hold for it.
type Condition struct {
	Path    string  `json:"path"`
	Matcher Matcher `json:"matcher"`

	sel *selector
}

// Matcher is the right hand side of a condition. Exactly one of its fields may
// be set; which one is checked by Compile.
//
// A condition holds when *at least one* of the values its selector resolves to
// matches. For a plain path that is the obvious reading; for a wildcard path
// like args.items[*].sku it is also the safe one. Take
//
//	when: { "args.items[*].path": { not_prefix: "/srv/app/" } }
//	action: deny
//
// which denies as soon as a single item points outside the directory. Requiring
// every item to match would let a batch through because one entry in it was
// fine, and a guardrail that under-blocks is worse than one that over-blocks.
type Matcher struct {
	Equals    *any     `yaml:"equals" json:"equals,omitempty"`
	NotEquals *any     `yaml:"not_equals" json:"not_equals,omitempty"`
	Regex     *string  `yaml:"regex" json:"regex,omitempty"`
	Prefix    *string  `yaml:"prefix" json:"prefix,omitempty"`
	NotPrefix *string  `yaml:"not_prefix" json:"not_prefix,omitempty"`
	In        []any    `yaml:"in" json:"in,omitempty"`
	Gt        *float64 `yaml:"gt" json:"gt,omitempty"`
	Lt        *float64 `yaml:"lt" json:"lt,omitempty"`
	Exists    *bool    `yaml:"exists" json:"exists,omitempty"`

	re *regexp.Regexp
}

var matcherKeys = map[string]bool{
	"equals": true, "not_equals": true, "regex": true, "prefix": true,
	"not_prefix": true, "in": true, "gt": true, "lt": true, "exists": true,
}

// UnmarshalYAML accepts the full mapping form as well as two shorthands:
//
//	args.dryRun: false          equals
//	args.env: [prod, staging]   in
func (m *Matcher) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i].Value
			if !matcherKeys[key] {
				return fmt.Errorf("line %d: unknown matcher %q", node.Content[i].Line, key)
			}
		}
		type raw Matcher
		var r raw
		if err := node.Decode(&r); err != nil {
			return err
		}
		*m = Matcher(r)
		return nil
	case yaml.SequenceNode:
		var vals []any
		if err := node.Decode(&vals); err != nil {
			return err
		}
		m.In = vals
		return nil
	default:
		var v any
		if err := node.Decode(&v); err != nil {
			return err
		}
		m.Equals = &v
		return nil
	}
}

// UnmarshalYAML preserves the order of the conditions in the file.
func (c *Conditions) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: when: must be a mapping of path to matcher", node.Line)
	}
	out := make(Conditions, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		cond := Condition{Path: node.Content[i].Value}
		if err := node.Content[i+1].Decode(&cond.Matcher); err != nil {
			return fmt.Errorf("%s: %w", cond.Path, err)
		}
		out = append(out, cond)
	}
	*c = out
	return nil
}

// compile validates the matcher and precompiles its regex.
func (c *Condition) compile() error {
	sel, err := compileSelector(c.Path)
	if err != nil {
		return err
	}
	c.sel = sel
	return c.Matcher.compile(c.Path)
}

func (m *Matcher) compile(path string) error {
	n := 0
	for _, set := range []bool{
		m.Equals != nil, m.NotEquals != nil, m.Regex != nil, m.Prefix != nil,
		m.NotPrefix != nil, m.In != nil, m.Gt != nil, m.Lt != nil, m.Exists != nil,
	} {
		if set {
			n++
		}
	}
	switch {
	case n == 0:
		return fmt.Errorf("%s: matcher is empty, expected one of equals, not_equals, regex, prefix, not_prefix, in, gt, lt, exists", path)
	case n > 1 && (m.Gt == nil || m.Lt == nil || n != 2):
		return fmt.Errorf("%s: matcher sets %d conditions, expected exactly one (gt+lt may be combined)", path, n)
	}
	if m.Regex != nil {
		re, err := regexp.Compile(*m.Regex)
		if err != nil {
			return fmt.Errorf("%s: invalid regex %q: %w", path, *m.Regex, err)
		}
		m.re = re
	}
	return nil
}

// holds reports whether the condition is satisfied by the call.
func (c *Condition) holds(call *Call) bool {
	if c.sel == nil {
		return false
	}
	values := c.sel.resolve(call)
	m := &c.Matcher
	if m.Exists != nil {
		return (len(values) > 0) == *m.Exists
	}
	// "Missing path -> condition false" holds for every other matcher,
	// the negative ones included: there is nothing to make a claim about.
	// Use exists: false to match on absence.
	for _, v := range values {
		if m.matchOne(v) {
			return true
		}
	}
	return false
}

func (m *Matcher) matchOne(v any) bool {
	switch {
	case m.Equals != nil:
		return jsonEqual(v, *m.Equals)
	case m.NotEquals != nil:
		return !jsonEqual(v, *m.NotEquals)
	case m.Prefix != nil:
		return strings.HasPrefix(stringify(v), *m.Prefix)
	case m.NotPrefix != nil:
		return !strings.HasPrefix(stringify(v), *m.NotPrefix)
	case m.re != nil:
		return m.re.MatchString(stringify(v))
	case m.In != nil:
		for _, want := range m.In {
			if jsonEqual(v, want) {
				return true
			}
		}
		return false
	case m.Gt != nil || m.Lt != nil:
		f, ok := toFloat(v)
		if !ok {
			return false
		}
		if m.Gt != nil && !(f > *m.Gt) {
			return false
		}
		if m.Lt != nil && !(f < *m.Lt) {
			return false
		}
		return true
	}
	return false
}

// jsonEqual compares two decoded JSON/YAML values. Numbers compare by value,
// so 0 from YAML and 0.0 from JSON are the same thing; everything else is
// compared on its canonical JSON encoding, which handles nested objects.
func jsonEqual(a, b any) bool {
	if af, ok := toFloat(a); ok {
		if bf, ok := toFloat(b); ok {
			return af == bf
		}
		return false
	}
	as, aIsStr := a.(string)
	bs, bIsStr := b.(string)
	if aIsStr || bIsStr {
		return aIsStr && bIsStr && as == bs
	}
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ab) == string(bb)
}

// stringify renders a value for the string matchers. Scalars keep their natural
// spelling; objects and arrays are rendered as JSON so that a regex can still
// be pointed at a whole subtree.
func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case json.Number:
		return t.String()
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int32:
		return float64(t), true
	case int64:
		return float64(t), true
	case uint64:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	}
	return 0, false
}
