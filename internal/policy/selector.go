package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// selector is a compiled JSONPath-lite expression, the left hand side of a
// "when:" condition. The grammar is deliberately tiny:
//
//	args                     the whole arguments object
//	args.path                an object member
//	args.items[0]            an array element
//	args.items[*].sku        a member of every array element
//	tool                     the exposed tool name ("fs__write_file")
//	tool_name                the name the upstream server uses ("write_file")
//	upstream                 the upstream name ("fs")
//	annotations.destructive  what the server says about the tool (also
//	                         read_only, idempotent, open_world, title)
//	time.hour                when the call was made, local time (also
//	                         minute, weekday as "monday".."sunday")
//	args.{command,cmd}       the first of several members that exist:
//	                         braces list alternatives, any of which may match
//	host.name                the host that opened the session (also version)
//	session.labels           every label the session has picked up so far
//	session.label.<name>     whether the session carries that label: true
//	                         or false, never missing
//	session.called           every tool the session has already called
//	session.calls            how many calls the session has made
//	result.is_error          whether the tool reported an error, and
//	result.text              the text it returned; label rules only, since
//	                         a result exists only once the call has run
//
// Resolving a selector yields zero or more values: zero when the path is
// missing, more than one when a [*] wildcard fans out. An annotation the
// server did not set, and any time.* path on a call with no timestamp, are
// missing.
type selector struct {
	src   string
	root  string
	steps []step
	// field is the sub-path of an annotations.*, time.*, host.*, session.*
	// or result.* selector.
	field string
	// label is the name in session.label.<name>.
	label string
}

type step struct {
	// key is set for object members.
	key string
	// keys is set for a {a,b,c} alternation of object members.
	keys []string
	// index is set for [n]; wildcard is set for [*].
	index    int
	isIndex  bool
	wildcard bool
}

func compileSelector(src string) (*selector, error) {
	trimmed := strings.TrimSpace(src)
	if trimmed == "" {
		return nil, fmt.Errorf("empty condition path")
	}
	root, rest, _ := strings.Cut(trimmed, ".")
	// A subscript directly on the root ("args[0]") keeps the subscript in rest.
	if i := strings.IndexByte(root, '['); i >= 0 {
		rest = root[i:] + func() string {
			if rest == "" {
				return ""
			}
			return "." + rest
		}()
		root = root[:i]
	}
	sel := &selector{src: trimmed, root: root}
	switch root {
	case "args":
	case "host":
		switch rest {
		case "name", "version":
			sel.field = rest
			return sel, nil
		}
		return nil, fmt.Errorf("unknown host field %q in %q: use name or version", rest, src)
	case "session":
		switch {
		case rest == "labels", rest == "called", rest == "calls":
			sel.field = rest
			return sel, nil
		case strings.HasPrefix(rest, "label."):
			name := strings.TrimPrefix(rest, "label.")
			if !ValidLabel(name) {
				return nil, fmt.Errorf("invalid label name %q in %q", name, src)
			}
			sel.field, sel.label = "label", name
			return sel, nil
		}
		return nil, fmt.Errorf("unknown session field %q in %q: use labels, label.<name>, called or calls", rest, src)
	case "result":
		switch rest {
		case "is_error", "text":
			sel.field = rest
			return sel, nil
		}
		return nil, fmt.Errorf("unknown result field %q in %q: use is_error or text", rest, src)
	case "tool", "tool_name", "upstream":
		if rest != "" {
			return nil, fmt.Errorf("%q takes no sub-path in %q", root, src)
		}
		return sel, nil
	case "annotations":
		switch rest {
		case "read_only", "destructive", "idempotent", "open_world", "title":
			sel.field = rest
			return sel, nil
		}
		return nil, fmt.Errorf("unknown annotation %q in %q: use read_only, destructive, idempotent, open_world or title", rest, src)
	case "time":
		switch rest {
		case "hour", "minute", "weekday":
			sel.field = rest
			return sel, nil
		}
		return nil, fmt.Errorf("unknown time field %q in %q: use hour, minute or weekday", rest, src)
	default:
		return nil, fmt.Errorf("unknown condition root %q in %q: use args, tool, tool_name, upstream, annotations, time, host, session or result", root, src)
	}
	if rest == "" {
		return sel, nil
	}
	for _, seg := range splitPath(rest) {
		if seg == "" {
			return nil, fmt.Errorf("empty path segment in %q", src)
		}
		if strings.HasPrefix(seg, "{") {
			keys, subs, err := splitAlternation(seg, src)
			if err != nil {
				return nil, err
			}
			sel.steps = append(sel.steps, step{keys: keys})
			sel.steps = append(sel.steps, subs...)
			continue
		}
		name, subs, err := splitSubscripts(seg, src)
		if err != nil {
			return nil, err
		}
		if name != "" {
			sel.steps = append(sel.steps, step{key: name})
		}
		sel.steps = append(sel.steps, subs...)
	}
	return sel, nil
}

// splitSubscripts breaks "items[*][0]" into the member name and its subscripts.
func splitSubscripts(seg, src string) (string, []step, error) {
	open := strings.IndexByte(seg, '[')
	if open < 0 {
		return seg, nil, nil
	}
	name, rest := seg[:open], seg[open:]
	var steps []step
	for rest != "" {
		if rest[0] != '[' {
			return "", nil, fmt.Errorf("unexpected %q after subscript in %q", rest, src)
		}
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return "", nil, fmt.Errorf("unterminated subscript in %q", src)
		}
		body := rest[1:end]
		rest = rest[end+1:]
		if body == "*" {
			steps = append(steps, step{wildcard: true})
			continue
		}
		n, err := strconv.Atoi(body)
		if err != nil {
			return "", nil, fmt.Errorf("invalid subscript [%s] in %q: want a number or *", body, src)
		}
		steps = append(steps, step{index: n, isIndex: true})
	}
	return name, steps, nil
}

// resolve walks the call and returns every value the selector points at.
func (s *selector) resolve(call *Call) []any {
	switch s.root {
	case "tool":
		return []any{call.Tool}
	case "tool_name":
		return []any{call.ToolName}
	case "upstream":
		return []any{call.Upstream}
	case "annotations":
		return annotationValue(&call.Annotations, s.field)
	case "time":
		return timeValue(call.At, s.field)
	case "host":
		return hostValue(&call.Host, s.field)
	case "session":
		return sessionValue(call, s.field, s.label)
	case "result":
		if call.Result == nil {
			return nil
		}
		if s.field == "is_error" {
			return []any{call.Result.IsError}
		}
		return []any{call.Result.Text}
	}
	if call.Args == nil {
		return nil
	}
	current := []any{any(call.Args)}
	for _, st := range s.steps {
		next := make([]any, 0, len(current))
		for _, v := range current {
			next = appendStep(next, v, st)
		}
		if len(next) == 0 {
			return nil
		}
		current = next
	}
	return current
}

func appendStep(out []any, v any, st step) []any {
	switch {
	case len(st.keys) > 0:
		obj, ok := v.(map[string]any)
		if !ok {
			return out
		}
		for _, k := range st.keys {
			if child, ok := obj[k]; ok {
				out = append(out, child)
			}
		}
		return out
	case st.key != "":
		obj, ok := v.(map[string]any)
		if !ok {
			return out
		}
		child, ok := obj[st.key]
		if !ok {
			return out
		}
		return append(out, child)
	case st.wildcard:
		arr, ok := v.([]any)
		if !ok {
			return out
		}
		return append(out, arr...)
	case st.isIndex:
		arr, ok := v.([]any)
		if !ok {
			return out
		}
		i := st.index
		if i < 0 {
			i += len(arr)
		}
		if i < 0 || i >= len(arr) {
			return out
		}
		return append(out, arr[i])
	}
	return out
}

func (s *selector) String() string { return s.src }

func annotationValue(a *Annotations, field string) []any {
	var b *bool
	switch field {
	case "title":
		if a.Title == "" {
			return nil
		}
		return []any{a.Title}
	case "read_only":
		b = a.ReadOnly
	case "destructive":
		b = a.Destructive
	case "idempotent":
		b = a.Idempotent
	case "open_world":
		b = a.OpenWorld
	}
	if b == nil {
		return nil
	}
	return []any{*b}
}

func timeValue(at time.Time, field string) []any {
	if at.IsZero() {
		return nil
	}
	local := at.Local()
	switch field {
	case "hour":
		return []any{local.Hour()}
	case "minute":
		return []any{local.Minute()}
	case "weekday":
		return []any{weekdayName(local)}
	}
	return nil
}

// splitPath splits an argument path on the dots that separate members, but
// not on the commas and dots inside a {a,b} alternation.
func splitPath(rest string) []string {
	var (
		out   []string
		depth int
		start int
	)
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case '.':
			if depth == 0 {
				out = append(out, rest[start:i])
				start = i + 1
			}
		}
	}
	return append(out, rest[start:])
}

// splitAlternation parses "{command,cmd}[0]" into its member names and any
// subscripts that follow the closing brace.
func splitAlternation(seg, src string) ([]string, []step, error) {
	end := strings.IndexByte(seg, '}')
	if end < 0 {
		return nil, nil, fmt.Errorf("unterminated {alternation} in %q", src)
	}
	var keys []string
	for _, k := range strings.Split(seg[1:end], ",") {
		k = strings.TrimSpace(k)
		if k == "" {
			return nil, nil, fmt.Errorf("empty name in {alternation} in %q", src)
		}
		keys = append(keys, k)
	}
	rest := seg[end+1:]
	if rest == "" {
		return keys, nil, nil
	}
	name, subs, err := splitSubscripts(rest, src)
	if err != nil {
		return nil, nil, err
	}
	if name != "" {
		return nil, nil, fmt.Errorf("unexpected %q after {alternation} in %q", name, src)
	}
	return keys, subs, nil
}

func hostValue(h *Host, field string) []any {
	var v string
	switch field {
	case "name":
		v = h.Name
	case "version":
		v = h.Version
	}
	if v == "" {
		return nil
	}
	return []any{v}
}

func sessionValue(call *Call, field, label string) []any {
	switch field {
	case "calls":
		return []any{call.Counts.Session}
	case "labels":
		if len(call.Session.Labels) == 0 {
			return nil
		}
		out := make([]any, len(call.Session.Labels))
		for i, l := range call.Session.Labels {
			out[i] = l
		}
		return out
	case "label":
		// A session without the label is a fact, not a missing value, so
		// "session.label.reviewed: false" holds until the label is earned.
		return []any{call.Session.HasLabel(label)}
	case "called":
		if len(call.Session.Called) == 0 {
			return nil
		}
		out := make([]any, len(call.Session.Called))
		for i, t := range call.Session.Called {
			out[i] = t
		}
		return out
	}
	return nil
}
