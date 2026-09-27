// Package policytest runs policy tests: calls, the session they are made in,
// and the decisions they have to get.
//
// A test file sits next to the config and runs in CI with `agentgate test`,
// so that a change to a rule, a pack or a parameter cannot quietly let through
// what it was there to stop. Each test runs in a session of its own, through
// the same evaluator, session tracker and label rules the proxy uses.
package policytest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// File is a test file.
type File struct {
	Tests []Case `yaml:"tests"`
	// Path is where the file was read from.
	Path string `yaml:"-"`
}

// Case is one test. It is written in one of two forms: a call, the calls
// before it and what the call has to get; or steps, a whole session in
// which any call may carry what it has to get.
type Case struct {
	Name string `yaml:"name"`
	// Host is the host that opened the session, as name or name/version.
	Host string `yaml:"host"`
	// At is when the calls are made; empty means now.
	At string `yaml:"at"`
	// Labels are the labels the session carries before its first call.
	Labels []string `yaml:"labels"`

	// Before are the calls the session made first, in order.
	Before []Step `yaml:"before"`
	// Call is the call under test.
	Call *Step `yaml:"call"`
	// Expect is what the call has to get.
	Expect *Expect `yaml:"expect"`

	// Steps is the session, call by call.
	Steps []Step `yaml:"steps"`

	// Line is where the test starts in its file.
	Line int `yaml:"-"`
}

// Step is one call.
type Step struct {
	// Tool is the tool as the host sees it (fs__write_file), or as
	// upstream.tool (fs.write_file).
	Tool        string         `yaml:"tool"`
	Args        map[string]any `yaml:"args"`
	Annotations *Annotations   `yaml:"annotations"`
	// Result is what the call returned, for label rules that look at it.
	Result *Result `yaml:"result"`
	// At is when this call is made, if not when the test's calls are.
	At string `yaml:"at"`
	// Repeat makes the call this many times.
	Repeat int `yaml:"repeat"`
	// Expect is what the call has to get; in steps only.
	Expect *Expect `yaml:"expect"`

	// Line is where the step starts in its file.
	Line int `yaml:"-"`
}

// Annotations is what the server says about a tool.
type Annotations struct {
	Title       string `yaml:"title"`
	ReadOnly    *bool  `yaml:"read_only"`
	Destructive *bool  `yaml:"destructive"`
	Idempotent  *bool  `yaml:"idempotent"`
	OpenWorld   *bool  `yaml:"open_world"`
}

// Result is what a call returned.
type Result struct {
	Text    string `yaml:"text"`
	IsError bool   `yaml:"is_error"`
}

// Expect is what a call has to get: an action, and optionally the rule that
// decides, words the reason contains and labels the session carries after
// the call. In a file it is either just the action, or a mapping.
type Expect struct {
	Action policy.Action `yaml:"action" json:"action"`
	Rule   string        `yaml:"rule" json:"rule,omitempty"`
	Reason string        `yaml:"reason" json:"reason,omitempty"`
	Labels []string      `yaml:"labels" json:"labels,omitempty"`
}

// UnmarshalYAML takes `expect: deny` as well as the mapping.
func (e *Expect) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		e.Action = policy.Action(n.Value)
		return nil
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expect is an action (allow, deny or ask) or a mapping", n.Line)
	}
	for i := 0; i < len(n.Content); i += 2 {
		switch k := n.Content[i].Value; k {
		case "action", "rule", "reason", "labels":
		default:
			return fmt.Errorf("line %d: expect has no field %q; it takes action, rule, reason and labels", n.Content[i].Line, k)
		}
	}
	type plain Expect
	return n.Decode((*plain)(e))
}

// Load reads and checks a test file.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	f.Path = path
	return f, nil
}

// Parse reads and checks a test file's contents.
func Parse(raw []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("no tests: the file is empty")
		}
		return nil, err
	}
	noteLines(raw, &f)
	if len(f.Tests) == 0 {
		return nil, errors.New("no tests: add them as a list under tests")
	}
	var errs []error
	seen := map[string]int{}
	for i := range f.Tests {
		c := &f.Tests[i]
		where := fmt.Sprintf("tests[%d]", i)
		if c.Line > 0 {
			where = fmt.Sprintf("line %d", c.Line)
		}
		bad := func(format string, a ...any) {
			errs = append(errs, fmt.Errorf("%s: %s", where, fmt.Sprintf(format, a...)))
		}
		if c.Name == "" {
			bad("missing name")
		} else if prev, dup := seen[c.Name]; dup {
			bad("%q is also the name of the test on line %d", c.Name, prev)
		} else {
			seen[c.Name] = c.Line
		}
		if c.At != "" {
			if _, err := ParseWhen(c.At, time.Now()); err != nil {
				bad("at: %v", err)
			}
		}
		for _, l := range c.Labels {
			if !policy.ValidLabel(l) {
				bad("label %q: labels are lower-case letters, digits, - and _", l)
			}
		}

		if len(c.Steps) > 0 {
			if c.Call != nil || c.Expect != nil || len(c.Before) > 0 {
				bad("a test has either steps, or call and expect (with before), not both")
			}
			checked := false
			for j, s := range c.Steps {
				for _, p := range checkStep(s, true) {
					bad("steps[%d]: %s", j, p)
				}
				checked = checked || s.Expect != nil
			}
			if !checked {
				bad("no step has an expect, so there is nothing to test")
			}
			continue
		}
		switch {
		case c.Call == nil:
			bad("a test needs a call and what it has to get, or steps")
		case c.Call.Expect != nil:
			bad("expect goes next to call, not inside it")
		default:
			for _, p := range checkStep(*c.Call, false) {
				bad("call: %s", p)
			}
			if c.Call.Repeat != 0 {
				bad("repeat is for the calls in before; the call under test is made once")
			}
		}
		if c.Expect == nil {
			bad("expect needs an action: allow, deny or ask")
		} else {
			for _, p := range checkExpect(*c.Expect) {
				bad("%s", p)
			}
		}
		for j, s := range c.Before {
			if s.Expect != nil {
				bad("before[%d]: an expect in before is not checked; write the test as steps to check every call", j)
			}
			for _, p := range checkStep(s, false) {
				bad("before[%d]: %s", j, p)
			}
		}
	}
	return &f, errors.Join(errs...)
}

func checkStep(s Step, inSteps bool) []string {
	var out []string
	if s.Tool == "" {
		out = append(out, "needs a tool")
	}
	if s.Repeat < 0 {
		out = append(out, "repeat must not be negative")
	}
	if s.At != "" {
		if _, err := ParseWhen(s.At, time.Now()); err != nil {
			out = append(out, "at: "+err.Error())
		}
	}
	if inSteps && s.Expect != nil {
		if s.Repeat > 1 {
			out = append(out, "a step with an expect is made once; drop repeat, or the expect")
		}
		out = append(out, checkExpect(*s.Expect)...)
	}
	return out
}

func checkExpect(e Expect) []string {
	var out []string
	switch e.Action {
	case policy.ActionAllow, policy.ActionDeny, policy.ActionAsk:
	case "":
		out = append(out, "expect needs an action: allow, deny or ask")
	default:
		out = append(out, fmt.Sprintf("expect %q: want allow, deny or ask", e.Action))
	}
	for _, l := range e.Labels {
		if !policy.ValidLabel(l) {
			out = append(out, fmt.Sprintf("label %q: labels are lower-case letters, digits, - and _", l))
		}
	}
	return out
}

// noteLines records where each test and each of its steps start, for the
// report.
func noteLines(raw []byte, f *File) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Content) == 0 {
		return
	}
	value := func(m *yaml.Node, key string) *yaml.Node {
		if m == nil || m.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == key {
				return m.Content[i+1]
			}
		}
		return nil
	}
	tests := value(doc.Content[0], "tests")
	if tests == nil {
		return
	}
	for i, item := range tests.Content {
		if i >= len(f.Tests) {
			break
		}
		c := &f.Tests[i]
		c.Line = item.Line
		if steps := value(item, "steps"); steps != nil {
			for j, s := range steps.Content {
				if j < len(c.Steps) {
					c.Steps[j].Line = s.Line
				}
			}
		}
		if before := value(item, "before"); before != nil {
			for j, s := range before.Content {
				if j < len(c.Before) {
					c.Before[j].Line = s.Line
				}
			}
		}
		if call := value(item, "call"); call != nil && c.Call != nil {
			c.Call.Line = call.Line
		}
	}
}

// Options control a run.
type Options struct {
	Config *config.Config
	// ResultLabels returns the labels agentgate itself attaches to a
	// result (canary-read, injection-suspected), as the proxy would. Nil
	// attaches none.
	ResultLabels func(*policy.Result) []string
	// Now is when a test without at runs.
	Now time.Time
	// Match selects the tests to run by name; nil runs every test.
	Match *regexp.Regexp
}

// Outcome is how one test went.
type Outcome struct {
	Name   string `json:"name"`
	Line   int    `json:"line,omitempty"`
	Passed bool   `json:"passed"`
	// Got is the decision the last checked call got.
	Got policy.Decision `json:"got"`
	// Labels are the labels that call earned.
	Labels []string `json:"labels,omitempty"`
	// Expected is what the test asked of it.
	Expected Expect `json:"expected"`
	// Checked counts the calls that had something to get: one, or in a
	// test written as steps, every step with an expect.
	Checked int `json:"checked"`
	// Problems say what did not match.
	Problems []string `json:"problems,omitempty"`
}

// Run runs the tests of f against the policy in opts.Config.
func Run(f *File, opts Options) []Outcome {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	var out []Outcome
	for _, c := range f.Tests {
		if opts.Match != nil && !opts.Match.MatchString(c.Name) {
			continue
		}
		out = append(out, runCase(c, opts))
	}
	return out
}

func runCase(c Case, opts Options) Outcome {
	cfg := opts.Config
	o := Outcome{Name: c.Name, Line: c.Line}
	at := opts.Now
	if c.At != "" {
		t, err := ParseWhen(c.At, opts.Now)
		if err != nil {
			o.Problems = append(o.Problems, "at: "+err.Error())
			return o
		}
		at = t
	}
	var host policy.Host
	host.Name, host.Version, _ = strings.Cut(c.Host, "/")

	// The two forms are one: a call with its expect is the last step.
	steps, scenario := c.Steps, true
	if len(steps) == 0 {
		scenario = false
		steps = append(append([]Step(nil), c.Before...), *c.Call)
		steps[len(steps)-1].Expect = c.Expect
	}

	var track policy.Tracker
	track.Earn(c.Labels...)
	for i, s := range steps {
		when := at
		if s.At != "" {
			t, err := ParseWhen(s.At, opts.Now)
			if err != nil {
				o.Problems = append(o.Problems, fmt.Sprintf("step %d: at: %v", i+1, err))
				return o
			}
			when = t
		}
		for range max(s.Repeat, 1) {
			d, earned, err := play(cfg, &track, s, when, host, opts.ResultLabels)
			if err != nil {
				o.Problems = append(o.Problems, fmt.Sprintf("%s: %v", s.Tool, err))
				return o
			}
			if s.Expect == nil {
				continue
			}
			o.Checked++
			o.Got, o.Labels, o.Expected = d, earned, *s.Expect
			prefix := ""
			if scenario {
				prefix = fmt.Sprintf("step %d (%s", i+1, s.Tool)
				if s.Line > 0 {
					prefix += fmt.Sprintf(", line %d", s.Line)
				}
				prefix += "): "
			}
			for _, p := range compare(*s.Expect, d, track.History()) {
				o.Problems = append(o.Problems, prefix+p)
			}
		}
	}
	o.Passed = len(o.Problems) == 0
	return o
}

// play evaluates one call in the session, and lets it through unless it is
// denied: a call the policy would ask about counts as approved, because the
// calls of a test are what the session did.
func play(cfg *config.Config, track *policy.Tracker, s Step, at time.Time, host policy.Host,
	resultLabels func(*policy.Result) []string) (policy.Decision, []string, error) {
	call, argsJSON, err := buildCall(cfg, s)
	if err != nil {
		return policy.Decision{}, nil, err
	}
	call.At, call.Host = at, host
	call.Counts = track.Observe(call.Tool, call.Tool+"\x00"+audit.Hash(argsJSON), at)
	call.Session = track.History()
	d := policy.Evaluate(&cfg.Policy, call)
	if d.Action == policy.ActionDeny {
		return d, nil, nil
	}
	var labels []string
	var resultJSON []byte
	if s.Result != nil {
		res := &policy.Result{Text: s.Result.Text, IsError: s.Result.IsError}
		if resultLabels != nil {
			labels = append(labels, resultLabels(res)...)
		}
		if cfg.Policy.LabelsReadResult() {
			call.Result = res
		}
		resultJSON, _ = json.Marshal(map[string]any{
			"content": []map[string]string{{"type": "text", "text": s.Result.Text}},
			"isError": s.Result.IsError,
		})
	}
	labels = append(labels, policy.LabelsFor(&cfg.Policy, call)...)
	track.Forwarded(call, audit.TokensEst(argsJSON, resultJSON), at)
	return d, track.Earn(labels...), nil
}

// compare says how a decision differs from what was expected of it.
func compare(want Expect, got policy.Decision, after policy.History) []string {
	var out []string
	if got.Action != want.Action {
		why := got.Reason
		if got.RuleID != "" {
			why += " (rule " + got.RuleID + ")"
		}
		out = append(out, fmt.Sprintf("want %s, got %s: %s", want.Action, got.Action, why))
	}
	// A different action already names the rule that decided.
	if want.Rule != "" && got.RuleID != want.Rule && got.Action == want.Action {
		rule := got.RuleID
		if rule == "" {
			rule = "no rule (the default decided)"
		}
		out = append(out, fmt.Sprintf("want rule %s, got %s", want.Rule, rule))
	}
	if want.Reason != "" && !strings.Contains(got.Reason, want.Reason) {
		out = append(out, fmt.Sprintf("want a reason containing %q, got %q", want.Reason, got.Reason))
	}
	for _, l := range want.Labels {
		if !after.HasLabel(l) {
			out = append(out, fmt.Sprintf("want the session labelled %s after the call; it is not", l))
		}
	}
	return out
}

// buildCall turns a step into the call the evaluator sees, with its
// arguments as JSON the way they would arrive on the wire.
func buildCall(cfg *config.Config, s Step) (*policy.Call, []byte, error) {
	exposed, upstream, name := cfg.ResolveTool(s.Tool)
	var argsJSON []byte
	var args map[string]any
	if s.Args != nil {
		raw, err := json.Marshal(s.Args)
		if err != nil {
			return nil, nil, fmt.Errorf("args: %w", err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&args); err != nil {
			return nil, nil, fmt.Errorf("args: %w", err)
		}
		argsJSON = raw
	}
	call := &policy.Call{Tool: exposed, Upstream: upstream, ToolName: name, Args: args}
	if a := s.Annotations; a != nil {
		call.Annotations = policy.Annotations{Title: a.Title, ReadOnly: a.ReadOnly, Destructive: a.Destructive,
			Idempotent: a.Idempotent, OpenWorld: a.OpenWorld}
	}
	return call, argsJSON, nil
}

// DefaultPath is where the tests for a config live when none are named: next
// to it, with .test before the extension — agentgate.test.yaml for
// agentgate.yaml.
func DefaultPath(configPath string) string {
	for _, ext := range []string{".yaml", ".yml"} {
		if base, ok := strings.CutSuffix(configPath, ext); ok {
			return base + ".test" + ext
		}
	}
	return configPath + ".test.yaml"
}

// ParseWhen understands a few spellings of a point in time: RFC3339, a date
// with a time, a date, a time alone (on the day of now), or a weekday with a
// time (the next one from now, today included).
func ParseWhen(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	if t, err := time.ParseInLocation("15:04", s, time.Local); err == nil {
		return time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, time.Local), nil
	}
	fields := strings.Fields(strings.ToLower(s))
	if len(fields) == 2 {
		for d := time.Sunday; d <= time.Saturday; d++ {
			if strings.HasPrefix(strings.ToLower(d.String()), fields[0]) {
				clock, err := time.ParseInLocation("15:04", fields[1], time.Local)
				if err != nil {
					break
				}
				days := (int(d) - int(now.Weekday()) + 7) % 7
				day := now.AddDate(0, 0, days)
				return time.Date(day.Year(), day.Month(), day.Day(), clock.Hour(), clock.Minute(), 0, 0, time.Local), nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse %q; use RFC3339, \"2006-01-02 15:04\", \"15:04\" or \"friday 17:00\"", s)
}
