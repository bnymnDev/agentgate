// Package policy contains the agentgate rule model and its evaluator.
//
// Evaluation is deliberately pure: [Evaluate] takes a [Policy] and a [Call]
// and returns a [Decision]. It performs no I/O, reads no clock and touches no
// global state, so a decision can be reproduced from a recorded call at any
// later time (see the replay package). Everything a decision depends on — the
// time of the call, the session's counters, whether the gateway is frozen — is
// carried on the Call, put there by whoever asks.
package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Action is the verdict a rule can hand down.
type Action string

const (
	// ActionAllow forwards the call to the upstream server.
	ActionAllow Action = "allow"
	// ActionDeny answers the call with an MCP error result.
	ActionDeny Action = "deny"
	// ActionAsk suspends the call until a human approves or rejects it.
	ActionAsk Action = "ask"
)

// Valid reports whether a is one of the three known actions.
func (a Action) Valid() bool {
	switch a {
	case ActionAllow, ActionDeny, ActionAsk:
		return true
	}
	return false
}

// Mode is how a decision is applied.
type Mode string

const (
	// ModeEnforce applies decisions: a deny denies, an ask asks.
	ModeEnforce Mode = "enforce"
	// ModeShadow records what the policy would have done and forwards the call
	// anyway. It is how you test a policy against live traffic before you
	// trust it with live traffic.
	ModeShadow Mode = "shadow"
)

// Decision is the typed outcome of evaluating a call. Every decision carries a
// human-readable reason; decisions produced by a rule also carry its id.
type Decision struct {
	Action Action `json:"action"`
	Reason string `json:"reason"`
	// RuleID is the id of the rule that produced this decision. Hard stops
	// that are not rules — budgets, the loop guard, a freeze — use a fixed id
	// so that they can still be told apart in the audit log.
	RuleID string `json:"rule_id,omitempty"`
}

// Ids used for decisions that do not come from a rule in the rules list.
const (
	RuleFrozen    = "frozen"
	RuleLoopGuard = "loop-guard"
	RuleBudget    = "budget"
	RuleHoneypot  = "honeypot"
	// RuleQuarantine denies calls to a tool whose definition changed since
	// it was pinned, or that the definition scan flagged.
	RuleQuarantine = "quarantine"
	// RuleCanary denies a call that carries a canary token out.
	RuleCanary = "canary"
)

// Allowed reports whether the call may be forwarded without further ado.
func (d Decision) Allowed() bool { return d.Action == ActionAllow }

// String renders the decision the way the CLI and the audit log show it.
func (d Decision) String() string {
	if d.RuleID == "" {
		return fmt.Sprintf("%s: %s", d.Action, d.Reason)
	}
	return fmt.Sprintf("%s: %s (rule %s)", d.Action, d.Reason, d.RuleID)
}

// Policy is the "policy:" section of an agentgate config file.
type Policy struct {
	// Default is applied when no rule matches. Only allow and deny are
	// meaningful here; ask is rejected by Compile.
	Default Action `yaml:"default" json:"default"`
	// Mode is enforce (the default) or shadow.
	Mode Mode `yaml:"mode" json:"mode,omitempty"`
	// RedactResults applies the audit redaction patterns to tool results
	// before they reach the agent, not only before they reach the audit log.
	// It is the one place agentgate deliberately changes a result, and it is
	// off unless you turn it on.
	RedactResults bool      `yaml:"redact_results" json:"redact_results,omitempty"`
	Budget        Budget    `yaml:"budget" json:"budget"`
	LoopGuard     LoopGuard `yaml:"loop_guard" json:"loop_guard"`
	// Labels attach names to a session once a matching call has gone
	// through, so that later rules can ask what the session has done
	// ("session.label.untrusted-input"). See LabelsFor.
	Labels []*LabelRule `yaml:"labels" json:"labels,omitempty"`
	// Packs are named rule sets that ship with agentgate or live in a file
	// next to the config. Their rules are evaluated after the rules below, so
	// your own rules can always make an exception.
	Packs []PackRef `yaml:"packs" json:"packs,omitempty"`
	// Rules are evaluated top to bottom; the first match wins.
	Rules []*Rule `yaml:"rules" json:"rules"`

	// labelsReadResult is set by Compile when a label rule looks at the
	// result, so the proxy only extracts one when something will read it.
	labelsReadResult bool
}

// LabelsReadResult reports whether any label rule has a result.* condition.
func (p *Policy) LabelsReadResult() bool { return p != nil && p.labelsReadResult }

// LabelRule attaches a label to the session when a call it matches has been
// forwarded. It matches like a rule — tool pattern plus conditions — but has
// no action of its own.
type LabelRule struct {
	Label string     `yaml:"label" json:"label"`
	Tool  string     `yaml:"tool" json:"tool,omitempty"`
	When  Conditions `yaml:"when" json:"when,omitempty"`
	// Pack names the pack the label rule came from, if any.
	Pack string `yaml:"-" json:"pack,omitempty"`

	tool *pattern
}

// Budget caps what a single session may do. Every cap is a hard stop checked
// before the rules, so no rule can lift one.
type Budget struct {
	// CallsPerSession caps calls across every tool. Zero means unlimited.
	CallsPerSession int `yaml:"calls_per_session" json:"calls_per_session,omitempty"`
	// CallsPerTool caps calls per exposed tool name. A missing entry means
	// unlimited. Keys are matched with the same separator tolerance as rule
	// patterns, so "fs.write_file" also caps "fs__write_file".
	CallsPerTool map[string]int `yaml:"calls_per_tool" json:"calls_per_tool,omitempty"`
	// CallsPerMinute caps the rate: more than this many calls in any trailing
	// sixty seconds and the session is throttled. Zero means unlimited.
	CallsPerMinute int `yaml:"calls_per_minute" json:"calls_per_minute,omitempty"`
	// TokensPerSession caps the estimated tokens (arguments plus results)
	// a session may push through its tools. Zero means unlimited.
	TokensPerSession int `yaml:"tokens_per_session" json:"tokens_per_session,omitempty"`
}

// LoopGuard stops an agent that is stuck repeating itself.
type LoopGuard struct {
	// Repeats is how many times in a row the identical call — same tool, same
	// arguments — may be made before the next one is denied. Zero disables
	// the guard.
	Repeats int `yaml:"repeats" json:"repeats,omitempty"`
}

// Rule is a single entry of the "rules:" list.
type Rule struct {
	ID     string     `yaml:"id" json:"id"`
	Tool   string     `yaml:"tool" json:"tool,omitempty"`
	When   Conditions `yaml:"when" json:"when,omitempty"`
	Action Action     `yaml:"action" json:"action"`
	Reason string     `yaml:"reason" json:"reason,omitempty"`
	// Pack names the pack the rule came from; empty for your own rules.
	Pack string `yaml:"-" json:"pack,omitempty"`

	// tool holds the compiled form of Tool. It is populated by Compile so that
	// Evaluate never has to compile anything.
	tool *pattern
}

// Call is everything the evaluator knows about a pending tools/call request.
type Call struct {
	// Tool is the name as the downstream host sees it, including the upstream
	// prefix ("fs__write_file").
	Tool string `json:"tool"`
	// Upstream is the name of the upstream server that owns the tool.
	Upstream string `json:"upstream"`
	// ToolName is the name the upstream server itself uses ("write_file").
	ToolName string `json:"tool_name"`
	// Args is the decoded arguments object, or nil when the host sent none.
	Args map[string]any `json:"args,omitempty"`
	// Counts carries the session counters the budgets and the loop guard use.
	Counts Counts `json:"counts,omitzero"`
	// Annotations are the hints the upstream server attached to the tool.
	// They are the server's claims about itself, which is exactly as
	// trustworthy as the server.
	Annotations Annotations `json:"annotations,omitzero"`
	// At is when the call was made. The zero value means "unknown", and makes
	// every time.* condition false.
	At time.Time `json:"at,omitzero"`
	// Frozen is set when the gateway's kill switch is on.
	Frozen bool `json:"frozen,omitempty"`
	// Host is the MCP client that opened the session.
	Host Host `json:"host,omitzero"`
	// Session is what the session has done before this call.
	Session History `json:"session,omitzero"`
	// Result is what the upstream answered. It is only known once the call
	// has been forwarded, so only label rules get to look at it; Compile
	// rejects a result.* condition in a rule.
	Result *Result `json:"result,omitempty"`
}

// Result is the part of a tool result a label rule can match on.
type Result struct {
	// IsError is the result's isError flag: the tool ran and failed.
	IsError bool `json:"is_error,omitempty"`
	// Text is what the agent reads: the text content and embedded text
	// resources, one per line, or the structured content as JSON when there
	// is no text.
	Text string `json:"text,omitempty"`
}

// ResultFromJSON extracts a Result from a tools/call result as it travels on
// the wire, which is also how the audit log stores it. It returns nil for
// anything that does not parse, such as a result the audit log truncated.
func ResultFromJSON(raw []byte) *Result {
	if len(raw) == 0 {
		return nil
	}
	var r struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			Resource *struct {
				Text string `json:"text"`
			} `json:"resource"`
		} `json:"content"`
		Structured json.RawMessage `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil
	}
	var parts []string
	for _, c := range r.Content {
		switch {
		case c.Type == "text" && c.Text != "":
			parts = append(parts, c.Text)
		case c.Resource != nil && c.Resource.Text != "":
			parts = append(parts, c.Resource.Text)
		}
	}
	if len(parts) == 0 && len(r.Structured) > 0 && string(r.Structured) != "null" {
		parts = append(parts, string(r.Structured))
	}
	return &Result{IsError: r.IsError, Text: strings.Join(parts, "\n")}
}

// Host identifies the MCP client on the other end of a session, as it
// introduced itself.
type Host struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// History is the part of a session's past the evaluator may look at.
type History struct {
	// Labels are the labels the session has picked up, sorted.
	Labels []string `json:"labels,omitempty"`
	// Called lists the tools the session has already called, in both the
	// exposed and the canonical upstream.tool spelling.
	Called []string `json:"called,omitempty"`
}

// HasLabel reports whether the history carries a label.
func (h History) HasLabel(label string) bool {
	for _, l := range h.Labels {
		if l == label {
			return true
		}
	}
	return false
}

// Counts are the calls already recorded for this session, not counting the
// call being evaluated.
type Counts struct {
	// Session is the number of allowed calls so far.
	Session int `json:"session,omitempty"`
	// Tool is the number of allowed calls to this tool so far.
	Tool int `json:"tool,omitempty"`
	// LastMinute is the number of allowed calls in the trailing sixty seconds.
	LastMinute int `json:"last_minute,omitempty"`
	// Repeats is how many times in a row this identical call was just made.
	Repeats int `json:"repeats,omitempty"`
	// Tokens is the estimated number of tokens spent so far.
	Tokens int `json:"tokens,omitempty"`
}

// Annotations mirror the MCP tool annotations. A nil field means the server
// said nothing, which is different from saying false.
type Annotations struct {
	Title       string `json:"title,omitempty"`
	ReadOnly    *bool  `json:"read_only,omitempty"`
	Destructive *bool  `json:"destructive,omitempty"`
	Idempotent  *bool  `json:"idempotent,omitempty"`
	OpenWorld   *bool  `json:"open_world,omitempty"`
}

// names returns the aliases a rule pattern may match against: the name as
// exposed downstream and the canonical "upstream.tool" spelling. Matching both
// means a policy keeps working when the prefix separator is changed.
func (c *Call) names() []string {
	if c.Upstream == "" || c.ToolName == "" {
		return []string{c.Tool}
	}
	dotted := c.Upstream + "." + c.ToolName
	if dotted == c.Tool {
		return []string{c.Tool}
	}
	return []string{c.Tool, dotted}
}

// Evaluate applies p to call and returns the decision. It is pure: the same
// policy and call always produce the same decision.
//
// Order of operations:
//
//  1. the kill switch, because a frozen gateway does nothing else;
//  2. the loop guard;
//  3. budgets, because a budget is a hard cap the rules must not be able to lift;
//  4. rules, top to bottom, first match wins;
//  5. the default action.
//
// Mode is not applied here. A shadow-mode gateway still wants the real
// decision, so that it can record it; turning it into an allow is the
// caller's job.
func Evaluate(p *Policy, call *Call) Decision {
	if p == nil {
		return Decision{Action: ActionDeny, Reason: "no policy loaded"}
	}
	if call.Frozen {
		return Decision{
			Action: ActionDeny,
			Reason: "agentgate is frozen; run `agentgate unfreeze` to let calls through again",
			RuleID: RuleFrozen,
		}
	}
	if d, hit := checkLoop(&p.LoopGuard, call); hit {
		return d
	}
	if d, over := checkBudget(&p.Budget, call); over {
		return d
	}
	for _, r := range p.Rules {
		if r.matches(call) {
			return Decision{Action: r.Action, Reason: r.reason(), RuleID: r.ID}
		}
	}
	def := p.Default
	if def == "" {
		def = ActionAllow
	}
	return Decision{Action: def, Reason: "default " + string(def)}
}

func checkLoop(g *LoopGuard, call *Call) (Decision, bool) {
	if g.Repeats > 0 && call.Counts.Repeats >= g.Repeats {
		return Decision{
			Action: ActionDeny,
			Reason: fmt.Sprintf("loop guard: the identical call has been made %d times in a row; change the arguments or stop", call.Counts.Repeats),
			RuleID: RuleLoopGuard,
		}, true
	}
	return Decision{}, false
}

func checkBudget(b *Budget, call *Call) (Decision, bool) {
	if b.CallsPerSession > 0 && call.Counts.Session >= b.CallsPerSession {
		return Decision{
			Action: ActionDeny,
			Reason: fmt.Sprintf("budget: session limit of %d calls reached", b.CallsPerSession),
			RuleID: RuleBudget,
		}, true
	}
	if b.CallsPerMinute > 0 && call.Counts.LastMinute >= b.CallsPerMinute {
		return Decision{
			Action: ActionDeny,
			Reason: fmt.Sprintf("budget: rate limit of %d calls per minute reached, slow down", b.CallsPerMinute),
			RuleID: RuleBudget,
		}, true
	}
	if b.TokensPerSession > 0 && call.Counts.Tokens >= b.TokensPerSession {
		return Decision{
			Action: ActionDeny,
			Reason: fmt.Sprintf("budget: session limit of roughly %d tokens through tools reached", b.TokensPerSession),
			RuleID: RuleBudget,
		}, true
	}
	for _, key := range call.names() {
		limit, ok := b.CallsPerTool[key]
		if !ok {
			continue
		}
		if limit > 0 && call.Counts.Tool >= limit {
			return Decision{
				Action: ActionDeny,
				Reason: fmt.Sprintf("budget: limit of %d calls for %s reached", limit, key),
				RuleID: RuleBudget,
			}, true
		}
		break
	}
	return Decision{}, false
}

// matches reports whether the rule applies to call. A rule with neither tool
// nor when matches everything, which makes a bare "action: deny" rule a usable
// catch-all at the end of a list.
func (r *Rule) matches(call *Call) bool {
	if r.tool != nil && !r.tool.matchAny(call.names()) {
		return false
	}
	for _, cond := range r.When {
		if !cond.holds(call) {
			return false
		}
	}
	return true
}

func (r *Rule) reason() string {
	if r.Reason != "" {
		return r.Reason
	}
	if r.Tool != "" {
		return fmt.Sprintf("matched rule %s (%s)", r.ID, r.Tool)
	}
	return "matched rule " + r.ID
}

// LabelsFor returns the labels a call earns for its session: those of every
// label rule it matches, in the order the rules are written, without
// duplicates. It is pure, like Evaluate, and meant to be applied once the call
// has actually been forwarded, with call.Result set when there is one.
func LabelsFor(p *Policy, call *Call) []string {
	if p == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, lr := range p.Labels {
		if seen[lr.Label] || !lr.matches(call) {
			continue
		}
		seen[lr.Label] = true
		out = append(out, lr.Label)
	}
	return out
}

func (lr *LabelRule) matches(call *Call) bool {
	if lr.tool != nil && !lr.tool.matchAny(call.names()) {
		return false
	}
	for _, cond := range lr.When {
		if !cond.holds(call) {
			return false
		}
	}
	return true
}

// Names returns the spellings rule patterns are matched against: the exposed
// name and, when it differs, the canonical upstream.tool name. session.called
// holds both, so that either spelling works in a condition on it.
func (c *Call) Names() []string { return c.names() }

// ValidLabel reports whether s may be used as a label name: lower-case
// letters, digits, dashes and underscores, starting with a letter or digit.
func ValidLabel(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case (r == '-' || r == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}

// Weekday names as time.* conditions see them.
var weekdays = [...]string{"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"}

// weekdayName returns the lower-case English name of the day.
func weekdayName(t time.Time) string { return weekdays[t.Weekday()] }

// IsShadow reports whether the policy only observes.
func (p *Policy) IsShadow() bool { return strings.EqualFold(string(p.Mode), string(ModeShadow)) }
