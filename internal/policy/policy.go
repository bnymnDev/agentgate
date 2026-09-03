// Package policy contains the agentgate rule model and its evaluator.
//
// Evaluation is deliberately pure: [Evaluate] takes a [Policy] and a [Call]
// and returns a [Decision]. It performs no I/O, reads no clock and touches no
// global state, so a decision can be reproduced from a recorded call at any
// later time (see the replay package).
package policy

import (
	"fmt"
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

// Decision is the typed outcome of evaluating a call. Every decision carries a
// human-readable reason; decisions produced by a rule also carry its id.
type Decision struct {
	Action Action `json:"action"`
	Reason string `json:"reason"`
	// RuleID is the id of the rule that produced this decision, or "" when the
	// decision came from the default action or a budget.
	RuleID string `json:"rule_id,omitempty"`
}

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
	Budget  Budget `yaml:"budget" json:"budget"`
	// Rules are evaluated top to bottom; the first match wins.
	Rules []*Rule `yaml:"rules" json:"rules"`
}

// Budget caps how many tool calls a single session may make.
type Budget struct {
	// CallsPerSession caps calls across every tool. Zero means unlimited.
	CallsPerSession int `yaml:"calls_per_session" json:"calls_per_session,omitempty"`
	// CallsPerTool caps calls per exposed tool name. A missing entry means
	// unlimited. Keys are matched with the same separator tolerance as rule
	// patterns, so "fs.write_file" also caps "fs__write_file".
	CallsPerTool map[string]int `yaml:"calls_per_tool" json:"calls_per_tool,omitempty"`
}

// Rule is a single entry of the "rules:" list.
type Rule struct {
	ID     string     `yaml:"id" json:"id"`
	Tool   string     `yaml:"tool" json:"tool,omitempty"`
	When   Conditions `yaml:"when" json:"when,omitempty"`
	Action Action     `yaml:"action" json:"action"`
	Reason string     `yaml:"reason" json:"reason,omitempty"`

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
	// Counts carries the call counters used by the budget check.
	Counts Counts `json:"counts,omitzero"`
}

// Counts are the calls already recorded for this session, not counting the
// call being evaluated.
type Counts struct {
	Session int `json:"session,omitempty"`
	Tool    int `json:"tool,omitempty"`
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

// budgetKeys returns the keys under which a per-tool budget may be recorded.
func (c *Call) budgetKeys() []string { return c.names() }

// Evaluate applies p to call and returns the decision. It is pure: the same
// policy and call always produce the same decision.
//
// Order of operations:
//
//  1. budgets, because a budget is a hard cap the rules must not be able to lift;
//  2. rules, top to bottom, first match wins;
//  3. the default action.
func Evaluate(p *Policy, call *Call) Decision {
	if p == nil {
		return Decision{Action: ActionDeny, Reason: "no policy loaded"}
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

func checkBudget(b *Budget, call *Call) (Decision, bool) {
	if b.CallsPerSession > 0 && call.Counts.Session >= b.CallsPerSession {
		return Decision{
			Action: ActionDeny,
			Reason: fmt.Sprintf("budget: session limit of %d calls reached", b.CallsPerSession),
		}, true
	}
	for _, key := range call.budgetKeys() {
		limit, ok := b.CallsPerTool[key]
		if !ok {
			continue
		}
		if limit > 0 && call.Counts.Tool >= limit {
			return Decision{
				Action: ActionDeny,
				Reason: fmt.Sprintf("budget: limit of %d calls for %s reached", limit, key),
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
