package policy

import (
	"errors"
	"fmt"
)

// Compile validates the policy and precompiles every pattern and regex it
// contains, so that Evaluate can stay free of error paths. It must be called
// once after loading a policy; Evaluate on an uncompiled policy will not match
// any rule.
//
// All problems are reported at once, so "agentgate policy validate" can show a
// complete list instead of one error per run.
func (p *Policy) Compile() error {
	var errs []error
	if p.Default == "" {
		p.Default = ActionAllow
	}
	switch p.Default {
	case ActionAllow, ActionDeny:
	case ActionAsk:
		errs = append(errs, errors.New("policy.default: ask is not a valid default, use allow or deny"))
	default:
		errs = append(errs, fmt.Errorf("policy.default: unknown action %q", p.Default))
	}
	switch p.Mode {
	case "", ModeEnforce, ModeShadow:
		if p.Mode == "" {
			p.Mode = ModeEnforce
		}
	default:
		errs = append(errs, fmt.Errorf("policy.mode: unknown mode %q, use enforce or shadow", p.Mode))
	}
	if p.Budget.CallsPerSession < 0 {
		errs = append(errs, errors.New("policy.budget.calls_per_session: must not be negative"))
	}
	if p.Budget.CallsPerMinute < 0 {
		errs = append(errs, errors.New("policy.budget.calls_per_minute: must not be negative"))
	}
	if p.Budget.TokensPerSession < 0 {
		errs = append(errs, errors.New("policy.budget.tokens_per_session: must not be negative"))
	}
	if p.LoopGuard.Repeats < 0 {
		errs = append(errs, errors.New("policy.loop_guard.repeats: must not be negative"))
	}
	for tool, limit := range p.Budget.CallsPerTool {
		if limit < 0 {
			errs = append(errs, fmt.Errorf("policy.budget.calls_per_tool[%s]: must not be negative", tool))
		}
	}
	seen := make(map[string]int, len(p.Rules))
	for i, r := range p.Rules {
		where := fmt.Sprintf("policy.rules[%d]", i)
		if r.ID == "" {
			errs = append(errs, fmt.Errorf("%s: missing id", where))
		} else {
			if prev, dup := seen[r.ID]; dup {
				errs = append(errs, fmt.Errorf("%s: duplicate rule id %q, first used by policy.rules[%d]", where, r.ID, prev))
			}
			seen[r.ID] = i
			where = fmt.Sprintf("policy.rules[%d] (%s)", i, r.ID)
		}
		if !r.Action.Valid() {
			errs = append(errs, fmt.Errorf("%s: unknown action %q, want allow, deny or ask", where, r.Action))
		}
		pat, err := compilePattern(r.Tool)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", where, err))
		}
		r.tool = pat
		if r.Tool == "" && len(r.When) == 0 {
			errs = append(errs, fmt.Errorf("%s: rule has neither tool nor when and would match every call; say tool: \"*\" if that is intended", where))
		}
		for j := range r.When {
			if err := r.When[j].compile(); err != nil {
				errs = append(errs, fmt.Errorf("%s: when: %w", where, err))
			}
		}
	}
	return errors.Join(errs...)
}

// Summary is a short human-readable description of the policy, used by
// "agentgate policy validate" and the web UI.
func (p *Policy) Summary() string {
	var asks, denies, allows int
	for _, r := range p.Rules {
		switch r.Action {
		case ActionAllow:
			allows++
		case ActionDeny:
			denies++
		case ActionAsk:
			asks++
		}
	}
	out := fmt.Sprintf("default %s, %d rules (%d allow, %d deny, %d ask)",
		p.Default, len(p.Rules), allows, denies, asks)
	if p.IsShadow() {
		out += ", shadow mode"
	}
	return out
}
