package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Severity of a lint finding.
type Severity string

const (
	// SeverityWarn is something that is probably not what was meant.
	SeverityWarn Severity = "warn"
	// SeverityInfo is worth knowing, and may well be intended.
	SeverityInfo Severity = "info"
)

// LintFinding is one thing policy lint noticed.
type LintFinding struct {
	Severity Severity `json:"severity"`
	// Rule is the id of the rule it is about; empty for the policy as a whole.
	Rule    string `json:"rule,omitempty"`
	Check   string `json:"check"`
	Message string `json:"message"`
}

// LintContext is what lint knows beyond the policy itself.
type LintContext struct {
	// Tools are the exposed and upstream.tool names the servers offer, when
	// known; a rule whose pattern matches none of them is reported.
	Tools []string
	// ApprovalMode is approval.mode from the config.
	ApprovalMode string
}

// builtinLabels are the labels agentgate attaches without a label rule.
var builtinLabels = map[string]bool{LabelCanaryRead: true, LabelInjectionSuspected: true}

// Lint looks for rules that cannot fire, rules that let more through than
// they seem to, and conditions that can never hold. The policy must be
// compiled.
func Lint(p *Policy, ctx LintContext) []LintFinding {
	var out []LintFinding
	add := func(sev Severity, rule, check, format string, args ...any) {
		out = append(out, LintFinding{Severity: sev, Rule: rule, Check: check, Message: fmt.Sprintf(format, args...)})
	}

	labels := map[string]bool{}
	for _, lr := range p.Labels {
		labels[lr.Label] = true
	}

	var asks, blocks int
	var own []*Rule
	for _, r := range p.Rules {
		switch r.Action {
		case ActionAsk:
			asks++
			blocks++
		case ActionDeny:
			blocks++
		}
		// Pack rules are reviewed where they ship; lint is about yours.
		if r.Pack == "" {
			own = append(own, r)
		}
	}
	for i, r := range own {
		// A rule behind an earlier rule that always matches its tools.
		for _, earlier := range own[:i] {
			if len(earlier.When) == 0 && covers(earlier, r) {
				add(SeverityWarn, r.ID, "unreachable", "never fires: %s comes first, matches every call to %s and has no conditions", earlier.ID, orAll(r.Tool))
				break
			}
		}
		if len(r.When) == 0 && (r.tool == nil || r.Tool == "*") && len(p.Packs) > 0 {
			add(SeverityWarn, r.ID, "packs-unreachable", "matches every call with no conditions, so no rule of the packs after it (%s) ever fires", packNames(p.Packs))
		}

		if len(ctx.Tools) > 0 && r.tool != nil && !r.tool.matchAny(ctx.Tools) {
			add(SeverityWarn, r.ID, "unknown-tool", "tool: %q matches none of the tools the servers offer; a typo, or a server that is not connected", r.Tool)
		}

		for _, c := range r.When {
			m := &c.Matcher
			if r.Action == ActionAllow && fansOut(c.Path) && positive(m) {
				add(SeverityWarn, r.ID, "allow-any-value", "%s fans out to several values, and one match is enough: a call where one value matches and another does not is allowed. Use deny rules with not_* matchers to fence in every value", c.Path)
			}
			if r.Action == ActionAllow && m.Regex != nil && !anchored(*m.Regex) {
				add(SeverityWarn, r.ID, "unanchored-allow", "%s: regex %q is not anchored, so it matches anywhere in the value; start it with ^", c.Path, *m.Regex)
			}
			for _, v := range []*string{m.Prefix, m.NotPrefix} {
				if v != nil && looksLikeDir(*v) {
					add(SeverityWarn, r.ID, "prefix-without-slash", "%s: %q also matches %s-something and %s.old; end it with a slash", c.Path, *v, *v, *v)
				}
			}
			if r.Action == ActionAllow && strings.HasPrefix(c.Path, "annotations.") {
				add(SeverityInfo, r.ID, "trusts-annotations", "allows on %s, which is what the server says about itself; a compromised server says whatever gets it through", c.Path)
			}
			if label, ok := strings.CutPrefix(c.Path, "session.label."); ok && !labels[label] && !builtinLabels[label] {
				add(SeverityWarn, r.ID, "unknown-label", "no label rule attaches %q, so this condition never changes", label)
			}
			if c.Path == "session.labels" {
				for _, v := range []*any{m.Includes, m.Excludes, m.Equals} {
					if v == nil {
						continue
					}
					if s, ok := (*v).(string); ok && !labels[s] && !builtinLabels[s] {
						add(SeverityWarn, r.ID, "unknown-label", "no label rule attaches %q, so this condition never changes", s)
					}
				}
			}
			if c.Path == "session.called" && m.NotEquals != nil {
				add(SeverityWarn, r.ID, "not-equals-on-a-list", "session.called: not_equals holds as soon as any other tool was called; to ask whether a tool was never called, use excludes")
			}
		}
	}

	if asks > 0 && ctx.ApprovalMode == "deny" {
		add(SeverityWarn, "", "ask-without-approvals", "%d rule(s) ask, but approval.mode is deny: every ask is a deny", asks)
	}
	b := p.Budget
	noBudget := b.CallsPerSession == 0 && b.CallsPerMinute == 0 && b.TokensPerSession == 0 && len(b.CallsPerTool) == 0
	if p.Default == ActionAllow && blocks == 0 && noBudget && p.LoopGuard.Repeats == 0 {
		add(SeverityInfo, "", "nothing-blocks", "default allow, no rule denies or asks and there is no budget: the policy only records. Try the baseline pack")
	}
	if p.IsShadow() {
		add(SeverityInfo, "", "shadow", "the policy is in shadow mode: decisions are recorded, nothing is blocked")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity == SeverityWarn && out[j].Severity != SeverityWarn })
	return out
}

// covers reports whether every call r's tool pattern can match is matched by
// earlier's pattern too.
func covers(earlier, r *Rule) bool {
	switch {
	case earlier.tool == nil:
		return true // no tool: every call
	case r.tool == nil:
		return false
	case earlier.Tool == "*" || earlier.Tool == r.Tool:
		return true
	case !strings.ContainsAny(r.Tool, "*?|/"):
		// A literal name: covered if the earlier pattern matches it in
		// either spelling.
		return earlier.tool.matchAny([]string{r.Tool, strings.ReplaceAll(r.Tool, ".", "__")})
	}
	return false
}

func packNames(refs []PackRef) string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Name)
	}
	return strings.Join(names, ", ")
}

func orAll(tool string) string {
	if tool == "" || tool == "*" {
		return "every tool"
	}
	return tool
}

// fansOut reports whether a path can resolve to more than one value.
func fansOut(path string) bool {
	return strings.Contains(path, "[*]") || strings.Contains(path, "{")
}

// positive reports whether a matcher allows by finding something, as
// opposed to by not finding it.
func positive(m *Matcher) bool {
	return m.Equals != nil || m.Regex != nil || m.Prefix != nil || m.In != nil || m.Gt != nil || m.Lt != nil
}

func anchored(re string) bool {
	re = strings.TrimPrefix(re, "(?i)")
	return strings.HasPrefix(re, "^") || strings.HasPrefix(re, `\A`)
}

var dirLike = regexp.MustCompile(`^(/|~/|[A-Za-z]:[\\/])[^*?]*[A-Za-z0-9_-]$`)

// looksLikeDir reports whether a prefix is a directory path without its
// trailing slash, like /home/me/repo.
func looksLikeDir(s string) bool {
	return dirLike.MatchString(s) && !strings.Contains(s[strings.LastIndexAny(s, `/\`)+1:], ".")
}
