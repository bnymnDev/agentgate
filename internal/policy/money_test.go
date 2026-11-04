package policy_test

import (
	"time"

	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/policy"
)

func TestMoneyBudget(t *testing.T) {
	p := mustCompile(t, `
default: allow
budget:
  money:
    per_million_tokens: 3
    per_call: {"search.*": 0.05, "search.images": 0.20}
    per_session: 1.00
    per_day: 5.00
`)
	m := &p.Budget.Money
	require.Equal(t, "EUR", m.Currency)
	web := &policy.Call{Tool: "search__web", Upstream: "search", ToolName: "web"}
	images := &policy.Call{Tool: "search__images", Upstream: "search", ToolName: "images"}
	require.InDelta(t, 0.05, m.CallPrice(web), 1e-9)
	require.InDelta(t, 0.05, m.CallPrice(images), 1e-9, "patterns are tried in name order: search.* before search.images")
	require.InDelta(t, 0.05+0.003, m.Cost(web, 1000), 1e-9)

	web.Counts = policy.Counts{Spent: 0.96}
	d := policy.Evaluate(p, web)
	require.Equal(t, policy.ActionDeny, d.Action)
	require.Equal(t, policy.RuleBudget, d.RuleID)
	require.Contains(t, d.Reason, "this call costs 0.05 EUR and only 0.04 EUR of the session budget is left")

	free := &policy.Call{Tool: "fs__read", Upstream: "fs", ToolName: "read", Counts: policy.Counts{Spent: 0.96}}
	require.Equal(t, policy.ActionAllow, policy.Evaluate(p, free).Action, "a free call still fits")
	free.Counts.Spent = 1.0
	require.Contains(t, policy.Evaluate(p, free).Reason, "the session budget of 1.00 EUR is spent")

	free.Counts = policy.Counts{SpentToday: 5.01}
	require.Contains(t, policy.Evaluate(p, free).Reason, "the daily budget of 5.00 EUR is spent")

	_, err := compile(t, "budget: {money: {per_session: 1}}")
	require.ErrorContains(t, err, "nothing has a price")
	_, err = compile(t, "budget: {money: {per_call: {'x': -1}}}")
	require.ErrorContains(t, err, "must not be negative")
}

func TestTrackerSpends(t *testing.T) {
	var tr policy.Tracker
	tr.Spend(0.25)
	tr.Spend(0.5)
	require.InDelta(t, 0.75, tr.Observe("x", "s", time.Now()).Spent, 1e-9)
}
