package policy

import (
	"errors"
	"fmt"
	"sort"
)

// Money caps what tools cost, in a currency rather than calls or tokens.
// Two things cost money when an agent uses tools: the tokens a result puts
// in front of the model, and paid APIs behind some tools — a search, a
// geocoder, an image model — that charge per call. Both are priced here, and
// spending is capped per session and per day across every session on the
// machine.
type Money struct {
	// Currency is what the amounts are in. It is a label only; the default
	// is EUR.
	Currency string `yaml:"currency" json:"currency,omitempty"`
	// PerMillionTokens is the price of a million tokens of tool arguments
	// and results, which is what the model reads. Zero leaves tokens free.
	PerMillionTokens float64 `yaml:"per_million_tokens" json:"per_million_tokens,omitempty"`
	// PerCall prices calls to paid tools: tool patterns, as in rules, to the
	// price of one call. The first pattern that matches, in name order, wins.
	PerCall map[string]float64 `yaml:"per_call" json:"per_call,omitempty"`
	// PerSession caps one session's spending. Zero means unlimited.
	PerSession float64 `yaml:"per_session" json:"per_session,omitempty"`
	// PerDay caps the spending of every session together since local
	// midnight. Zero means unlimited.
	PerDay float64 `yaml:"per_day" json:"per_day,omitempty"`

	perCall []pricedPattern
}

type pricedPattern struct {
	pat   *pattern
	price float64
}

// Enabled reports whether anything costs money.
func (m *Money) Enabled() bool { return m.PerMillionTokens > 0 || len(m.PerCall) > 0 }

func (m *Money) compile() error {
	var errs []error
	if m.Currency == "" {
		m.Currency = "EUR"
	}
	for name, v := range map[string]float64{"per_million_tokens": m.PerMillionTokens, "per_session": m.PerSession, "per_day": m.PerDay} {
		if v < 0 {
			errs = append(errs, fmt.Errorf("policy.budget.money.%s: must not be negative", name))
		}
	}
	keys := make([]string, 0, len(m.PerCall))
	for k := range m.PerCall {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	m.perCall = nil
	for _, k := range keys {
		if m.PerCall[k] < 0 {
			errs = append(errs, fmt.Errorf("policy.budget.money.per_call[%s]: must not be negative", k))
			continue
		}
		pat, err := compilePattern(k)
		if err != nil {
			errs = append(errs, fmt.Errorf("policy.budget.money.per_call[%s]: %w", k, err))
			continue
		}
		m.perCall = append(m.perCall, pricedPattern{pat: pat, price: m.PerCall[k]})
	}
	if (m.PerSession > 0 || m.PerDay > 0) && !m.Enabled() {
		errs = append(errs, errors.New("policy.budget.money: a cap is set but nothing has a price; set per_million_tokens or per_call"))
	}
	return errors.Join(errs...)
}

// CallPrice is what calling the tool costs before any token is counted.
func (m *Money) CallPrice(call *Call) float64 {
	names := call.names()
	for _, p := range m.perCall {
		if p.pat.matchAny(names) {
			return p.price
		}
	}
	return 0
}

// Cost is what a forwarded call cost: its price plus its tokens.
func (m *Money) Cost(call *Call, tokens int) float64 {
	return m.CallPrice(call) + float64(tokens)*m.PerMillionTokens/1e6
}

// Format renders an amount in the currency.
func (m *Money) Format(v float64) string {
	cur := m.Currency
	if cur == "" {
		cur = "EUR"
	}
	return fmt.Sprintf("%.2f %s", v, cur)
}

// checkMoney stops a call the session or the day cannot pay for. A call
// whose own price would cross a cap is stopped before it is made; tokens are
// only known afterwards, so they are charged once spent.
func checkMoney(m *Money, call *Call) (Decision, bool) {
	if m.PerSession <= 0 && m.PerDay <= 0 {
		return Decision{}, false
	}
	price := m.CallPrice(call)
	over := func(spent, limit float64, what string) (Decision, bool) {
		if limit <= 0 {
			return Decision{}, false
		}
		switch {
		case spent >= limit:
			return Decision{Action: ActionDeny, RuleID: RuleBudget,
				Reason: fmt.Sprintf("budget: the %s budget of %s is spent", what, m.Format(limit))}, true
		case price > 0 && spent+price > limit+1e-9:
			return Decision{Action: ActionDeny, RuleID: RuleBudget,
				Reason: fmt.Sprintf("budget: this call costs %s and only %s of the %s budget is left", m.Format(price), m.Format(limit-spent), what)}, true
		}
		return Decision{}, false
	}
	if d, hit := over(call.Counts.Spent, m.PerSession, "session"); hit {
		return d, true
	}
	return over(call.Counts.SpentToday, m.PerDay, "daily")
}
