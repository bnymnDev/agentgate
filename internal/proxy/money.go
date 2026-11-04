package proxy

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// dailySpend is what every session on the machine has spent today. The
// audit log is the shared ledger: every gateway writes to it, so its sum
// since midnight is re-read every few seconds, and what this process spent
// since then is added on top.
type dailySpend struct {
	mu     sync.Mutex
	day    string
	base   float64
	baseAt time.Time
	local  float64
}

const spendRefresh = 15 * time.Second

// spentToday returns today's spending as it stands.
func (p *Proxy) spentToday(ctx context.Context, cfg *config.Config, now time.Time) float64 {
	m := &cfg.Policy.Budget.Money
	if m.PerDay <= 0 {
		return 0
	}
	d := &p.spend
	d.mu.Lock()
	defer d.mu.Unlock()
	day := now.Format(time.DateOnly)
	if day != d.day || now.Sub(d.baseAt) > spendRefresh {
		if p.store != nil {
			if base, err := ledgerSince(ctx, p.store, cfg, midnight(now)); err == nil {
				d.base, d.local = base, 0
			} else {
				p.log.Warn("money budget: cannot read today's spending from the audit log", "error", err)
			}
		} else if day != d.day {
			d.base, d.local = 0, 0
		}
		d.day, d.baseAt = day, now
	}
	return d.base + d.local
}

// spent records what a forwarded call cost.
func (p *Proxy) spent(amount float64) {
	if amount <= 0 {
		return
	}
	p.spend.mu.Lock()
	p.spend.local += amount
	p.spend.mu.Unlock()
}

func midnight(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// ledgerSince prices every call forwarded since a time with the current
// price list.
func ledgerSince(ctx context.Context, store *audit.Store, cfg *config.Config, since time.Time) (float64, error) {
	calls, err := store.ForwardedSince(ctx, since)
	if err != nil {
		return 0, err
	}
	total := 0.0
	for _, c := range calls {
		total += cfg.Policy.Budget.Money.Cost(CallOf(cfg, c.Upstream, c.Tool), c.TokensEst)
	}
	return total, nil
}

// CallOf rebuilds as much of a policy call as a recorded call allows: the
// exposed name, the upstream, and the server's own name for the tool when
// the exposed one carries the upstream's prefix.
func CallOf(cfg *config.Config, upstream, exposed string) *policy.Call {
	name := exposed
	if upstream != "" {
		name = strings.TrimPrefix(exposed, upstream+cfg.PrefixSeparator)
	}
	return &policy.Call{Tool: exposed, Upstream: upstream, ToolName: name}
}
