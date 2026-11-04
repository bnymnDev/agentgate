package proxy

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bnymnDev/agentgate/internal/config"
)

// sharedLabels is what other sessions earned lately, for shared_labels:
// the audit log's view, re-read every few seconds, and what this process
// saw itself in between, which the log may not have yet.
type sharedLabels struct {
	mu     sync.Mutex
	fromDB map[string][]string
	readAt time.Time
	local  []localLabel
}

type localLabel struct {
	label, session string
	at             time.Time
}

const sharedRefresh = 5 * time.Second

// noteLabels remembers labels a session of this process just earned.
func (p *Proxy) noteLabels(cfg *config.Config, session string, labels []string, at time.Time) {
	if !cfg.SharedLabels.Enabled() {
		return
	}
	s := &p.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range labels {
		if slices.Contains(cfg.SharedLabels.Labels, l) {
			s.local = append(s.local, localLabel{label: l, session: session, at: at})
		}
	}
}

// inherit gives a session the shared labels other sessions earned within
// the window, and returns the ones it did not have.
func (p *Proxy) inherit(ctx context.Context, cfg *config.Config, st *sessionState, now time.Time) []string {
	sl := &cfg.SharedLabels
	if !sl.Enabled() {
		return nil
	}
	since := now.Add(-time.Duration(sl.Within))
	from := map[string]bool{}
	s := &p.shared
	s.mu.Lock()
	if p.store != nil && now.Sub(s.readAt) > sharedRefresh {
		if got, err := p.store.LabelsSince(ctx, since); err == nil {
			s.fromDB, s.readAt = got, now
		} else {
			p.log.Warn("shared labels: cannot read the audit log", "error", err)
		}
	}
	keep := s.local[:0]
	for _, l := range s.local {
		if l.at.After(since) {
			keep = append(keep, l)
			if l.session != st.id {
				from[l.label] = true
			}
		}
	}
	s.local = keep
	for _, l := range sl.Labels {
		for _, sess := range s.fromDB[l] {
			if sess != st.id {
				from[l] = true
			}
		}
	}
	s.mu.Unlock()
	if len(from) == 0 {
		return nil
	}
	labels := make([]string, 0, len(from))
	for l := range from {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	added := st.earn(labels...)
	if len(added) > 0 {
		p.log.Info("session picked up labels another session earned", "session", st.id, "labels", strings.Join(added, ","))
	}
	return added
}
