package proxy

import (
	"fmt"
	"time"

	"github.com/bnymnDev/agentgate/internal/canary"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
	"github.com/bnymnDev/agentgate/internal/taint"
)

// maxTainted bounds how many values a session remembers. A session that read
// more secrets than this is reading a secret store wholesale; the first
// values are kept.
const maxTainted = 1000

// tainted is what a session read that it should keep to itself.
type tainted struct {
	values   []string
	from     map[string]string // value -> where it was read
	detector *canary.Detector  // nil until something is tainted, rebuilt on change
}

func (st *sessionState) addTainted(values []string, from string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.taint.from == nil {
		st.taint.from = map[string]string{}
	}
	added := 0
	for _, v := range values {
		if _, ok := st.taint.from[v]; ok || len(st.taint.values) >= maxTainted {
			continue
		}
		st.taint.from[v] = from
		st.taint.values = append(st.taint.values, v)
		added++
	}
	if added > 0 {
		st.taint.detector = nil
	}
	return added
}

func (st *sessionState) findTainted(text string) (string, string, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.taint.values) == 0 {
		return "", "", false
	}
	if st.taint.detector == nil {
		cs := make([]canary.Canary, len(st.taint.values))
		for i, v := range st.taint.values {
			cs[i] = canary.Canary{ID: fmt.Sprint(i), Kind: "taint", Values: []string{v}}
		}
		st.taint.detector = canary.NewDetector(cs)
	}
	hit, ok := st.taint.detector.Find(text)
	if !ok {
		return "", "", false
	}
	v := hit.Canary.Values[0]
	return st.taint.from[v], hit.Encoding, true
}

// taintsFrom reports whether what a call or a read returned is private.
func (p *Proxy) taintsFrom(st *sessionState, what string, labels []string) bool {
	cfg := p.Config()
	return cfg.Taint.Enabled() && cfg.Taint.Private([]string{what}, labels)
}

// taint remembers the secret-looking values of a private result.
func (p *Proxy) taint(st *sessionState, text, from string) {
	cfg := p.Config()
	if n := st.addTainted(taint.Extract(text, cfg.Taint.MinLength), from); n > 0 {
		p.log.Info("session tainted: values from a private result are watched on their way out",
			"session", st.id, "from", from, "values", n)
	}
}

// taintHit reports a tainted value on its way out. In warn mode it is
// reported and let through.
func (p *Proxy) taintHit(st *sessionState, text string) (policy.Decision, bool) {
	cfg := p.Config()
	if !cfg.Taint.Enabled() {
		return policy.Decision{}, false
	}
	from, encoding, ok := st.findTainted(text)
	if !ok {
		return policy.Decision{}, false
	}
	how := "in plain text"
	if encoding != "plain" {
		how = encoding + "-encoded"
	}
	reason := fmt.Sprintf("taint: a value this session read from %s is leaving %s", from, how)
	d := policy.Decision{Action: policy.Action(cfg.Taint.Mode), RuleID: policy.RuleTaint, Reason: reason}
	p.log.Warn("tainted value leaving", "session", st.id, "from", from, "encoding", encoding, "mode", cfg.Taint.Mode)
	event := Event{Event: config.EventExfiltration, At: time.Now(), SessionID: st.id, Host: hostLabel(st), Decision: d, Message: reason}
	if cfg.Taint.Mode == "warn" {
		event.Decision = policy.Decision{Action: policy.ActionAllow, RuleID: policy.RuleTaint, Reason: reason + "; taint.mode is warn"}
		p.notify.emit(event)
		return policy.Decision{}, false
	}
	p.notify.emit(event)
	return d, true
}
