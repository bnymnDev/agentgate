package proxy

import (
	"time"

	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/flow"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// maxFlowPrints bounds the fingerprints a session keeps per flow: about a
// megabyte of text read from the flow's sources.
const maxFlowPrints = 200_000

// readFrom fingerprints a result for every flow it is a source of.
func (p *Proxy) readFrom(cfg *config.Config, st *sessionState, names, labels []string, text string) {
	if len(cfg.Flows) == 0 || text == "" {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for i := range cfg.Flows {
		f := &cfg.Flows[i]
		if !f.Source(names, labels) {
			continue
		}
		if st.flows == nil {
			st.flows = map[string]*flow.Set{}
		}
		set := st.flows[f.ID]
		if set == nil {
			set = flow.NewSet(maxFlowPrints)
			st.flows[f.ID] = set
		}
		set.Add(text)
	}
}

// flowHit reports a call that carries data out to a sink its flow forbids.
// In warn mode it is reported and let through.
func (p *Proxy) flowHit(cfg *config.Config, st *sessionState, names []string, args string) (policy.Decision, bool) {
	if len(cfg.Flows) == 0 {
		return policy.Decision{}, false
	}
	var hit *config.Flow
	st.mu.Lock()
	for i := range cfg.Flows {
		f := &cfg.Flows[i]
		if f.Sink(names) && st.flows[f.ID].Shares(args) {
			hit = f
			break
		}
	}
	st.mu.Unlock()
	if hit == nil {
		return policy.Decision{}, false
	}
	d := policy.Decision{Action: policy.Action(hit.Action), RuleID: policy.RuleFlow, Reason: hit.Reason}
	p.log.Warn("data flow contract", "session", st.id, "flow", hit.ID, "action", hit.Action)
	event := Event{Event: config.EventExfiltration, At: time.Now(), SessionID: st.id, Host: hostLabel(st), Decision: d, Message: hit.Reason}
	if hit.Action == "warn" {
		event.Decision = policy.Decision{Action: policy.ActionAllow, RuleID: policy.RuleFlow, Reason: hit.Reason + "; the flow's action is warn"}
		p.notify.emit(event)
		return policy.Decision{}, false
	}
	p.notify.emit(event)
	return d, true
}
