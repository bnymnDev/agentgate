package proxy

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/bnymnDev/agentgate/internal/behavior"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// behaviorCache holds the profile, read again when its file changes.
type behaviorCache struct {
	mu      sync.Mutex
	path    string
	stamp   fileStamp
	profile *behavior.Profile
}

func (p *Proxy) behaviorProfile(cfg *config.Config) *behavior.Profile {
	if !cfg.Behavior.Enabled() {
		return nil
	}
	c := &p.behavior
	c.mu.Lock()
	defer c.mu.Unlock()
	path := cfg.Behavior.Profile
	if st := stampOf(path); path != c.path || st != c.stamp {
		prof, err := behavior.Load(path)
		if err != nil {
			p.log.Warn("behavior: cannot read the profile; calls are not compared", "path", path, "error", err)
		}
		c.path, c.stamp, c.profile = path, st, prof
	}
	return c.profile
}

func (p *Proxy) toolProfile(cfg *config.Config, tool string) (*behavior.ToolProfile, behavior.Thresholds) {
	prof := p.behaviorProfile(cfg)
	th := behavior.Thresholds{MinCalls: cfg.Behavior.MinCalls, Factor: cfg.Behavior.Factor}
	if prof == nil {
		return nil, th
	}
	return prof.Tools[tool], th
}

// behaviorBefore checks a call's arguments against its tool's profile.
func (p *Proxy) behaviorBefore(cfg *config.Config, st *sessionState, tool string, args json.RawMessage) (policy.Decision, bool) {
	tp, th := p.toolProfile(cfg, tool)
	found := tp.Before(args, th)
	if len(found) == 0 {
		return policy.Decision{}, false
	}
	reason := "behavior: " + tool + " " + describe(found)
	p.reportAnomaly(st, tool, found, reason)
	if cfg.Behavior.Mode == "warn" {
		return policy.Decision{}, false
	}
	return policy.Decision{Action: policy.Action(cfg.Behavior.Mode), RuleID: policy.RuleBehavior, Reason: reason}, true
}

// behaviorAfter checks what a call did, and returns the label to add when
// it was outside the profile.
func (p *Proxy) behaviorAfter(cfg *config.Config, st *sessionState, tool string, result []byte, took time.Duration, labels []string) []string {
	tp, th := p.toolProfile(cfg, tool)
	found := tp.After(int64(len(result)), took.Milliseconds(), labels, th)
	if len(found) == 0 {
		return nil
	}
	p.reportAnomaly(st, tool, found, "behavior: "+tool+" "+describe(found))
	return []string{policy.LabelBehaviorAnomaly}
}

func describe(as []behavior.Anomaly) string {
	parts := make([]string, len(as))
	for i, a := range as {
		parts[i] = a.Detail
	}
	return strings.Join(parts, "; ")
}

func (p *Proxy) reportAnomaly(st *sessionState, tool string, found []behavior.Anomaly, reason string) {
	kinds := make([]string, len(found))
	for i, a := range found {
		kinds[i] = a.Kind
	}
	p.log.Warn("tool behaves unlike before", "session", st.id, "tool", tool, "anomalies", strings.Join(kinds, ","), "detail", reason)
	p.notify.emit(Event{Event: config.EventAnomaly, At: time.Now(), SessionID: st.id, Host: hostLabel(st), Tool: tool,
		Decision: policy.Decision{Action: policy.ActionAllow, RuleID: policy.RuleBehavior, Reason: reason}, Message: reason})
}
