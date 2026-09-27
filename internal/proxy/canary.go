package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/canary"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/pinning"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// detector returns the canary detector, or nil when there are no canaries.
func (p *Proxy) detector() *canary.Detector {
	if p.canaries == nil {
		return nil
	}
	d := p.canaries.Detector()
	if d.Empty() {
		return nil
	}
	return d
}

// findCanary looks for a canary in a call's arguments, in the raw JSON and
// in its decoded strings, which undoes any escaping.
func (p *Proxy) findCanary(raw json.RawMessage, decoded map[string]any) (canary.Hit, bool) {
	d := p.detector()
	if d == nil || len(raw) == 0 {
		return canary.Hit{}, false
	}
	return d.Find(string(raw) + "\n" + canary.Strings(decoded))
}

// canaryTripped denies a call that carries a canary out, records it, tells
// the webhooks, and freezes the gateway if the config says so.
func (p *Proxy) canaryTripped(st *sessionState, b ToolBinding, args json.RawMessage, hit canary.Hit, started time.Time) *mcp.CallToolResult {
	cfg := p.Config()
	name := hit.Canary.ID
	if hit.Canary.Label != "" {
		name = hit.Canary.Label
	}
	how := ""
	if hit.Encoding != "plain" {
		how = ", " + hit.Encoding + "-encoded"
	}
	decision := policy.Decision{
		Action: policy.ActionDeny,
		RuleID: policy.RuleCanary,
		Reason: fmt.Sprintf("canary: this call carries the %s canary %s out%s. It is a fake credential nothing legitimate ever sends anywhere; whatever asked for this is trying to exfiltrate what the agent read",
			hit.Canary.Kind, name, how),
	}
	p.log.Error("canary token leaving",
		"session", st.id, "host", st.hostName, "tool", b.Exposed, "canary", name, "encoding", hit.Encoding)

	frozen := false
	if cfg.Canaries.Action == "freeze" {
		reason := fmt.Sprintf("canary %s sent to %s by %s (session %s)", name, b.Exposed, hostLabel(st), shortID(st.id))
		if err := p.Freeze(reason, "canary"); err != nil {
			p.log.Error("could not freeze the gateway", "error", err)
		} else {
			frozen = true
			decision.Reason += ". The gateway is now frozen"
		}
	}
	result := deniedResult(decision)
	p.record(st, &audit.Call{
		ID: audit.NewID(), SessionID: st.id, TS: started, Upstream: b.Upstream, Tool: b.Exposed, Args: args,
		Decision: decision.Action, RuleID: decision.RuleID, Reason: decision.Reason,
		Result: marshalResult(result), IsError: true, DurationMS: time.Since(started).Milliseconds(),
		CatalogHash: p.catalogHash(),
	})
	msg := fmt.Sprintf("exfiltration stopped: %s tried to send the %s canary %s out through %s%s",
		hostLabel(st), hit.Canary.Kind, name, b.Exposed, how)
	if frozen {
		msg += "\nThe gateway is frozen. Run `agentgate unfreeze` when you have looked."
	}
	p.notify.emit(Event{
		Event: config.EventExfiltration, At: started, SessionID: st.id, Host: hostLabel(st),
		Upstream: b.Upstream, Tool: b.Exposed, Decision: decision, Args: args, Message: msg,
	})
	return result
}

// inspectResult looks at what a tool returned, before anything is changed for
// the agent, and returns the labels agentgate attaches for it: canary-read
// when a canary came back, injection-suspected when the result carries text
// aimed at the model.
func (p *Proxy) inspectResult(st *sessionState, b ToolBinding, raw []byte) []string {
	res := policy.ResultFromJSON(raw)
	if res == nil || res.Text == "" {
		return nil
	}
	var labels []string
	if d := p.detector(); d != nil {
		if hit, ok := d.Find(res.Text); ok {
			labels = append(labels, policy.LabelCanaryRead)
			p.log.Warn("a canary came back in a tool result; its way out is watched",
				"session", st.id, "tool", b.Exposed, "canary", hit.Canary.ID)
		}
	}
	if findings := pinning.ScanResult(res.Text); len(findings) > 0 {
		labels = append(labels, policy.LabelInjectionSuspected)
		var lines []string
		for _, f := range findings {
			line := f.Detail
			if f.Excerpt != "" {
				line += fmt.Sprintf(": %q", truncateRunes(f.Excerpt, 200))
			}
			lines = append(lines, line)
		}
		p.log.Warn("tool result carries text aimed at the model",
			"session", st.id, "tool", b.Exposed, "findings", strings.Join(lines, "; "))
		p.notify.emit(Event{
			Event: config.EventInjection, SessionID: st.id, Host: hostLabel(st), Upstream: b.Upstream, Tool: b.Exposed,
			Decision: policy.Decision{Action: policy.ActionAllow, Reason: "the result was forwarded; the session is labelled " + policy.LabelInjectionSuspected},
			Message:  fmt.Sprintf("possible prompt injection in what %s returned to %s:\n%s", b.Exposed, hostLabel(st), strings.Join(lines, "\n")),
		})
	}
	return labels
}

// stripInvisible removes invisible and reordering characters from what the
// agent is about to read. It returns how many it removed.
func stripInvisible(res *mcp.CallToolResult) int {
	if res == nil {
		return 0
	}
	n := 0
	for i, c := range res.Content {
		switch t := c.(type) {
		case *mcp.TextContent:
			if out, k := pinning.StripInvisible(t.Text); k > 0 {
				clone := *t
				clone.Text = out
				res.Content[i] = &clone
				n += k
			}
		case *mcp.EmbeddedResource:
			if t.Resource != nil && t.Resource.Text != "" {
				if out, k := pinning.StripInvisible(t.Resource.Text); k > 0 {
					resource := *t.Resource
					resource.Text = out
					clone := *t
					clone.Resource = &resource
					res.Content[i] = &clone
					n += k
				}
			}
		}
	}
	if res.StructuredContent != nil {
		var k int
		res.StructuredContent, k = stripValue(res.StructuredContent)
		n += k
	}
	return n
}

func stripValue(v any) (any, int) {
	switch t := v.(type) {
	case string:
		return pinning.StripInvisible(t)
	case []any:
		n := 0
		out := make([]any, len(t))
		for i, e := range t {
			var k int
			out[i], k = stripValue(e)
			n += k
		}
		return out, n
	case map[string]any:
		n := 0
		out := make(map[string]any, len(t))
		for key, e := range t {
			var k int
			out[key], k = stripValue(e)
			n += k
		}
		return out, n
	}
	return v, 0
}

// registerDecoy advertises the decoy resource, whose content is the decoy
// files of every canary.
func (p *Proxy) registerDecoy(cfg *config.Config) {
	uri := cfg.Canaries.Resource
	if uri == "" || p.canaries == nil {
		return
	}
	p.catalog.mu.Lock()
	_, clash := p.catalog.resources[uri]
	already := p.catalog.decoy
	p.catalog.decoy = !clash
	p.catalog.mu.Unlock()
	if clash {
		p.log.Warn("the decoy resource URI is taken by a real resource; not registering the decoy", "uri", uri)
		return
	}
	if already {
		return
	}
	name := uri
	if i := strings.LastIndexAny(uri, "/\\"); i >= 0 && i < len(uri)-1 {
		name = uri[i+1:]
	}
	p.server.AddResource(&mcp.Resource{URI: uri, Name: name, MIMEType: "text/plain"},
		func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			var body strings.Builder
			for _, c := range p.canaries.List() {
				body.WriteString(c.Decoy())
			}
			if st, ok := p.sessions.Load(req.Session); ok {
				s := st.(*sessionState)
				s.mu.Lock()
				s.track.Earn(policy.LabelCanaryRead)
				s.mu.Unlock()
				p.log.Warn("decoy resource read", "session", s.id, "host", s.hostName, "uri", uri)
			}
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
				URI: uri, MIMEType: "text/plain", Text: body.String(),
			}}}, nil
		})
}

// keepsCanary reports whether text contains a canary, which redaction must
// leave alone: a decoy is there to be read.
func (p *Proxy) keepsCanary(text string) bool {
	d := p.detector()
	if d == nil {
		return false
	}
	_, ok := d.Find(text)
	return ok
}
