package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// registerHoneypots advertises the decoy tools. They look like any other tool
// to the host; only agentgate knows that nothing is behind them.
func (p *Proxy) registerHoneypots(cfg *config.Config) {
	p.catalog.mu.Lock()
	if p.catalog.honeypots == nil {
		p.catalog.honeypots = map[string]bool{}
	}
	registered := p.catalog.honeypots
	real := p.catalog.tools
	p.catalog.mu.Unlock()

	for _, h := range cfg.Honeypots.Tools {
		if _, clash := real[h.Name]; clash {
			p.log.Warn("honeypot name is taken by a real tool; not registering the decoy", "tool", h.Name)
			continue
		}
		if registered[h.Name] {
			continue
		}
		p.server.AddTool(&mcp.Tool{
			Name:        h.Name,
			Description: h.Description,
			InputSchema: map[string]any{"type": "object", "additionalProperties": true},
		}, p.honeypotHandler(h.Name))
		registered[h.Name] = true
		p.log.Debug("honeypot armed", "tool", h.Name)
	}
}

// honeypotHandler is what a decoy does when called: deny, record loudly,
// notify, and if configured, freeze the gateway.
func (p *Proxy) honeypotHandler(name string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cfg := p.Config()
		st := p.state(req.Session)
		now := time.Now()
		args := req.Params.Arguments

		decision := policy.Decision{
			Action: policy.ActionDeny,
			RuleID: policy.RuleHoneypot,
			Reason: fmt.Sprintf("honeypot: %s does not exist. Calling it means the agent is following instructions its operator never gave", name),
		}
		p.log.Error("honeypot tripped",
			"session", st.id, "host", st.hostName, "tool", name, "args", string(p.redactor().Redact(args)))

		frozen := false
		if cfg.Honeypots.Action == "freeze" {
			reason := fmt.Sprintf("honeypot %s tripped by %s (session %s)", name, hostLabel(st), shortID(st.id))
			if err := p.Freeze(reason, "honeypot"); err != nil {
				p.log.Error("could not freeze the gateway", "error", err)
			} else {
				frozen = true
				decision.Reason += ". The gateway is now frozen"
			}
		}

		result := deniedResult(decision)
		p.store.RecordCall(&audit.Call{
			ID: audit.NewID(), SessionID: st.id, TS: now,
			Upstream: "agentgate", Tool: name, Args: args,
			Decision: decision.Action, RuleID: decision.RuleID, Reason: decision.Reason,
			Result: marshalResult(result), IsError: true, DurationMS: time.Since(now).Milliseconds(),
		})
		p.notify.emit(Event{
			Event: config.EventHoneypot, At: now, SessionID: st.id, Host: hostLabel(st),
			Upstream: "agentgate", Tool: name, Decision: decision, Args: args,
			Message: honeypotMessage(name, st, args, frozen),
		})
		return result, nil
	}
}

func honeypotMessage(name string, st *sessionState, args json.RawMessage, frozen bool) string {
	msg := fmt.Sprintf("honeypot tripped: %s called %s", hostLabel(st), name)
	if len(args) > 0 && len(args) <= 400 {
		msg += " with " + string(args)
	}
	if frozen {
		msg += "\nThe gateway is frozen. Run `agentgate unfreeze` when you have looked."
	}
	return msg
}

func hostLabel(st *sessionState) string {
	if st.hostName == "" {
		return "an unknown host"
	}
	if st.hostVersion == "" {
		return st.hostName
	}
	return st.hostName + " " + st.hostVersion
}
