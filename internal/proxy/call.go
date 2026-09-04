package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/killswitch"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// toolHandler returns the downstream handler for one proxied tool.
func (p *Proxy) toolHandler(u *upstream, b ToolBinding) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return p.dispatch(ctx, u, b, req)
	}
}

// dispatch runs one tools/call through the policy and, if it survives, through
// to the upstream server.
func (p *Proxy) dispatch(ctx context.Context, u *upstream, b ToolBinding, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cfg := p.Config()
	st := p.state(req.Session)
	started := time.Now()

	args := req.Params.Arguments
	signature := b.Exposed + "\x00" + audit.Hash(args)
	call := &policy.Call{
		Tool:        b.Exposed,
		Upstream:    b.Upstream,
		ToolName:    b.Name,
		Args:        decodeArgs(args, p.log),
		Counts:      st.observe(b.Exposed, signature, started),
		Annotations: b.Annotations,
		At:          started,
		Frozen:      killswitch.Engaged(cfg.FreezeFile()),
	}
	decision := policy.Evaluate(&cfg.Policy, call)

	rec := &audit.Call{
		ID:        audit.NewID(),
		SessionID: st.id,
		TS:        started,
		Upstream:  b.Upstream,
		Tool:      b.Exposed,
		Args:      args,
	}
	event := Event{At: started, SessionID: st.id, Host: hostLabel(st), Upstream: b.Upstream, Tool: b.Exposed, Args: args}

	if decision.Action != policy.ActionAllow && cfg.Policy.IsShadow() {
		// Shadow mode: the record keeps the verdict, the call goes through.
		rec.Shadow = true
		rec.Decision, rec.RuleID, rec.Reason = decision.Action, decision.RuleID, decision.Reason
		p.log.Info("shadow: would have "+verb(decision.Action),
			"session", st.id, "tool", b.Exposed, "rule", decision.RuleID, "reason", decision.Reason)
		event.Event, event.Decision, event.Shadow = config.EventShadow, decision, true
		p.notify.emit(event)
		decision = policy.Decision{Action: policy.ActionAllow, RuleID: decision.RuleID,
			Reason: "shadow mode: would have " + verb(decision.Action) + " (" + decision.Reason + ")"}
	} else {
		if decision.Action == policy.ActionAsk {
			event.Event, event.Decision = config.EventAsk, decision
			p.notify.emit(event)
			decision = p.resolveAsk(ctx, st, b, args, decision)
		}
		rec.Decision, rec.RuleID, rec.Reason = decision.Action, decision.RuleID, decision.Reason
	}

	if decision.Action != policy.ActionAllow {
		rec.IsError = true
		rec.DurationMS = time.Since(started).Milliseconds()
		result := deniedResult(decision)
		rec.Result = marshalResult(result)
		p.store.RecordCall(rec)
		p.log.Info("call denied",
			"session", st.id, "tool", b.Exposed, "rule", decision.RuleID, "reason", decision.Reason)
		event.Event, event.Decision = config.EventDeny, decision
		p.notify.emit(event)
		return result, nil
	}

	p.log.Debug("call allowed",
		"session", st.id, "tool", b.Exposed, "rule", decision.RuleID, "reason", decision.Reason)

	timeout := cfg.Timeout(u.cfg)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := p.forward(callCtx, u, b, req)
	rec.DurationMS = time.Since(started).Milliseconds()

	switch {
	case err != nil && errors.Is(callCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil:
		// agentgate's own deadline fired. The host never asked for that, so it
		// gets a readable tool error instead of a dead connection.
		timeoutErr := fmt.Errorf("upstream %q did not answer within %s", b.Upstream, timeout)
		rec.IsError = true
		rec.Error = timeoutErr.Error()
		result = errorResult("agentgate: " + timeoutErr.Error())
		rec.Result = marshalResult(result)
		st.forwarded(b.Exposed, audit.TokensEst(args), started)
		p.store.RecordCall(rec)
		p.log.Warn("call timed out", "session", st.id, "tool", b.Exposed, "timeout", timeout.String())
		event.Event, event.Decision = config.EventError, policy.Decision{Action: policy.ActionAllow, Reason: timeoutErr.Error()}
		p.notify.emit(event)
		return result, nil
	case err != nil:
		// A genuine protocol error from the upstream is passed through as one.
		rec.IsError = true
		rec.Error = err.Error()
		st.forwarded(b.Exposed, audit.TokensEst(args), started)
		p.store.RecordCall(rec)
		p.log.Warn("call failed", "session", st.id, "tool", b.Exposed, "error", err)
		event.Event, event.Decision = config.EventError, policy.Decision{Action: policy.ActionAllow, Reason: err.Error()}
		p.notify.emit(event)
		return nil, err
	}

	if cfg.Policy.RedactResults {
		if n := p.redactResult(result); n > 0 {
			p.log.Info("redacted secrets from a tool result before the agent saw it",
				"session", st.id, "tool", b.Exposed, "replacements", n)
		}
	}

	rec.Result = marshalResult(result)
	rec.IsError = result != nil && result.IsError
	st.forwarded(b.Exposed, audit.TokensEst(args, rec.Result), started)
	p.store.RecordCall(rec)
	return result, nil
}

// verb is the past tense the shadow-mode messages use.
func verb(a policy.Action) string {
	switch a {
	case policy.ActionDeny:
		return "denied"
	case policy.ActionAsk:
		return "asked for approval"
	default:
		return "allowed"
	}
}

// redactResult applies the redaction patterns to what the agent is about to
// read. It rewrites text content, embedded text resources and the structured
// result; binary content is left alone. It returns how many replacements were
// made.
func (p *Proxy) redactResult(res *mcp.CallToolResult) int {
	if res == nil {
		return 0
	}
	r := p.redactor()
	if !r.Enabled() {
		return 0
	}
	n := 0
	for i, c := range res.Content {
		switch t := c.(type) {
		case *mcp.TextContent:
			if out := r.RedactString(t.Text); out != t.Text {
				n += strings.Count(out, audit.Placeholder) - strings.Count(t.Text, audit.Placeholder)
				clone := *t
				clone.Text = out
				res.Content[i] = &clone
			}
		case *mcp.EmbeddedResource:
			if t.Resource != nil && t.Resource.Text != "" {
				if out := r.RedactString(t.Resource.Text); out != t.Resource.Text {
					n += strings.Count(out, audit.Placeholder) - strings.Count(t.Resource.Text, audit.Placeholder)
					resource := *t.Resource
					resource.Text = out
					clone := *t
					clone.Resource = &resource
					res.Content[i] = &clone
				}
			}
		}
	}
	if res.StructuredContent != nil {
		raw, err := json.Marshal(res.StructuredContent)
		if err == nil {
			if out := r.Redact(raw); !bytes.Equal(out, raw) {
				var v any
				if json.Unmarshal(out, &v) == nil {
					n += strings.Count(string(out), audit.Placeholder) - strings.Count(string(raw), audit.Placeholder)
					res.StructuredContent = v
				}
			}
		}
	}
	return n
}

// forward sends the call upstream unchanged: same arguments, same _meta, same
// progress token.
func (p *Proxy) forward(ctx context.Context, u *upstream, b ToolBinding, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	session, err := u.conn()
	if err != nil {
		return nil, err
	}
	params := &mcp.CallToolParams{
		Name: b.Name,
		Meta: req.Params.Meta,
	}
	if len(req.Params.Arguments) > 0 {
		params.Arguments = req.Params.Arguments
	}
	return session.CallTool(ctx, params)
}

// resolveAsk turns an "ask" decision into allow or deny by consulting the
// approver.
func (p *Proxy) resolveAsk(ctx context.Context, st *sessionState, b ToolBinding, args json.RawMessage, decision policy.Decision) policy.Decision {
	cfg := p.Config()
	timeout := cfg.Approval.Timeout.Or(0)
	askCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		askCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	p.log.Info("approval required",
		"session", st.id, "tool", b.Exposed, "rule", decision.RuleID, "reason", decision.Reason)
	out, err := p.approver.Approve(askCtx, ApprovalRequest{
		SessionID: st.id,
		Upstream:  b.Upstream,
		Tool:      b.Exposed,
		ToolName:  b.Name,
		Args:      args,
		Decision:  decision,
		Timeout:   timeout,
	})
	if err != nil {
		return policy.Decision{
			Action: policy.ActionDeny,
			Reason: "approval required: " + err.Error(),
			RuleID: decision.RuleID,
		}
	}
	out.RuleID = decision.RuleID
	return out
}

// deniedResult is the answer a blocked call gets. It is a tool result, not a
// transport error, so the agent can read the reason and try something else.
func deniedResult(d policy.Decision) *mcp.CallToolResult {
	msg := "agentgate denied: " + d.Reason
	if d.RuleID != "" {
		msg += " (rule " + d.RuleID + ")"
	}
	return errorResult(msg)
}

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}

// decodeArgs turns the raw arguments into the map the evaluator walks. Numbers
// keep their exact spelling so that a gt/lt comparison sees what the host sent.
func decodeArgs(raw json.RawMessage, log logger) map[string]any {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var args map[string]any
	if err := dec.Decode(&args); err != nil {
		// Not an object: the policy simply sees no arguments. The call itself
		// is still forwarded verbatim.
		log.Debug("tool arguments are not a JSON object", "error", err)
		return nil
	}
	return args
}

type logger interface {
	Debug(msg string, args ...any)
}

func marshalResult(result *mcp.CallToolResult) json.RawMessage {
	if result == nil {
		return nil
	}
	b, err := json.Marshal(result)
	if err != nil {
		return nil
	}
	return b
}

// Forward sends a tools/call to the upstream that owns the tool, without
// consulting the policy. It exists for "agentgate replay", which evaluates the
// policy itself so that it can report what changed.
func (p *Proxy) Forward(ctx context.Context, exposed string, args json.RawMessage) (*mcp.CallToolResult, error) {
	u, b, ok := p.upstreamFor(exposed)
	if !ok {
		return nil, fmt.Errorf("no upstream offers a tool called %q", exposed)
	}
	session, err := u.conn()
	if err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, p.Config().Timeout(u.cfg))
	defer cancel()
	params := &mcp.CallToolParams{Name: b.Name}
	if len(args) > 0 {
		params.Arguments = args
	}
	return session.CallTool(callCtx, params)
}

// ForwardJSON is Forward with the result marshalled, which is the shape the
// replay package needs.
func (p *Proxy) ForwardJSON(ctx context.Context, exposed string, args json.RawMessage) (json.RawMessage, error) {
	result, err := p.Forward(ctx, exposed, args)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
