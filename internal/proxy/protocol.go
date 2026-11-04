package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/canary"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/pinning"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// A server can ask the host for two things in the middle of a call: to have
// the host's model answer something (sampling), and to ask the user for input
// (elicitation). Both are ways in: what a server writes into a sampling
// request reaches the model unfiltered, and an elicitation can ask the user
// for a token. Both are also ways out: the model's answer and the user's
// input go back to the server.
//
// On protocol 2026-07-28 such a request travels inside the call's result
// ("input required"), and the answer inside the retried call. agentgate lets
// both pass through unchanged — the upstream clients do not answer for the
// host — and looks at them on the way: the request is scanned and put to
// policy.sampling or policy.elicitation, the answer is checked for canaries
// and tainted values like any argument. Servers on older protocols send the
// request on its own; clientOptions installs handlers that put it through the
// same checks and pass it to the host session the call came from.

// inputRequest is one request of a server to the host.
type inputRequest struct {
	id   string
	kind string // policy.RuleSampling or policy.RuleElicitation
	// text is everything in the request a person or a model would read.
	text string
	// credential is set when an elicitation asks the user for something
	// that looks like a secret.
	credential string
}

func describeInputRequests(m mcp.InputRequestMap) []inputRequest {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []inputRequest
	for _, id := range ids {
		r := describeInputRequest(id, m[id])
		if r.kind != "" {
			out = append(out, r)
		}
	}
	return out
}

func describeInputRequest(id string, req any) inputRequest {
	r := inputRequest{id: id, text: stringsOf(req)}
	switch p := req.(type) {
	case *mcp.CreateMessageParams, *mcp.CreateMessageWithToolsParams:
		r.kind = policy.RuleSampling
	case *mcp.ElicitParams:
		r.kind = policy.RuleElicitation
		r.credential = credentialField(p.RequestedSchema)
	}
	return r
}

// stringsOf is every string in a value, as its JSON has them.
func stringsOf(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return ""
	}
	return canary.Strings(decoded)
}

var credentialName = regexp.MustCompile(`(?i)(pass(word|phrase)?|secret|token|api[_-]?key|credential|private[_-]?key|otp|2fa|mfa|pin\b|cvv|card[_-]?number|seed|mnemonic)`)

// credentialField names the first field of an elicitation's schema that asks
// for something that looks like a secret.
func credentialField(schema any) string {
	raw, err := json.Marshal(schema)
	if err != nil {
		return ""
	}
	var s struct {
		Properties map[string]struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Format      string `json:"format"`
		} `json:"properties"`
	}
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	names := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		f := s.Properties[name]
		if f.Format == "password" || credentialName.MatchString(name+" "+f.Title+" "+f.Description) {
			return name
		}
	}
	return ""
}

// inputRequestsDecision puts a server's requests to the host through the
// policy: the strictest setting among the kinds asked for decides, and a
// request the scan flags is never let through without a human when the
// setting would allow it silently. It also returns the labels the session
// earns: a request with text aimed at the model is an injection attempt like
// one in a result.
func (p *Proxy) inputRequestsDecision(ctx context.Context, st *sessionState, upstream, tool string, reqs []inputRequest) (policy.Decision, []string) {
	cfg := p.Config()
	decision := policy.Decision{Action: policy.ActionAllow}
	var labels []string
	for _, r := range reqs {
		action := cfg.Policy.Sampling
		what := "have the host's model answer"
		if r.kind == policy.RuleElicitation {
			action = cfg.Policy.Elicitation
			what = "ask the user"
		}
		reason := fmt.Sprintf("%s asks to %s: %s", upstream, what, truncateRunes(strings.Join(strings.Fields(pinning.VisibleText(r.text)), " "), 120))
		if r.credential != "" {
			reason = fmt.Sprintf("%s asks the user for something that looks like a secret (%q)", upstream, r.credential)
			p.log.Warn("server asks the user for a credential", "session", st.id, "upstream", upstream, "field", r.credential)
		}
		if findings := pinning.ScanResult(r.text); len(findings) > 0 {
			labels = append(labels, policy.LabelInjectionSuspected)
			f := findings[0]
			p.log.Warn("request to the host carries text aimed at the model", "session", st.id, "upstream", upstream, "kind", r.kind, "finding", f.Detail)
			p.notify.emit(Event{Event: config.EventInjection, At: time.Now(), SessionID: st.id, Host: hostLabel(st), Upstream: upstream, Tool: tool,
				Decision: policy.Decision{Action: action, RuleID: r.kind, Reason: f.Detail},
				Message:  fmt.Sprintf("%s's %s request %s: %q", upstream, r.kind, f.Detail, truncateRunes(pinning.Reveal(f.Excerpt), 200))})
		}
		if rank(action) > rank(decision.Action) {
			decision = policy.Decision{Action: action, RuleID: r.kind, Reason: reason}
		} else if decision.RuleID == "" {
			decision.RuleID, decision.Reason = r.kind, reason
		}
	}
	if decision.Action == policy.ActionAllow {
		return decision, labels
	}
	if cfg.Policy.IsShadow() {
		p.log.Info("shadow: would have "+verb(decision.Action), "session", st.id, "upstream", upstream, "rule", decision.RuleID, "reason", decision.Reason)
		return policy.Decision{Action: policy.ActionAllow, RuleID: decision.RuleID,
			Reason: "shadow mode: would have " + verb(decision.Action) + " (" + decision.Reason + ")"}, labels
	}
	if decision.Action == policy.ActionAsk {
		decision = p.resolveAsk(ctx, st, ToolBinding{Exposed: tool + " (" + decision.RuleID + ")", Name: decision.RuleID, Upstream: upstream}, nil, decision)
	}
	return decision, labels
}

func rank(a policy.Action) int {
	switch a {
	case policy.ActionDeny:
		return 2
	case policy.ActionAsk:
		return 1
	}
	return 0
}

// egressHit says why something on its way to a server must not leave:
// a canary or a tainted value in it.
func (p *Proxy) egressHit(st *sessionState, raw []byte) (policy.Decision, bool) {
	if len(raw) == 0 {
		return policy.Decision{}, false
	}
	var decoded any
	_ = json.Unmarshal(raw, &decoded)
	if d := p.detector(); d != nil {
		if hit, ok := d.Find(string(raw) + "\n" + canary.Strings(decoded)); ok {
			name := hit.Canary.ID
			if hit.Canary.Label != "" {
				name = hit.Canary.Label
			}
			return policy.Decision{Action: policy.ActionDeny, RuleID: policy.RuleCanary,
				Reason: fmt.Sprintf("canary: %s leaving %s-encoded in an answer to the server; it is a fake credential that nothing legitimate ever sends anywhere", name, hit.Encoding)}, true
		}
	}
	if d, ok := p.taintHit(st, string(raw)+"\n"+canary.Strings(decoded)); ok {
		return d, true
	}
	return policy.Decision{}, false
}

// hostSessions tracks which host session each upstream is serving a call
// for, so a request an older server sends on its own reaches the host that
// made the call.
type hostSessions struct {
	mu       sync.Mutex
	inflight map[string]map[*mcp.ServerSession]int
}

func (h *hostSessions) enter(upstream string, ss *mcp.ServerSession) func() {
	if ss == nil {
		return func() {}
	}
	h.mu.Lock()
	if h.inflight == nil {
		h.inflight = map[string]map[*mcp.ServerSession]int{}
	}
	if h.inflight[upstream] == nil {
		h.inflight[upstream] = map[*mcp.ServerSession]int{}
	}
	h.inflight[upstream][ss]++
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.inflight[upstream][ss]--; h.inflight[upstream][ss] <= 0 {
			delete(h.inflight[upstream], ss)
		}
	}
}

var errWhichHost = errors.New("agentgate cannot tell which host session this request belongs to; it is only passed on while one host is calling this server")

// hostFor picks the host session a server's own request goes to: the one
// calling the server, or the only one connected.
func (p *Proxy) hostFor(upstream string) (*mcp.ServerSession, error) {
	p.hosts.mu.Lock()
	var calling []*mcp.ServerSession
	for ss := range p.hosts.inflight[upstream] {
		calling = append(calling, ss)
	}
	p.hosts.mu.Unlock()
	if len(calling) == 1 {
		return calling[0], nil
	}
	if len(calling) == 0 && p.server != nil {
		var all []*mcp.ServerSession
		for ss := range p.server.Sessions() {
			all = append(all, ss)
		}
		if len(all) == 1 {
			return all[0], nil
		}
	}
	return nil, errWhichHost
}

// stateOf is the session state of a host session.
func (p *Proxy) stateOf(ss *mcp.ServerSession) *sessionState {
	if v, ok := p.sessions.Load(ss); ok {
		return v.(*sessionState)
	}
	return p.state(&mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}})
}

// onSampling handles sampling/createMessage from a server that sends it as a
// request of its own.
func (p *Proxy) onSampling(u *upstream) func(context.Context, *mcp.CreateMessageWithToolsRequest) (*mcp.CreateMessageWithToolsResult, error) {
	return func(ctx context.Context, req *mcp.CreateMessageWithToolsRequest) (*mcp.CreateMessageWithToolsResult, error) {
		ss, err := p.hostFor(u.name())
		if err != nil {
			return nil, err
		}
		started := time.Now()
		st := p.stateOf(ss)
		r := describeInputRequest("", req.Params)
		decision, labels := p.inputRequestsDecision(ctx, st, u.name(), methodTool(policy.RuleSampling), []inputRequest{r})
		raw, _ := json.Marshal(req.Params)
		rec := p.protocolRecord(st, u.name(), policy.RuleSampling, raw, decision, started)
		if decision.Action != policy.ActionAllow {
			p.record(st, rec)
			return nil, fmt.Errorf("agentgate denied: %s (rule %s)", decision.Reason, decision.RuleID)
		}
		res, err := ss.CreateMessageWithTools(ctx, req.Params)
		if err == nil {
			out, _ := json.Marshal(res)
			if d, hit := p.egressHit(st, out); hit {
				p.denyEgress(st, rec, d)
				return nil, fmt.Errorf("agentgate denied: %s (rule %s)", d.Reason, d.RuleID)
			}
			rec.Result = out
		} else {
			rec.IsError, rec.Error = true, err.Error()
		}
		rec.DurationMS = time.Since(started).Milliseconds()
		pc, tokens := &policy.Call{Tool: rec.Tool, Upstream: u.name()}, audit.TokensEst(raw, rec.Result)
		cost := p.Config().Policy.Budget.Money.Cost(pc, tokens)
		p.spent(cost)
		rec.Labels = st.forwarded(pc, tokens, cost, started, labels)
		p.record(st, rec)
		return res, err
	}
}

// onElicitation handles elicitation/create from a server that sends it as a
// request of its own.
func (p *Proxy) onElicitation(u *upstream) func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	return func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		ss, err := p.hostFor(u.name())
		if err != nil {
			return nil, err
		}
		started := time.Now()
		st := p.stateOf(ss)
		r := describeInputRequest("", req.Params)
		decision, labels := p.inputRequestsDecision(ctx, st, u.name(), methodTool(policy.RuleElicitation), []inputRequest{r})
		raw, _ := json.Marshal(req.Params)
		rec := p.protocolRecord(st, u.name(), policy.RuleElicitation, raw, decision, started)
		if decision.Action != policy.ActionAllow {
			p.record(st, rec)
			// A refusal the protocol has a word for: the server carries on.
			return &mcp.ElicitResult{Action: "decline"}, nil
		}
		res, err := ss.Elicit(ctx, req.Params)
		if err == nil {
			out, _ := json.Marshal(res)
			if d, hit := p.egressHit(st, out); hit {
				p.denyEgress(st, rec, d)
				return &mcp.ElicitResult{Action: "decline"}, nil
			}
			rec.Result = out
		} else {
			rec.IsError, rec.Error = true, err.Error()
		}
		rec.DurationMS = time.Since(started).Milliseconds()
		pc, tokens := &policy.Call{Tool: rec.Tool, Upstream: u.name()}, audit.TokensEst(raw, rec.Result)
		cost := p.Config().Policy.Budget.Money.Cost(pc, tokens)
		p.spent(cost)
		rec.Labels = st.forwarded(pc, tokens, cost, started, labels)
		p.record(st, rec)
		return res, err
	}
}

// methodTool is how a server's own request shows in the audit log.
func methodTool(kind string) string {
	if kind == policy.RuleElicitation {
		return "elicitation/create"
	}
	return "sampling/createMessage"
}

func (p *Proxy) protocolRecord(st *sessionState, upstream, kind string, raw []byte, d policy.Decision, at time.Time) *audit.Call {
	rec := &audit.Call{
		ID: audit.NewID(), SessionID: st.id, TS: at, Upstream: upstream, Tool: methodTool(kind),
		Args: raw, Decision: d.Action, RuleID: d.RuleID, Reason: d.Reason, CatalogHash: p.catalogHash(),
	}
	if d.Action != policy.ActionAllow {
		rec.IsError = true
		p.notify.emit(Event{Event: config.EventDeny, At: at, SessionID: st.id, Host: hostLabel(st), Upstream: upstream, Tool: rec.Tool, Decision: d})
	}
	return rec
}

func (p *Proxy) denyEgress(st *sessionState, rec *audit.Call, d policy.Decision) {
	rec.Decision, rec.RuleID, rec.Reason, rec.IsError = d.Action, d.RuleID, d.Reason, true
	p.record(st, rec)
	p.log.Error("an answer to a server carried a secret out", "session", st.id, "upstream", rec.Upstream, "rule", d.RuleID)
	p.notify.emit(Event{Event: config.EventExfiltration, At: rec.TS, SessionID: st.id, Host: hostLabel(st), Upstream: rec.Upstream, Tool: rec.Tool, Decision: d, Message: d.Reason})
}

// inspectContent reads what a resource or a prompt brought back the way a
// tool result is read — for hidden text and instructions aimed at the model,
// and for canaries — and labels the session with what it found.
func (p *Proxy) inspectContent(ss *mcp.ServerSession, upstream, what string, content any) {
	if ss == nil {
		return
	}
	st := p.stateOf(ss)
	text := stringsOf(content)
	wrapped, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	labels := p.inspectResult(st, ToolBinding{Exposed: what, Upstream: upstream}, wrapped)
	if added := st.earn(labels...); len(added) > 0 {
		p.log.Info("session labelled", "session", st.id, "by", what, "labels", strings.Join(added, ","))
	}
	if p.taintsFrom(st, what, labels) {
		p.taint(st, text, what)
	}
}
