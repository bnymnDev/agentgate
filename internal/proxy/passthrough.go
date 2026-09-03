package proxy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bnymnDev/agentgate/internal/audit"
)

// middleware sits in front of every message the host sends. Only the messages
// agentgate has something to add to are handled here; everything else falls
// through to the SDK, which serves it from the merged catalog.
func (p *Proxy) middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		switch method {
		case "initialize":
			return p.onInitialize(ctx, method, req, next)
		case "resources/read":
			return p.onReadResource(ctx, method, req, next)
		case "logging/setLevel":
			return p.onSetLevel(ctx, method, req, next)
		case "notifications/roots/list_changed":
			res, err := next(ctx, method, req)
			p.mirrorRoots(ctx, req.GetSession())
			return res, err
		}
		return next(ctx, method, req)
	}
}

// onInitialize lets the SDK do the handshake and then opens the audit session,
// so that the session row carries the real host name and version.
func (p *Proxy) onInitialize(ctx context.Context, method string, req mcp.Request, next mcp.MethodHandler) (mcp.Result, error) {
	res, err := next(ctx, method, req)
	if err != nil {
		return res, err
	}
	ss, ok := req.GetSession().(*mcp.ServerSession)
	if !ok {
		return res, nil
	}
	params, _ := req.GetParams().(*mcp.InitializeParams)
	st := newSessionState(p.catalog.transport)
	if _, dup := p.sessions.LoadOrStore(ss, st); !dup {
		p.recordSessionStart(ss, st, params)
	}
	// Roots are a client feature; mirroring them upstream is what lets a
	// filesystem server behind agentgate see the same workspace the host sees.
	// It has to happen off this goroutine: roots/list is a request back to the
	// host, which cannot answer while it is still waiting for initialize.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		mirrorCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		p.mirrorRoots(mirrorCtx, ss)
	}()
	return res, nil
}

// onReadResource routes a read to the upstream that listed the URI. The SDK
// already does that for anything in the catalog; this fallback covers servers
// that serve URIs they never listed, which would otherwise be answered with a
// "resource not found" agentgate invented.
func (p *Proxy) onReadResource(ctx context.Context, method string, req mcp.Request, next mcp.MethodHandler) (mcp.Result, error) {
	res, err := next(ctx, method, req)
	if err == nil {
		return res, nil
	}
	params, ok := req.GetParams().(*mcp.ReadResourceParams)
	if !ok || !isNotFound(err) {
		return res, err
	}
	for _, u := range p.upstreams {
		caps := u.capabilities()
		if caps == nil || caps.Resources == nil {
			continue
		}
		session, connErr := u.conn()
		if connErr != nil {
			continue
		}
		out, readErr := session.ReadResource(ctx, params)
		if readErr == nil {
			return out, nil
		}
	}
	return res, err
}

// onSetLevel applies the level to agentgate and passes it on, so that upstream
// log messages honour what the host asked for.
func (p *Proxy) onSetLevel(ctx context.Context, method string, req mcp.Request, next mcp.MethodHandler) (mcp.Result, error) {
	res, err := next(ctx, method, req)
	params, ok := req.GetParams().(*mcp.SetLoggingLevelParams)
	if !ok {
		return res, err
	}
	for _, u := range p.upstreams {
		caps := u.capabilities()
		if caps == nil || caps.Logging == nil {
			continue
		}
		session, connErr := u.conn()
		if connErr != nil {
			continue
		}
		if setErr := session.SetLoggingLevel(ctx, params); setErr != nil {
			p.log.Debug("upstream rejected logging level", "upstream", u.name(), "error", setErr)
		}
	}
	return res, err
}

// resourceHandler forwards resources/read to the upstream that owns the URI.
func (p *Proxy) resourceHandler(u *upstream) mcp.ResourceHandler {
	return func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		session, err := u.conn()
		if err != nil {
			return nil, err
		}
		return session.ReadResource(ctx, req.Params)
	}
}

// promptHandler forwards prompts/get to the upstream that owns the prompt.
func (p *Proxy) promptHandler(u *upstream) mcp.PromptHandler {
	return func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		session, err := u.conn()
		if err != nil {
			return nil, err
		}
		return session.GetPrompt(ctx, req.Params)
	}
}

// handleComplete routes completion/complete by what it refers to: a prompt name
// or a resource URI. Unknown references go to the first upstream that supports
// completion, which is the documented fallback for requests that carry no
// routable name.
func (p *Proxy) handleComplete(ctx context.Context, req *mcp.CompleteRequest) (*mcp.CompleteResult, error) {
	var target *upstream
	if ref := req.Params.Ref; ref != nil {
		switch {
		case ref.Name != "":
			target = p.ownerOfPrompt(ref.Name)
		case ref.URI != "":
			target = p.ownerOfResource(ref.URI)
		}
	}
	if target == nil {
		target = p.firstWith(func(c *mcp.ServerCapabilities) bool { return c.Completions != nil })
	}
	if target == nil {
		return nil, errors.New("no upstream supports completion")
	}
	session, err := target.conn()
	if err != nil {
		return nil, err
	}
	return session.Complete(ctx, req.Params)
}

// handleSubscribe forwards a resource subscription to the owning upstream.
func (p *Proxy) handleSubscribe(ctx context.Context, req *mcp.SubscribeRequest) error {
	u := p.ownerOfResource(req.Params.URI)
	if u == nil {
		u = p.firstWith(func(c *mcp.ServerCapabilities) bool {
			return c.Resources != nil && c.Resources.Subscribe
		})
	}
	if u == nil {
		return fmt.Errorf("no upstream can subscribe to %s", req.Params.URI)
	}
	session, err := u.conn()
	if err != nil {
		return err
	}
	return session.Subscribe(ctx, req.Params)
}

// handleUnsubscribe is the counterpart of handleSubscribe.
func (p *Proxy) handleUnsubscribe(ctx context.Context, req *mcp.UnsubscribeRequest) error {
	u := p.ownerOfResource(req.Params.URI)
	if u == nil {
		u = p.firstWith(func(c *mcp.ServerCapabilities) bool {
			return c.Resources != nil && c.Resources.Subscribe
		})
	}
	if u == nil {
		return nil
	}
	session, err := u.conn()
	if err != nil {
		return err
	}
	return session.Unsubscribe(ctx, req.Params)
}

// firstWith returns the first upstream, in config order, whose capabilities
// satisfy pred.
func (p *Proxy) firstWith(pred func(*mcp.ServerCapabilities) bool) *upstream {
	for _, u := range p.upstreams {
		if c := u.capabilities(); c != nil && pred(c) {
			return u
		}
	}
	return nil
}

// mirrorRoots copies the host's roots onto every upstream client. With more
// than one host connected at once the most recent list wins; agentgate is meant
// to sit in front of a single host, and this is documented in docs/architecture.md.
func (p *Proxy) mirrorRoots(ctx context.Context, session mcp.Session) {
	ss, ok := session.(*mcp.ServerSession)
	if !ok {
		return
	}
	if init := ss.InitializeParams(); init == nil || init.Capabilities == nil {
		return
	}
	res, err := ss.ListRoots(ctx, nil)
	if err != nil {
		p.log.Debug("host did not return roots", "error", err)
		return
	}
	for _, u := range p.upstreams {
		u.mu.RLock()
		client := u.client
		u.mu.RUnlock()
		if client == nil {
			continue
		}
		client.RemoveRoots(u.rootURIs()...)
		client.AddRoots(res.Roots...)
		u.setRootURIs(res.Roots)
	}
	p.log.Debug("mirrored host roots to upstreams", "roots", len(res.Roots))
}

// isNotFound reports whether err is the SDK's "resource not found".
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "not found")
}

// newSessionState is the constructor used before a session row exists.
func newSessionState(transport string) *sessionState {
	return &sessionState{
		id:        audit.NewID(),
		transport: transport,
		startedAt: time.Now(),
		perTool:   map[string]int{},
	}
}
