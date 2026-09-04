// Package proxy is the MCP passthrough: it terminates the connection from the
// host (downstream), keeps connections to the real MCP servers (upstream), and
// puts the policy evaluator and the audit log in between.
//
// Everything that is not a tools/call is forwarded unchanged. tools/call is the
// only place agentgate has an opinion.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// Version is stamped into the implementation agentgate advertises. It is
// overridden from main at build time.
var Version = "dev"

// Proxy fronts one or more upstream MCP servers.
type Proxy struct {
	log      *slog.Logger
	store    *audit.Store
	approver Approver

	// cfg is swapped wholesale on hot reload, so it is read under mu.
	mu        sync.RWMutex
	cfg       *config.Config
	upstreams []*upstream
	byName    map[string]*upstream

	server  *mcp.Server
	catalog catalog

	sessions sync.Map // *mcp.ServerSession -> *sessionState

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// Options configure a Proxy.
type Options struct {
	Config *config.Config
	Store  *audit.Store
	Logger *slog.Logger
	// Approver decides "ask" calls. When nil, ask falls back to deny.
	Approver Approver
	// DownstreamTransport is recorded with the session ("stdio" or "http").
	DownstreamTransport string
}

// sessionState is what agentgate tracks per downstream connection. The call
// counters live here rather than in the audit store so that budgets keep
// working when auditing is switched off.
type sessionState struct {
	id          string
	transport   string
	startedAt   time.Time
	hostName    string
	hostVersion string

	mu       sync.Mutex
	calls    int
	perTool  map[string]int
	finished bool
}

// hostInfo records who connected. It is called once, before the session is
// visible to any other goroutine.
func (st *sessionState) hostInfo(name, version string) {
	st.hostName, st.hostVersion = name, version
}

// New builds a proxy. Call Connect before serving.
func New(opts Options) (*Proxy, error) {
	if opts.Config == nil {
		return nil, errors.New("proxy: no config")
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	p := &Proxy{
		log:      log,
		store:    opts.Store,
		approver: opts.Approver,
		cfg:      opts.Config,
		byName:   map[string]*upstream{},
		done:     make(chan struct{}),
	}
	if p.approver == nil {
		p.approver = DenyApprover{}
	}
	for i := range opts.Config.Upstreams {
		u := &upstream{
			cfg: &opts.Config.Upstreams[i],
			log: log,
		}
		p.upstreams = append(p.upstreams, u)
		p.byName[u.name()] = u
	}
	p.catalog.transport = opts.DownstreamTransport
	return p, nil
}

// Config returns the configuration currently in force.
func (p *Proxy) Config() *config.Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cfg
}

// SetPolicy swaps the policy in place, for hot reload from the web UI or a
// SIGHUP. Upstream connections are untouched.
func (p *Proxy) SetPolicy(pol *policy.Policy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg.Policy = *pol
	p.log.Info("policy reloaded", "summary", pol.Summary())
}

// Connect dials every upstream and builds the merged catalog. Upstreams that
// fail to connect are reported but do not stop the others: a broken server
// should not take the whole gateway down.
func (p *Proxy) Connect(ctx context.Context) error {
	impl := &mcp.Implementation{Name: "agentgate", Title: "agentgate", Version: Version}
	var errs []error
	for _, u := range p.upstreams {
		if err := u.connect(ctx, p.clientOptions(u), impl); err != nil {
			p.log.Error("upstream unavailable", "upstream", u.name(), "error", err)
			errs = append(errs, err)
		}
	}
	if len(errs) == len(p.upstreams) {
		return fmt.Errorf("no upstream could be reached: %w", errors.Join(errs...))
	}
	p.server = mcp.NewServer(p.implementation(), p.serverOptions())
	p.server.AddReceivingMiddleware(p.middleware)
	if err := p.Refresh(ctx); err != nil {
		p.log.Warn("building tool catalog", "error", err)
	}
	return nil
}

// implementation is what the downstream host sees in initialize.
func (p *Proxy) implementation() *mcp.Implementation {
	return &mcp.Implementation{
		Name:       "agentgate",
		Title:      "agentgate",
		Version:    Version,
		WebsiteURL: "https://github.com/bnymnDev/agentgate",
	}
}

// serverOptions merges the capabilities of every upstream, so the host sees the
// union of what the servers behind agentgate can do.
func (p *Proxy) serverOptions() *mcp.ServerOptions {
	caps := &mcp.ServerCapabilities{}
	var subscribe bool
	for _, u := range p.upstreams {
		c := u.capabilities()
		if c == nil {
			continue
		}
		if c.Tools != nil {
			caps.Tools = &mcp.ToolCapabilities{ListChanged: true}
		}
		if c.Prompts != nil {
			caps.Prompts = &mcp.PromptCapabilities{ListChanged: true}
		}
		if c.Resources != nil {
			caps.Resources = &mcp.ResourceCapabilities{ListChanged: true, Subscribe: c.Resources.Subscribe || subscribe}
			subscribe = subscribe || c.Resources.Subscribe
		}
		if c.Logging != nil {
			caps.Logging = &mcp.LoggingCapabilities{}
		}
		if c.Completions != nil {
			caps.Completions = &mcp.CompletionCapabilities{}
		}
	}
	opts := &mcp.ServerOptions{
		Logger:       p.log,
		Capabilities: caps,
		Instructions: p.instructions(),
	}
	if caps.Completions != nil {
		opts.CompletionHandler = p.handleComplete
	}
	if caps.Resources != nil && caps.Resources.Subscribe {
		opts.SubscribeHandler = p.handleSubscribe
		opts.UnsubscribeHandler = p.handleUnsubscribe
	}
	return opts
}

// instructions concatenates the upstream instructions, labelled by upstream, so
// the host still gets the guidance the servers wrote.
func (p *Proxy) instructions() string {
	var parts []string
	for _, u := range p.upstreams {
		if s := u.instructions(); s != "" {
			parts = append(parts, fmt.Sprintf("## %s\n\n%s", u.name(), s))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 && len(p.upstreams) == 1 {
		return p.upstreams[0].instructions()
	}
	out := "Tools are proxied by agentgate; the prefix of a tool name is the server it belongs to.\n\n"
	for i, part := range parts {
		if i > 0 {
			out += "\n\n"
		}
		out += part
	}
	return out
}

// Server exposes the downstream MCP server, for tests and for the HTTP handler.
func (p *Proxy) Server() *mcp.Server { return p.server }

// RunStdio serves a single downstream connection on stdin/stdout and returns
// when the host disconnects or ctx is cancelled.
func (p *Proxy) RunStdio(ctx context.Context) error {
	ss, err := p.server.Connect(ctx, &mcp.StdioTransport{}, nil)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- ss.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = ss.Close()
		return ctx.Err()
	}
}

// HTTPHandler serves the Streamable HTTP transport for downstream hosts.
func (p *Proxy) HTTPHandler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return p.server },
		&mcp.StreamableHTTPOptions{Logger: p.log})
}

// Close ends every downstream session and closes every upstream.
func (p *Proxy) Close() error {
	var errs []error
	p.closeOnce.Do(func() {
		close(p.done)
		if p.server != nil {
			// Closing the session is what makes its Wait return, which is how
			// the per-session goroutine gets its exit. A session that is
			// already gone is exactly the outcome we want.
			for ss := range p.server.Sessions() {
				_ = ss.Close()
			}
		}
		for _, u := range p.upstreams {
			if err := u.close(); err != nil {
				errs = append(errs, err)
			}
		}
		p.wg.Wait()
	})
	return errors.Join(errs...)
}

// state returns the tracked state of a downstream session, creating it if the
// session appeared without an initialize agentgate saw (which happens for the
// stateless HTTP transport).
func (p *Proxy) state(ss *mcp.ServerSession) *sessionState {
	if v, ok := p.sessions.Load(ss); ok {
		return v.(*sessionState)
	}
	st := newSessionState(p.catalog.transport)
	actual, loaded := p.sessions.LoadOrStore(ss, st)
	st = actual.(*sessionState)
	if !loaded {
		p.recordSessionStart(ss, st, nil)
	}
	return st
}

// recordSessionStart writes the session row and arranges for it to be closed
// when the downstream connection goes away.
func (p *Proxy) recordSessionStart(ss *mcp.ServerSession, st *sessionState, params *mcp.InitializeParams) {
	if params != nil && params.ClientInfo != nil {
		st.hostInfo(params.ClientInfo.Name, params.ClientInfo.Version)
	}
	if p.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rec := &audit.Session{
			ID:                  st.id,
			StartedAt:           st.startedAt,
			HostName:            st.hostName,
			HostVersion:         st.hostVersion,
			DownstreamTransport: st.transport,
		}
		if err := p.store.StartSession(ctx, rec); err != nil {
			p.log.Warn("audit: cannot open session", "session", st.id, "error", err)
		}
	}
	p.log.Info("session started",
		"session", st.id, "host", st.hostName, "host_version", st.hostVersion, "transport", st.transport)

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		// Wait returns when the host disconnects; Close on shutdown makes that
		// happen, so this goroutine always has an exit.
		_ = ss.Wait()
		p.endSession(ss)
	}()
}

func (p *Proxy) endSession(ss *mcp.ServerSession) {
	v, ok := p.sessions.LoadAndDelete(ss)
	if !ok {
		return
	}
	st := v.(*sessionState)
	st.mu.Lock()
	if st.finished {
		st.mu.Unlock()
		return
	}
	st.finished = true
	calls := st.calls
	st.mu.Unlock()

	if p.store != nil {
		p.store.EndSession(st.id, time.Now())
	}
	p.log.Info("session ended", "session", st.id, "calls", calls,
		"duration", time.Since(st.startedAt).Round(time.Millisecond).String())
}

// count records a forwarded call and returns the counters as they were before
// it, which is what the budget check needs.
func (st *sessionState) count(tool string) policy.Counts {
	st.mu.Lock()
	defer st.mu.Unlock()
	return policy.Counts{Session: st.calls, Tool: st.perTool[tool]}
}

func (st *sessionState) increment(tool string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.calls++
	st.perTool[tool]++
}
