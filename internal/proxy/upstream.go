package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bnymnDev/agentgate/internal/config"
)

// upstream is one real MCP server agentgate has connected to.
type upstream struct {
	cfg *config.Upstream
	log *slog.Logger

	mu      sync.RWMutex
	client  *mcp.Client
	session *mcp.ClientSession
	roots   []string

	// override replaces the transport built from the config. Tests use it to
	// put an in-process server behind the proxy; it is nil in production.
	override mcp.Transport
}

// name returns the upstream's configured name.
func (u *upstream) name() string { return u.cfg.Name }

// conn returns the live client session, or an error if the upstream is down.
func (u *upstream) conn() (*mcp.ClientSession, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.session == nil {
		return nil, fmt.Errorf("upstream %q is not connected", u.cfg.Name)
	}
	return u.session, nil
}

// connect dials the upstream and performs the MCP handshake.
func (u *upstream) connect(ctx context.Context, opts *mcp.ClientOptions, impl *mcp.Implementation) error {
	transport, err := u.transport()
	if err != nil {
		return err
	}
	client := mcp.NewClient(impl, opts)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return fmt.Errorf("connecting to upstream %q: %w", u.cfg.Name, err)
	}
	u.mu.Lock()
	u.client, u.session = client, session
	u.mu.Unlock()

	info := session.InitializeResult()
	attrs := []any{"upstream", u.cfg.Name, "transport", u.cfg.Transport()}
	if info != nil && info.ServerInfo != nil {
		attrs = append(attrs, "server", info.ServerInfo.Name, "version", info.ServerInfo.Version)
	}
	u.log.Info("upstream connected", attrs...)
	return nil
}

// transport builds the SDK transport described by the config.
func (u *upstream) transport() (mcp.Transport, error) {
	if u.override != nil {
		return u.override, nil
	}
	if u.cfg.HTTP != "" {
		client := http.DefaultClient
		if len(u.cfg.Headers) > 0 {
			client = &http.Client{Transport: &headerTransport{
				base:    http.DefaultTransport,
				headers: u.cfg.Headers,
			}}
		}
		return &mcp.StreamableClientTransport{Endpoint: u.cfg.HTTP, HTTPClient: client}, nil
	}
	if len(u.cfg.Stdio) == 0 {
		return nil, fmt.Errorf("upstream %q has no command", u.cfg.Name)
	}
	cmd := exec.Command(u.cfg.Stdio[0], u.cfg.Stdio[1:]...)
	cmd.Dir = u.cfg.Cwd
	cmd.Env = os.Environ()
	for k, v := range u.cfg.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	// The upstream's diagnostics belong on agentgate's stderr, next to
	// agentgate's own log lines. Its stdout is the MCP channel and is wired up
	// by the transport.
	cmd.Stderr = os.Stderr
	return &mcp.CommandTransport{Command: cmd}, nil
}

// capabilities reports what the upstream said it can do.
func (u *upstream) capabilities() *mcp.ServerCapabilities {
	session, err := u.conn()
	if err != nil {
		return nil
	}
	res := session.InitializeResult()
	if res == nil {
		return nil
	}
	return res.Capabilities
}

// instructions returns the upstream's initialize instructions, if any.
func (u *upstream) instructions() string {
	session, err := u.conn()
	if err != nil {
		return ""
	}
	if res := session.InitializeResult(); res != nil {
		return res.Instructions
	}
	return ""
}

// close tears down the connection.
func (u *upstream) close() error {
	u.mu.Lock()
	session := u.session
	u.session = nil
	u.mu.Unlock()
	if session == nil {
		return nil
	}
	return session.Close()
}

// headerTransport adds static headers to every request to an HTTP upstream.
type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	for k, v := range t.headers {
		clone.Header.Set(k, v)
	}
	return t.base.RoundTrip(clone)
}

// rootURIs returns the roots currently mirrored onto this upstream.
func (u *upstream) rootURIs() []string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return append([]string(nil), u.roots...)
}

// setRootURIs remembers which roots were pushed, so the next mirror can remove
// exactly those and nothing else.
func (u *upstream) setRootURIs(roots []*mcp.Root) {
	uris := make([]string, 0, len(roots))
	for _, r := range roots {
		uris = append(uris, r.URI)
	}
	u.mu.Lock()
	u.roots = uris
	u.mu.Unlock()
}
