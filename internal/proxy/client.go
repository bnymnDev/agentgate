package proxy

import (
	"context"
	"os"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bnymnDev/agentgate/internal/audit"
)

// clientOptions wires an upstream's notifications back to the host. A change on
// an upstream has to reach the host, or the host keeps calling tools that are
// no longer there.
func (p *Proxy) clientOptions(u *upstream) *mcp.ClientOptions {
	return &mcp.ClientOptions{
		Logger:                 p.log,
		ToolListChangedHandler: func(ctx context.Context, _ *mcp.ToolListChangedRequest) { p.refreshAsync("tools", u) },
		PromptListChangedHandler: func(ctx context.Context, _ *mcp.PromptListChangedRequest) {
			p.refreshAsync("prompts", u)
		},
		ResourceListChangedHandler: func(ctx context.Context, _ *mcp.ResourceListChangedRequest) {
			p.refreshAsync("resources", u)
		},
		ResourceUpdatedHandler: func(ctx context.Context, req *mcp.ResourceUpdatedNotificationRequest) {
			if p.server == nil {
				return
			}
			if err := p.server.ResourceUpdated(ctx, req.Params); err != nil {
				p.log.Debug("forwarding resource update", "upstream", u.name(), "error", err)
			}
		},
		LoggingMessageHandler: func(ctx context.Context, req *mcp.LoggingMessageRequest) {
			p.broadcast(ctx, func(ss *mcp.ServerSession) error { return ss.Log(ctx, req.Params) })
		},
		ProgressNotificationHandler: func(ctx context.Context, req *mcp.ProgressNotificationClientRequest) {
			p.broadcast(ctx, func(ss *mcp.ServerSession) error { return ss.NotifyProgress(ctx, req.Params) })
		},
	}
}

// refreshAsync rebuilds the catalog off the notification goroutine, so a slow
// upstream cannot stall the one that sent the notification.
func (p *Proxy) refreshAsync(what string, u *upstream) {
	select {
	case <-p.done:
		return
	default:
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		p.log.Debug("upstream reported a change", "upstream", u.name(), "what", what)
		if err := p.Refresh(ctx); err != nil {
			p.log.Warn("refreshing catalog", "error", err)
		}
	}()
}

// broadcast sends a notification to every connected host session.
func (p *Proxy) broadcast(ctx context.Context, fn func(*mcp.ServerSession) error) {
	if p.server == nil {
		return
	}
	for ss := range p.server.Sessions() {
		if err := fn(ss); err != nil {
			p.log.Debug("forwarding notification to host", "error", err)
		}
	}
}

// newApprovalID gives each pending approval a sortable id.
func newApprovalID() string { return audit.NewID() }

// isTerminal reports whether f is attached to a terminal.
func isTerminal(f *os.File) bool {
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}
