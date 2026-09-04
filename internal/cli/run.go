package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/killswitch"
	"github.com/bnymnDev/agentgate/internal/proxy"
	"github.com/bnymnDev/agentgate/internal/ui"
)

func newRunCmd(g *globals) *cobra.Command {
	var (
		stdio       bool
		httpAddr    string
		uiAddr      string
		allowRemote bool
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the proxy",
		Long: `Run the proxy.

With --stdio (the default) agentgate speaks MCP on stdin and stdout, which is
what an MCP host expects when it launches a server as a subprocess.

With --http agentgate serves the Streamable HTTP transport instead, which is
also the mode to use when you want approvals: in stdio mode the terminal is
taken by the MCP conversation.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if httpAddr != "" && stdio {
				return errors.New("choose either --stdio or --http, not both")
			}
			return runProxy(cmd.Context(), g, runOptions{
				httpAddr:    httpAddr,
				uiAddr:      uiAddr,
				allowRemote: allowRemote,
			})
		},
	}
	cmd.Flags().BoolVar(&stdio, "stdio", false, "serve MCP on stdin/stdout (the default)")
	cmd.Flags().StringVar(&httpAddr, "http", "", "serve MCP over Streamable HTTP on this address, e.g. :3333")
	cmd.Flags().StringVar(&uiAddr, "ui", "", "also serve the web UI on this address, e.g. 127.0.0.1:7777")
	cmd.Flags().BoolVar(&allowRemote, "allow-remote-ui", false,
		"allow the web UI to bind to a non-loopback address (it has no authentication)")
	return cmd
}

type runOptions struct {
	httpAddr    string
	uiAddr      string
	allowRemote bool
}

func runProxy(ctx context.Context, g *globals, opts runOptions) error {
	log := g.logger()
	cfg, err := g.load()
	if err != nil {
		return err
	}
	log.Info("starting agentgate",
		"version", version(), "config", cfg.Path,
		"upstreams", len(cfg.Upstreams), "policy", cfg.Policy.Summary())

	store, err := openStoreForWriting(ctx, cfg, log)
	if err != nil {
		return err
	}
	if store != nil {
		defer func() {
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := store.Close(shutdown); err != nil {
				log.Warn("closing audit store", "error", err)
			}
		}()
	}

	inbox := proxy.NewInbox()
	transport := "stdio"
	if opts.httpAddr != "" {
		transport = "http"
	}
	p, err := proxy.New(proxy.Options{
		Config:              cfg,
		Store:               store,
		Redactor:            audit.NewRedactor(cfg.Audit.Redactors()),
		Logger:              log,
		Approver:            buildApprover(cfg, inbox, opts.uiAddr != "", log),
		DownstreamTransport: transport,
	})
	if err != nil {
		return err
	}
	if err := p.Connect(ctx); err != nil {
		return err
	}
	defer func() {
		if err := p.Close(); err != nil {
			log.Warn("closing upstreams", "error", err)
		}
	}()

	for _, b := range p.Tools() {
		log.Debug("tool available", "tool", b.Exposed, "upstream", b.Upstream)
	}
	if st, frozen := killswitch.Status(cfg.FreezeFile()); frozen {
		log.Warn("the gateway is FROZEN: every call will be denied until `agentgate unfreeze`",
			"since", st.At.Format(time.RFC3339), "by", st.By, "reason", st.Reason)
	}
	if n := len(cfg.Honeypots.Tools); n > 0 {
		log.Info("honeypots armed", "count", n, "on_trip", cfg.Honeypots.Action)
	}
	if cfg.Policy.IsShadow() {
		log.Warn("policy is in shadow mode: decisions are recorded, nothing is blocked")
	}
	log.Info("proxy ready", "tools", len(p.Tools()))

	group, groupCtx := newRunGroup(ctx)

	if opts.uiAddr != "" {
		srv, err := buildUIServer(opts, cfg, store, inbox, p, log)
		if err != nil {
			return err
		}
		group.serve(srv, "web UI", log)
	}

	switch {
	case opts.httpAddr != "":
		mux := http.NewServeMux()
		mux.Handle("/", p.HTTPHandler())
		group.serve(&http.Server{Addr: opts.httpAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}, "MCP over HTTP", log)
	default:
		group.run(func() error {
			err := p.RunStdio(groupCtx)
			if err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return errShutdown
		})
	}
	return group.wait()
}

// buildApprover decides who answers an "ask" rule. The choice is deliberate and
// logged, because a policy that says "ask" and silently means "deny" is worse
// than one that says "deny".
func buildApprover(cfg *config.Config, inbox *proxy.Inbox, uiRunning bool, log *slog.Logger) proxy.Approver {
	switch cfg.Approval.Mode {
	case "deny":
		return proxy.DenyApprover{Reason: "approval required, approvals are disabled (approval.mode: deny)"}
	case "ui":
		if !uiRunning {
			log.Warn("approval.mode is ui but the web UI is not running; ask rules will deny")
			return proxy.DenyApprover{Reason: "approval required, the web UI is not running"}
		}
		return inbox
	case "tty":
		if tty := proxy.NewTTYApprover(); tty != nil {
			return tty
		}
		log.Warn("approval.mode is tty but no terminal is attached; ask rules will deny")
		return proxy.DenyApprover{}
	default: // auto
		var chain proxy.ChainApprover
		if uiRunning {
			chain = append(chain, inbox)
		}
		if tty := proxy.NewTTYApprover(); tty != nil {
			chain = append(chain, tty)
		}
		if len(chain) == 0 {
			log.Info("no approval channel available; ask rules will deny", "hint", "run with --ui to approve in the browser")
			return proxy.DenyApprover{}
		}
		return chain
	}
}

// buildUIServer wires the web UI to the running proxy, including the reload
// button, which re-reads the config file and swaps the policy in without
// touching upstream connections.
func buildUIServer(opts runOptions, cfg *config.Config, store *audit.Store, inbox *proxy.Inbox, p *proxy.Proxy, log *slog.Logger) (*http.Server, error) {
	if err := checkUIAddr(opts.uiAddr, opts.allowRemote); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("the web UI needs the audit store, but auditing is disabled in the config")
	}
	srv, err := ui.New(ui.Options{
		Store:     store,
		Config:    p.Config,
		Approvals: inbox,
		Reload: func() (*config.Config, error) {
			fresh, err := config.Load(cfg.Path)
			if err != nil {
				return nil, err
			}
			p.SetPolicy(&fresh.Policy)
			return fresh, nil
		},
		Freeze:   p.Freeze,
		Unfreeze: p.Unfreeze,
		Logger:   log,
		Version:  version(),
	})
	if err != nil {
		return nil, err
	}
	log.Info("web UI listening", "addr", "http://"+opts.uiAddr)
	return &http.Server{
		Addr:              opts.uiAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}, nil
}

// errShutdown ends the run group without being reported as a failure.
var errShutdown = errors.New("shutdown")

// checkUIAddr refuses to expose the unauthenticated UI on a public interface
// unless the operator insisted.
func checkUIAddr(addr string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("--ui %q: %w", addr, err)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if loopback || allowRemote {
		return nil
	}
	return fmt.Errorf("the web UI has no authentication and %s is not a loopback address; "+
		"bind it to 127.0.0.1 or pass --allow-remote-ui if you really mean it", addr)
}
