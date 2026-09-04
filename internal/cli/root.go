package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
)

// globals holds the flags every subcommand shares.
type globals struct {
	configPath string
	logLevel   string
}

// NewRootCmd builds the whole command tree.
func NewRootCmd() *cobra.Command {
	g := &globals{}
	root := &cobra.Command{
		Use:   "agentgate",
		Short: "Firewall and flight recorder for your AI agent's tools",
		Long: `agentgate sits between an MCP host and the MCP servers it uses.

Every tools/call is checked against a YAML policy, written to a local audit log,
and can be replayed later against a new policy. Everything else passes through
untouched.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       versionString(),
	}
	root.PersistentFlags().StringVarP(&g.configPath, "config", "c", "",
		"path to agentgate.yaml (default: ./agentgate.yaml, then ~/.agentgate/agentgate.yaml)")
	root.PersistentFlags().StringVar(&g.logLevel, "log-level", "info",
		"log level: debug, info, warn or error")

	root.AddCommand(
		newRunCmd(g),
		newCheckCmd(g),
		newSessionsCmd(g),
		newShowCmd(g),
		newTailCmd(g),
		newStatsCmd(g),
		newReplayCmd(g),
		newDiffCmd(g),
		newUICmd(g),
		newPolicyCmd(g),
		newFreezeCmd(g),
		newUnfreezeCmd(g),
		newStatusCmd(g),
	)
	return root
}

func versionString() string {
	out := build.Version
	if build.Commit != "" {
		out += " (" + build.Commit
		if build.Date != "" {
			out += ", " + build.Date
		}
		out += ")"
	}
	return out
}

// logger builds the structured logger. It always writes to stderr: in stdio
// mode stdout carries MCP traffic and a stray log line would corrupt it.
func (g *globals) logger() *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToLower(g.logLevel))); err != nil {
		level = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// configFile resolves which config file to use.
func (g *globals) configFile() (string, error) {
	if g.configPath != "" {
		return g.configPath, nil
	}
	candidates := []string{"agentgate.yaml", "agentgate.yml"}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".agentgate", "agentgate.yaml"),
			filepath.Join(home, ".config", "agentgate", "agentgate.yaml"))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("no config file found; looked for %s. Write one or pass --config",
		strings.Join(candidates, ", "))
}

// load reads the config file.
func (g *globals) load() (*config.Config, error) {
	path, err := g.configFile()
	if err != nil {
		return nil, err
	}
	return config.Load(path)
}

// openStore opens the audit database for reading. Reporting commands use this
// so that they never migrate or prune a database out from under a running
// proxy.
func (g *globals) openStore(ctx context.Context, cfg *config.Config) (*audit.Store, error) {
	store, err := audit.Open(ctx, audit.Options{
		Path:     cfg.Audit.Path,
		Logger:   g.logger(),
		ReadOnly: true,
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no audit database at %s yet — run agentgate and make a tool call first", cfg.Audit.Path)
	}
	return store, err
}

// openStoreForWriting opens the audit database for the proxy: migrations run
// and the retention job fires.
func openStoreForWriting(ctx context.Context, cfg *config.Config, log *slog.Logger) (*audit.Store, error) {
	if !cfg.AuditEnabled() {
		log.Warn("auditing is disabled in the config; no calls will be recorded")
		return nil, nil
	}
	return audit.Open(ctx, audit.Options{
		Path:           cfg.Audit.Path,
		Redactor:       audit.NewRedactor(cfg.Audit.Redactors()),
		MaxResultBytes: cfg.Audit.MaxResultBytes,
		Retention:      cfg.Audit.Retention.Duration(),
		Logger:         log,
	})
}
