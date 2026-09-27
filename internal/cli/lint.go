package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
	"github.com/bnymnDev/agentgate/internal/proxy"
)

func newPolicyLintCmd(g *globals) *cobra.Command {
	var (
		connect bool
		asJSON  bool
	)
	cmd := &cobra.Command{
		Use:   "lint [file]",
		Short: "Find rules that never fire or let more through than they seem to",
		Long: `Look through the policy for the mistakes that validate cannot see because
the file is valid: a rule that never fires because an earlier one always
matches first, an allow that one matching value out of many is enough for, an
unanchored regex in an allow, a directory prefix without its trailing slash
(/home/me/repo also matches /home/me/repo-old), a label no rule attaches, a
tool pattern that matches none of the tools the servers offer.

The tools are taken from the catalog agentgate last recorded; --connect asks
the servers instead. Exits 1 when there is a warning.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) == 1 {
				path = args[0]
			} else {
				var err error
				if path, err = g.configFile(); err != nil {
					return err
				}
			}
			cfg, err := config.Load(path)
			if err != nil {
				return err
			}
			tools, source := lintTools(cmd.Context(), g, cfg, connect)
			findings := policy.Lint(&cfg.Policy, policy.LintContext{Tools: tools, ApprovalMode: cfg.Approval.Mode})
			if asJSON {
				if err := writeJSON(cmd.OutOrStdout(), findings); err != nil {
					return err
				}
			} else {
				out := cmd.OutOrStdout()
				if source != "" {
					fmt.Fprintf(out, "tools from %s\n\n", source)
				}
				if len(findings) == 0 {
					fmt.Fprintf(out, "%s: nothing to report\n", path)
					return nil
				}
				t := newTable(out, "LEVEL", "RULE", "CHECK", "WHAT")
				for _, f := range findings {
					t.row(f.Severity, orDash(f.Rule), f.Check, f.Message)
				}
				t.flush()
			}
			for _, f := range findings {
				if f.Severity == policy.SeverityWarn {
					return errExitDenied
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&connect, "connect", false, "ask the servers for their tools instead of using the last recorded catalog")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the findings as JSON")
	return cmd
}

// lintTools returns the tool names to check tool patterns against, and where
// they came from.
func lintTools(ctx context.Context, g *globals, cfg *config.Config, connect bool) ([]string, string) {
	if connect {
		p, err := proxy.New(proxy.Options{Config: cfg, Logger: g.quietLogger(), DownstreamTransport: "lint", Pinning: proxy.PinningInspect})
		if err != nil {
			return nil, ""
		}
		if err := p.Connect(ctx); err != nil {
			return nil, ""
		}
		defer func() { _ = p.Close() }()
		var names []string
		for _, b := range p.Tools() {
			names = append(names, b.Exposed, b.Upstream+"."+b.Name)
		}
		return names, "the servers, just now"
	}
	store, err := g.openStore(ctx, cfg)
	if err != nil {
		return nil, ""
	}
	defer closeStore(store)
	raw, err := store.LatestCatalog(ctx)
	if err != nil {
		return nil, ""
	}
	var entries []audit.CatalogEntry
	if json.Unmarshal(raw, &entries) != nil {
		return nil, ""
	}
	var names []string
	for _, e := range entries {
		var t struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(e.Tool, &t)
		names = append(names, e.Exposed, e.Upstream+"."+t.Name)
	}
	return names, "the catalog agentgate last recorded"
}
