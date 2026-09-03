package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
	"github.com/bnymnDev/agentgate/internal/proxy"
	"github.com/bnymnDev/agentgate/internal/replay"
)

func newReplayCmd(g *globals) *cobra.Command {
	var (
		dryRun      bool
		onlyAllowed bool
		asJSON      bool
	)
	cmd := &cobra.Command{
		Use:   "replay <session-id>",
		Short: "Re-run a recorded session through the current policy",
		Long: `Re-run the tool calls of a recorded session.

With --dry-run nothing leaves the machine: every recorded call is re-evaluated
against the policy as it stands now, and the differences are printed. This is
how you test a new policy against yesterday's real session before shipping it.

Without --dry-run the allowed calls are actually sent to the upstreams that are
configured now, and the fresh results are compared with the recorded ones.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			store, err := g.openStore(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer closeStore(store)

			sess, err := store.GetSession(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			calls, err := store.ListCalls(cmd.Context(), audit.CallFilter{SessionID: sess.ID})
			if err != nil {
				return err
			}

			opts := replay.Options{Policy: &cfg.Policy, OnlyAllowed: onlyAllowed}
			if !dryRun {
				p, err := connectForReplay(cmd.Context(), g, cfg)
				if err != nil {
					return err
				}
				defer func() {
					if err := p.Close(); err != nil {
						g.logger().Warn("closing upstreams", "error", err)
					}
				}()
				opts.Forwarder = p
			}

			report, err := replay.Run(cmd.Context(), sess.ID, calls, opts)
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), report)
			}
			printReplay(cmd, report, dryRun)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "only re-evaluate the policy, send nothing")
	cmd.Flags().BoolVar(&onlyAllowed, "only-allowed", false, "skip calls that were denied when they were recorded")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	return cmd
}

func printReplay(cmd *cobra.Command, report *replay.Report, dryRun bool) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "replaying session %s (%d calls)%s\n\n",
		report.SessionID, len(report.Entries), dryRunLabel(dryRun))
	if len(report.Entries) == 0 {
		fmt.Fprintln(out, "nothing to replay")
		return
	}
	headers := []string{"#", "TOOL", "WAS", "NOW", "CHANGE"}
	if !dryRun {
		headers = append(headers, "RESULT")
	}
	t := newTable(out, headers...)
	for i, e := range report.Entries {
		change := ""
		switch {
		case e.Skipped:
			change = "skipped"
		case e.DecisionChanged():
			change = string(e.Was.Action) + " → " + string(e.Now.Action)
		}
		row := []any{i, truncate(e.Call.Tool, 32), e.Was.Action, e.Now.Action, change}
		if !dryRun {
			row = append(row, replayResultLabel(e))
		}
		t.row(row...)
	}
	t.flush()

	allowed, denied, changed, failed := report.Counts()
	fmt.Fprintf(out, "\n%d allowed, %d not allowed, %d decisions changed", allowed, denied, changed)
	if !dryRun {
		fmt.Fprintf(out, ", %d failed", failed)
	}
	fmt.Fprintln(out)
	if changed > 0 {
		fmt.Fprintln(out, "\nchanged decisions:")
		for _, e := range report.Changed() {
			fmt.Fprintf(out, "  %-32s %s → %s  %s\n",
				truncate(e.Call.Tool, 32), e.Was.Action, e.Now.Action, e.Now.Reason)
		}
	}
}

func replayResultLabel(e *replay.Entry) string {
	switch {
	case e.Error != "":
		return "error: " + truncate(e.Error, 40)
	case !e.Sent:
		return "-"
	case e.ResultChanged():
		return "differs"
	case e.Call.ResultTruncated:
		return "sent (recorded result was truncated)"
	default:
		return "same"
	}
}

func dryRunLabel(dryRun bool) string {
	if dryRun {
		return " — dry run, nothing is sent"
	}
	return ""
}

// connectForReplay brings up the upstreams without an audit store: a replay
// records nothing, it only reports.
func connectForReplay(ctx context.Context, g *globals, cfg *config.Config) (*proxy.Proxy, error) {
	p, err := proxy.New(proxy.Options{
		Config:              cfg,
		Logger:              g.logger(),
		Approver:            proxy.DenyApprover{Reason: "approval required, replay cannot ask"},
		DownstreamTransport: "replay",
	})
	if err != nil {
		return nil, err
	}
	if err := p.Connect(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// decisionParam validates a --decision flag.
func decisionParam(v string) policy.Action {
	a := policy.Action(strings.TrimSpace(v))
	if a.Valid() {
		return a
	}
	return ""
}
