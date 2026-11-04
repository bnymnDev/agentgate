package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/behavior"
	"github.com/bnymnDev/agentgate/internal/config"
)

func newBehaviorCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "behavior",
		Short: "Learn what every tool normally does, and find calls far outside it",
		Long: `Pinning catches a server that changes what a tool says. A profile catches one
that keeps saying the same and starts doing something else: a read tool that
returns forty times as much as it ever did, takes an argument it never took,
or earns the session a label it never earned.

	agentgate behavior learn --since 14d    profile the last two weeks
	agentgate behavior check --since 1d     what in the last day is outside it

With behavior.profile in the config, the gateway compares every call as it
happens. The profile is JSON, meant to be reviewed and committed.`,
	}
	cmd.AddCommand(newBehaviorLearnCmd(g), newBehaviorCheckCmd(g))
	return cmd
}

func profilePath(cfg *config.Config, out string) string {
	switch {
	case out != "":
		return out
	case cfg.Behavior.Profile != "":
		return cfg.Behavior.Profile
	}
	return strings.TrimSuffix(cfg.Path, ".yaml") + ".behavior.json"
}

func callsSince(g *globals, cmd *cobra.Command, cfg *config.Config, since string) ([]*audit.Call, error) {
	d, err := config.ParseDuration(since)
	if err != nil {
		return nil, fmt.Errorf("--since: %w", err)
	}
	store, err := g.openStore(cmd.Context(), cfg)
	if err != nil {
		return nil, err
	}
	defer closeStore(store)
	return store.ListCalls(cmd.Context(), audit.CallFilter{Since: time.Now().Add(-d), Limit: 200000})
}

func newBehaviorLearnCmd(g *globals) *cobra.Command {
	var since, out string
	cmd := &cobra.Command{
		Use:   "learn",
		Short: "Write a profile of every tool from the audit log",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			calls, err := callsSince(g, cmd, cfg, since)
			if err != nil {
				return err
			}
			prof := behavior.Learn(calls)
			path := profilePath(cfg, out)
			if err := prof.Save(path); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			t := newTable(w, "TOOL", "CALLS", "RESULT P95", "TIME P95", "ERRORS", "ARGUMENTS")
			for _, name := range sortedTools(prof) {
				tp := prof.Tools[name]
				t.row(truncate(name, 36), tp.Calls, fmt.Sprintf("%d B", tp.ResultBytes.P95),
					fmt.Sprintf("%d ms", tp.DurationMS.P95), fmt.Sprintf("%.0f%%", 100*tp.ErrorRate), truncate(strings.Join(tp.ArgKeys, ","), 40))
			}
			t.flush()
			fmt.Fprintf(w, "\nwrote %s (%d tools, %d calls)", path, len(prof.Tools), len(calls))
			if cfg.Behavior.Profile == "" {
				fmt.Fprintf(w, "; set behavior.profile to compare calls as they happen")
			}
			fmt.Fprintln(w)
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "14d", "how much of the audit log to learn from")
	cmd.Flags().StringVarP(&out, "output", "o", "", "where to write the profile; default behavior.profile, or next to the config")
	return cmd
}

func newBehaviorCheckCmd(g *globals) *cobra.Command {
	var since, profile string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "List recorded calls that are outside the profile",
		Long:  "List the calls of a stretch of the audit log that are far outside the profile, and exit 1 if there are any.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			path := profilePath(cfg, profile)
			prof, err := behavior.Load(path)
			if err != nil {
				return err
			}
			if prof == nil {
				return fmt.Errorf("no profile at %s; agentgate behavior learn writes one", path)
			}
			calls, err := callsSince(g, cmd, cfg, since)
			if err != nil {
				return err
			}
			th := behavior.Thresholds{MinCalls: cfg.Behavior.MinCalls, Factor: cfg.Behavior.Factor}
			w := cmd.OutOrStdout()
			found := 0
			for _, c := range calls {
				if c.TS.Before(prof.To) || c.Decision != "allow" && !c.Shadow {
					continue
				}
				tp := prof.Tools[c.Tool]
				as := append(tp.Before(c.Args, th), tp.After(int64(len(c.Result)), c.DurationMS, c.Labels, th)...)
				for _, a := range as {
					found++
					fmt.Fprintf(w, "%s  %-28s  %-13s  %s\n", c.TS.Local().Format("01-02 15:04:05"), truncate(c.Tool, 28), a.Kind, a.Detail)
				}
			}
			fmt.Fprintf(w, "\n%d anomalies in %d calls since %s, against a profile of %s to %s\n", found, len(calls), since,
				prof.From.Local().Format(time.DateOnly), prof.To.Local().Format(time.DateOnly))
			if found > 0 {
				return errExitDenied
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "1d", "how much of the audit log to check")
	cmd.Flags().StringVar(&profile, "profile", "", "the profile; default behavior.profile, or next to the config")
	return cmd
}

func sortedTools(p *behavior.Profile) []string {
	out := make([]string, 0, len(p.Tools))
	for k := range p.Tools {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
