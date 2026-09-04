package cli

import (
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/killswitch"
)

func newFreezeCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "freeze [reason...]",
		Short: "Stop every agent: deny all tool calls until unfreeze",
		Long: `Throw the kill switch.

Every tools/call through every agentgate that shares this config is denied
with a readable reason until "agentgate unfreeze". Nothing is restarted and no
connection is dropped: the agents stay connected, they just cannot do anything.

The switch is a marker file next to the audit database, so it works from any
shell, with or without a proxy running, and survives a restart.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			reason := strings.Join(args, " ")
			if reason == "" {
				reason = "frozen from the command line"
			}
			st, err := killswitch.Engage(cfg.FreezeFile(), reason, whoami())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "frozen: %s\n  by     %s\n  since  %s\n  marker %s\n\nrun `agentgate unfreeze` to let calls through again\n",
				st.Reason, st.By, st.At.Local().Format(time.RFC3339), cfg.FreezeFile())
			return nil
		},
	}
}

func newUnfreezeCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "unfreeze",
		Short: "Lift the kill switch",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			st, frozen := killswitch.Status(cfg.FreezeFile())
			if err := killswitch.Release(cfg.FreezeFile()); err != nil {
				return err
			}
			if !frozen {
				fmt.Fprintln(cmd.OutOrStdout(), "the gateway was not frozen")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "unfrozen (was frozen since %s: %s)\n",
				st.At.Local().Format(time.RFC3339), st.Reason)
			return nil
		},
	}
}

func newStatusCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the gateway's state at a glance",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if st, frozen := killswitch.Status(cfg.FreezeFile()); frozen {
				fmt.Fprintf(out, "state      FROZEN since %s by %s: %s\n", st.At.Local().Format(time.RFC3339), st.By, st.Reason)
			} else {
				fmt.Fprintln(out, "state      running")
			}
			fmt.Fprintf(out, "config     %s\n", cfg.Path)
			fmt.Fprintf(out, "policy     %s\n", cfg.Policy.Summary())
			if cfg.Policy.LoopGuard.Repeats > 0 {
				fmt.Fprintf(out, "loop guard %d repeats\n", cfg.Policy.LoopGuard.Repeats)
			}
			if n := len(cfg.Honeypots.Tools); n > 0 {
				fmt.Fprintf(out, "honeypots  %d armed (%s on trip)\n", n, cfg.Honeypots.Action)
			}
			if n := len(cfg.Notify.Webhooks); n > 0 {
				fmt.Fprintf(out, "webhooks   %d configured\n", n)
			}
			fmt.Fprintf(out, "upstreams  %d\n", len(cfg.Upstreams))

			store, err := g.openStore(cmd.Context(), cfg)
			if err != nil {
				fmt.Fprintf(out, "audit      %s (no database yet)\n", cfg.Audit.Path)
				return nil
			}
			defer closeStore(store)
			st, err := store.Stats(cmd.Context(), time.Now().Add(-24*time.Hour))
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "audit      %s\n", cfg.Audit.Path)
			fmt.Fprintf(out, "last 24h   %d sessions, %d calls, %d denied, %d shadowed, %d honeypot trips, %d errors\n",
				st.Sessions, st.Calls, st.Denied, st.Shadowed, st.Honeypots, st.Errors)
			return nil
		},
	}
}

func whoami() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		if host, err := os.Hostname(); err == nil {
			return u.Username + "@" + host
		}
		return u.Username
	}
	return "cli"
}
