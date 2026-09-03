package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
)

func newSessionsCmd(g *globals) *cobra.Command {
	var (
		since  string
		limit  int
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "List recorded sessions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			store, err := g.openStore(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer closeStore(store)

			filter := audit.SessionFilter{Limit: limit}
			if since != "" {
				d, err := config.ParseDuration(since)
				if err != nil {
					return fmt.Errorf("--since: %w", err)
				}
				filter.Since = time.Now().Add(-d)
			}
			sessions, err := store.ListSessions(cmd.Context(), filter)
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), sessions)
			}
			if len(sessions) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no sessions recorded yet")
				return nil
			}
			t := newTable(cmd.OutOrStdout(), "SESSION", "STARTED", "HOST", "TRANSPORT", "CALLS", "DENIED", "DURATION")
			for _, s := range sessions {
				host := s.HostName
				if host == "" {
					host = "-"
				} else if s.HostVersion != "" {
					host += " " + s.HostVersion
				}
				live := ""
				if s.EndedAt == nil {
					live = " (live)"
				}
				t.row(shortID(s.ID), s.StartedAt.Local().Format("2006-01-02 15:04:05"),
					truncate(host, 28), orDash(s.DownstreamTransport), s.Calls, s.Denied,
					s.Duration().Round(time.Second).String()+live)
			}
			t.flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "only sessions started within this window, e.g. 24h or 7d")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of sessions to list")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return cmd
}

func newShowCmd(g *globals) *cobra.Command {
	var (
		asJSON   bool
		decision string
		tool     string
		showArgs bool
	)
	cmd := &cobra.Command{
		Use:   "show <session-id>",
		Short: "Show the calls of one session",
		Args:  cobra.ExactArgs(1),
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
			calls, err := store.ListCalls(cmd.Context(), audit.CallFilter{
				SessionID: sess.ID,
				Decision:  decisionParam(decision),
				Tool:      tool,
			})
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), map[string]any{"session": sess, "calls": calls})
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "session  %s\n", sess.ID)
			fmt.Fprintf(out, "host     %s %s\n", orDash(sess.HostName), sess.HostVersion)
			fmt.Fprintf(out, "started  %s (%s)\n\n", sess.StartedAt.Local().Format(time.RFC3339),
				sess.Duration().Round(time.Second))
			if len(calls) == 0 {
				fmt.Fprintln(out, "no calls match")
				return nil
			}
			t := newTable(out, "TIME", "DECISION", "TOOL", "MS", "RULE", "DETAIL")
			for _, c := range calls {
				detail := c.Reason
				if c.Error != "" {
					detail = c.Error
				}
				if showArgs {
					detail = string(c.Args)
				}
				t.row(c.TS.Local().Format("15:04:05"), c.Decision, truncate(c.Tool, 32),
					c.DurationMS, orDash(c.RuleID), truncate(detail, 48))
			}
			t.flush()
			fmt.Fprintf(out, "\n%d calls, %d denied\n", sess.Calls, sess.Denied)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	cmd.Flags().StringVar(&decision, "decision", "", "only calls with this decision: allow, deny or ask")
	cmd.Flags().StringVar(&tool, "tool", "", "only calls whose tool name contains this")
	cmd.Flags().BoolVar(&showArgs, "args", false, "show the arguments instead of the reason")
	return cmd
}

// closeStore closes a read-only store opened by a reporting command. There is
// nothing queued to flush and nothing useful to do about a failure at exit.
func closeStore(s *audit.Store) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.Close(ctx)
}

func writeJSON(w interface{ Write([]byte) (int, error) }, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
