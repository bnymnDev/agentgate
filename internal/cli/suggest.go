package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
)

func newPolicySuggestCmd(g *globals) *cobra.Command {
	var (
		since     string
		session   string
		outPath   string
		loopGuard int
	)
	cmd := &cobra.Command{
		Use:   "suggest",
		Short: "Write a deny-by-default policy from what the agent actually did",
		Long: `Turn the audit log into a policy.

Run agentgate for a while with "default: allow" and no rules, then let this
command write the allow-list: one rule per tool the agent used, everything
else denied, a budget a little above what was observed, and a loop guard.
Review it, tighten it, ship it.

The output is a complete "policy:" section. Paste it over the one in your
config, or write it with --out and copy the block from there.`,
		Args: cobra.NoArgs,
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

			var cutoff time.Time
			if since != "" {
				d, err := config.ParseDuration(since)
				if err != nil {
					return fmt.Errorf("--since: %w", err)
				}
				cutoff = time.Now().Add(-d)
			}
			sessionID := ""
			if session != "" {
				sess, err := store.GetSession(cmd.Context(), session)
				if err != nil {
					return err
				}
				sessionID = sess.ID
				cutoff = time.Time{}
			}
			tools, err := store.ToolStats(cmd.Context(), cutoff, sessionID)
			if err != nil {
				return err
			}
			if len(tools) == 0 {
				return fmt.Errorf("no calls recorded in this window; run the agent for a while first")
			}
			sessions, err := store.ListSessions(cmd.Context(), audit.SessionFilter{Since: cutoff, Limit: 100000})
			if err != nil {
				return err
			}

			if outPath == "" {
				writeSuggestion(cmd.OutOrStdout(), tools, sessions, since, sessionID, loopGuard)
				return nil
			}
			f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			writeSuggestion(f, tools, sessions, since, sessionID, loopGuard)
			if err := f.Close(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s — review it, then run: agentgate policy validate %s\n", outPath, outPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "7d", "window to learn from, e.g. 24h, 7d; empty for everything")
	cmd.Flags().StringVar(&session, "session", "", "learn from one session instead (id or prefix)")
	cmd.Flags().StringVar(&outPath, "out", "", "write the policy to this file instead of stdout")
	cmd.Flags().IntVar(&loopGuard, "loop-guard", 10, "loop_guard.repeats to include; 0 to leave it out")
	return cmd
}

func writeSuggestion(w io.Writer, tools []*audit.ToolStat, sessions []*audit.Session, since, sessionID string, loopGuard int) {
	var (
		totalCalls, maxPerSession int
		denied, honeypots         []*audit.ToolStat
	)
	for _, s := range sessions {
		if s.Calls > maxPerSession {
			maxPerSession = s.Calls
		}
	}
	for _, t := range tools {
		totalCalls += t.Calls
	}
	scope := "everything recorded"
	switch {
	case sessionID != "":
		scope = "session " + shortID(sessionID)
	case since != "":
		scope = "the last " + since
	}
	fmt.Fprintf(w, "# Suggested by `agentgate policy suggest` on %s\n", time.Now().Format("2006-01-02"))
	fmt.Fprintf(w, "# Learned from %d calls in %d sessions (%s).\n", totalCalls, len(sessions), scope)
	fmt.Fprintf(w, "# This allows exactly what the agent did and nothing else. Read it before you trust it.\n")
	fmt.Fprintf(w, "policy:\n  default: deny\n")
	if maxPerSession > 0 {
		fmt.Fprintf(w, "  budget:\n    calls_per_session: %d   # busiest session had %d\n", roundUp(maxPerSession*2), maxPerSession)
	}
	if loopGuard > 0 {
		fmt.Fprintf(w, "  loop_guard:\n    repeats: %d\n", loopGuard)
	}
	fmt.Fprintf(w, "  rules:\n")
	sort.Slice(tools, func(i, j int) bool { return tools[i].Tool < tools[j].Tool })
	for _, t := range tools {
		if t.Upstream == "agentgate" {
			honeypots = append(honeypots, t)
			continue
		}
		if t.Allowed == 0 {
			denied = append(denied, t)
			continue
		}
		fmt.Fprintf(w, "    - id: allow-%s\n", ruleID(t.Tool))
		fmt.Fprintf(w, "      tool: %q\n", t.Tool)
		fmt.Fprintf(w, "      action: allow\n")
		note := fmt.Sprintf("%d calls", t.Calls)
		if t.Denied > 0 {
			note += fmt.Sprintf(", %d denied by the old policy — keep those rules above this one", t.Denied)
		}
		fmt.Fprintf(w, "      reason: %q\n", "observed: "+note)
	}
	if len(denied) > 0 {
		fmt.Fprintf(w, "    # Only ever denied, so no rule: %s\n", toolList(denied))
	}
	if len(honeypots) > 0 {
		fmt.Fprintf(w, "    # Honeypots tripped in this window: %s\n", toolList(honeypots))
	}
}

func ruleID(tool string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(tool) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(strings.ReplaceAll(b.String(), "--", "-"), "-")
}

func toolList(ts []*audit.ToolStat) string {
	names := make([]string, 0, len(ts))
	for _, t := range ts {
		names = append(names, t.Tool)
	}
	return strings.Join(names, ", ")
}

func roundUp(n int) int {
	switch {
	case n <= 10:
		return 10
	case n <= 100:
		return (n + 9) / 10 * 10
	default:
		return (n + 99) / 100 * 100
	}
}
