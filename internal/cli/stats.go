package cli

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
)

func newStatsCmd(g *globals) *cobra.Command {
	var (
		since    string
		session  string
		asJSON   bool
		markdown bool
		top      int
		failOn   string
	)
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "What did the agent actually do? Per tool, per rule",
		Long: `Summarise the audit log: calls per tool, what was denied and by which rule,
how long tools take, and roughly how many tokens went through them.

--markdown prints a table you can paste into a pull request or a post.

--fail-on turns it into a check, for CI or cron: it exits 1 when any of the
thresholds is crossed, and says which.

	agentgate stats --since 1h --fail-on 'canary>0,honeypot>0,denied>=10'
	agentgate stats --fail-on 'rule:baseline/rm-rf-root>0'

Counters: calls, denied, shadowed, honeypot, canary, quarantine, errors,
tokens, sessions, and rule:<id> for how often one rule decided.`,
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
			totals, err := store.Stats(cmd.Context(), cutoff)
			if err != nil {
				return err
			}
			tools, err := store.ToolStats(cmd.Context(), cutoff, sessionID)
			if err != nil {
				return err
			}
			rules, err := store.RuleStats(cmd.Context(), cutoff, sessionID)
			if err != nil {
				return err
			}
			var crossed []string
			if failOn != "" {
				if crossed, err = checkThresholds(failOn, totals, rules); err != nil {
					return err
				}
			}
			if top > 0 && len(tools) > top {
				tools = tools[:top]
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), map[string]any{
					"since": cutoff, "session": sessionID, "totals": totals, "tools": tools, "rules": rules,
				})
			}
			printStats(cmd.OutOrStdout(), markdown, since, sessionID, totals, tools, rules)
			if len(crossed) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "\nthreshold crossed: %s\n", strings.Join(crossed, ", "))
				return errExitDenied
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "24h", "window to summarise, e.g. 1h, 24h, 7d; empty for everything")
	cmd.Flags().StringVar(&session, "session", "", "summarise one session instead (id or prefix)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	cmd.Flags().BoolVar(&markdown, "markdown", false, "print as Markdown tables")
	cmd.Flags().IntVar(&top, "top", 25, "how many tools to list")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit 1 when a threshold is crossed, e.g. 'canary>0,denied>=10'")
	return cmd
}

var thresholdRe = regexp.MustCompile(`^\s*([a-z]+|rule:[^<>=!\s]+)\s*(>=|<=|>|<|==|=|!=)\s*(\d+)\s*$`)

// checkThresholds evaluates a --fail-on list against the numbers and returns
// the conditions that hold, as written.
func checkThresholds(spec string, t *audit.Stats, rules []*audit.RuleStat) ([]string, error) {
	var crossed []string
	for _, part := range strings.Split(spec, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		m := thresholdRe.FindStringSubmatch(part)
		if m == nil {
			return nil, fmt.Errorf("--fail-on %q: want counter, operator and number, like denied>0", strings.TrimSpace(part))
		}
		var value int
		switch name := m[1]; {
		case strings.HasPrefix(name, "rule:"):
			id := strings.TrimPrefix(name, "rule:")
			for _, r := range rules {
				if r.RuleID == id {
					value += r.Calls
				}
			}
		default:
			v, ok := map[string]int{
				"calls": t.Calls, "denied": t.Denied, "shadowed": t.Shadowed, "honeypot": t.Honeypots,
				"canary": t.Canaries, "quarantine": t.Quarantined, "errors": t.Errors, "tokens": t.Tokens,
				"sessions": t.Sessions,
			}[name]
			if !ok {
				return nil, fmt.Errorf("--fail-on: unknown counter %q", name)
			}
			value = v
		}
		limit, _ := strconv.Atoi(m[3])
		var hit bool
		switch m[2] {
		case ">":
			hit = value > limit
		case ">=":
			hit = value >= limit
		case "<":
			hit = value < limit
		case "<=":
			hit = value <= limit
		case "=", "==":
			hit = value == limit
		case "!=":
			hit = value != limit
		}
		if hit {
			crossed = append(crossed, fmt.Sprintf("%s (is %d)", strings.TrimSpace(part), value))
		}
	}
	return crossed, nil
}

func printStats(out io.Writer, md bool, since, sessionID string, t *audit.Stats, tools []*audit.ToolStat, rules []*audit.RuleStat) {
	scope := "everything"
	switch {
	case sessionID != "":
		scope = "session " + shortID(sessionID)
	case since != "":
		scope = "last " + since
	}
	if md {
		fmt.Fprintf(out, "### agentgate — %s\n\n", scope)
		fmt.Fprintf(out, "| sessions | calls | denied | shadowed | honeypot trips | canaries caught | quarantined | errors | tokens (est.) |\n|---|---|---|---|---|---|---|---|---|\n")
		fmt.Fprintf(out, "| %d | %d | %d | %d | %d | %d | %d | %d | %s |\n\n", t.Sessions, t.Calls, t.Denied, t.Shadowed, t.Honeypots, t.Canaries, t.Quarantined, t.Errors, humanTokens(t.Tokens))
		if len(tools) > 0 {
			fmt.Fprintf(out, "| tool | calls | allowed | denied | errors | avg ms | tokens |\n|---|---|---|---|---|---|---|\n")
			for _, s := range tools {
				fmt.Fprintf(out, "| `%s` | %d | %d | %d | %d | %.0f | %s |\n", s.Tool, s.Calls, s.Allowed, s.Denied, s.Errors, s.AvgMS, humanTokens(s.Tokens))
			}
			fmt.Fprintln(out)
		}
		if len(rules) > 0 {
			fmt.Fprintf(out, "| rule | decision | times |\n|---|---|---|\n")
			for _, r := range rules {
				fmt.Fprintf(out, "| `%s` | %s | %d |\n", r.RuleID, r.Decision, r.Calls)
			}
		}
		return
	}

	fmt.Fprintf(out, "agentgate stats — %s\n\n", scope)
	fmt.Fprintf(out, "  sessions %-6d calls %-6d denied %-6d shadowed %-6d errors %-4d tokens ~%s\n",
		t.Sessions, t.Calls, t.Denied, t.Shadowed, t.Errors, humanTokens(t.Tokens))
	fmt.Fprintf(out, "  honeypot trips %-4d canaries caught %-4d quarantined calls %d\n\n", t.Honeypots, t.Canaries, t.Quarantined)
	if len(tools) == 0 {
		fmt.Fprintln(out, "no calls recorded in this window")
		return
	}
	tb := newTable(out, "TOOL", "CALLS", "ALLOWED", "DENIED", "ERRORS", "AVG MS", "TOKENS", "LAST SEEN")
	for _, s := range tools {
		tb.row(truncate(s.Tool, 36), s.Calls, s.Allowed, s.Denied, s.Errors, fmt.Sprintf("%.0f", s.AvgMS),
			humanTokens(s.Tokens), s.LastSeen.Local().Format("01-02 15:04"))
	}
	tb.flush()
	if len(rules) > 0 {
		fmt.Fprintln(out)
		rb := newTable(out, "RULE", "DECISION", "TIMES")
		for _, r := range rules {
			rb.row(r.RuleID, r.Decision, r.Calls)
		}
		rb.flush()
	}
}

func humanTokens(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 10_000:
		return fmt.Sprintf("%.0fk", float64(n)/1e3)
	case n >= 1000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return fmt.Sprint(n)
}
