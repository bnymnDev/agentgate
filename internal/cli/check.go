package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/killswitch"
	"github.com/bnymnDev/agentgate/internal/policy"
)

func newCheckCmd(g *globals) *cobra.Command {
	var (
		tool     string
		argsJSON string
		asJSON   bool
		counts   int
		at       string
		repeats  int
	)
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Dry-evaluate one call against the policy",
		Long: `Ask the policy what it would do with a call, without connecting to anything.

	agentgate check --tool db.query --args '{"sql":"DROP TABLE users"}'

Nothing is sent upstream and nothing is recorded; this only runs the evaluator.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			if tool == "" {
				return fmt.Errorf("--tool is required, for example --tool %s", exampleTool(cfg.PrefixSeparator))
			}
			args, err := parseArgs(argsJSON)
			if err != nil {
				return err
			}
			when := time.Now()
			if at != "" {
				parsed, err := parseWhen(at)
				if err != nil {
					return err
				}
				when = parsed
			}
			upstream, name, _ := cfg.SplitTool(tool)
			call := &policy.Call{
				Tool:     tool,
				Upstream: upstream,
				ToolName: name,
				Args:     args,
				Counts:   policy.Counts{Session: counts, Tool: counts, Repeats: repeats},
				At:       when,
				Frozen:   killswitch.Engaged(cfg.FreezeFile()),
			}
			decision := policy.Evaluate(&cfg.Policy, call)
			shadow := cfg.Policy.IsShadow() && decision.Action != policy.ActionAllow

			if asJSON {
				out, err := json.MarshalIndent(map[string]any{
					"call":     call,
					"decision": decision,
				}, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "%-9s %s\n", "tool", tool)
				if upstream != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "%-9s %s (as %s)\n", "upstream", upstream, name)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-9s %s\n", "decision", strings.ToUpper(string(decision.Action)))
				fmt.Fprintf(cmd.OutOrStdout(), "%-9s %s\n", "reason", decision.Reason)
				if decision.RuleID != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "%-9s %s\n", "rule", decision.RuleID)
				}
				if at != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "%-9s %s\n", "at", when.Format(time.RFC1123))
				}
				if shadow {
					fmt.Fprintf(cmd.OutOrStdout(), "%-9s %s\n", "mode", "shadow — the call would still be forwarded")
				}
			}
			if decision.Action == policy.ActionDeny && !shadow {
				// A non-zero exit makes `check` usable as a test in CI.
				return errExitDenied
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tool, "tool", "", "tool name as the host sees it, prefix included")
	cmd.Flags().StringVar(&argsJSON, "args", "", "tool arguments as a JSON object")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the call and the decision as JSON")
	cmd.Flags().IntVar(&counts, "calls-so-far", 0, "pretend this many calls were already made, to test budgets")
	cmd.Flags().IntVar(&repeats, "repeats", 0, "pretend the identical call was just made this many times, to test the loop guard")
	cmd.Flags().StringVar(&at, "at", "", "evaluate as if the call were made at this time, e.g. \"2026-09-04 16:30\" or \"friday 17:00\", to test time rules")
	return cmd
}

// errExitDenied makes `agentgate check` fail when the call would be denied,
// without printing a second error message.
var errExitDenied = &silentError{code: 1}

type silentError struct{ code int }

func (e *silentError) Error() string { return "" }

func parseArgs(raw string) (map[string]any, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var args map[string]any
	if err := dec.Decode(&args); err != nil {
		return nil, fmt.Errorf("--args must be a JSON object: %w", err)
	}
	return args, nil
}

func exampleTool(sep string) string { return "fs" + sep + "write_file" }

// parseWhen understands a few spellings of a point in time: RFC3339, a date
// with a time, a time alone (today), or a weekday with a time (the coming one).
func parseWhen(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	now := time.Now()
	if t, err := time.ParseInLocation("15:04", s, time.Local); err == nil {
		return time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, time.Local), nil
	}
	fields := strings.Fields(strings.ToLower(s))
	if len(fields) == 2 {
		for d := time.Sunday; d <= time.Saturday; d++ {
			if strings.HasPrefix(strings.ToLower(d.String()), fields[0]) {
				clock, err := time.ParseInLocation("15:04", fields[1], time.Local)
				if err != nil {
					break
				}
				days := (int(d) - int(now.Weekday()) + 7) % 7
				day := now.AddDate(0, 0, days)
				return time.Date(day.Year(), day.Month(), day.Day(), clock.Hour(), clock.Minute(), 0, 0, time.Local), nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("--at: cannot parse %q; use RFC3339, \"2006-01-02 15:04\", \"15:04\" or \"friday 17:00\"", s)
}
