package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/policy"
)

func newCheckCmd(g *globals) *cobra.Command {
	var (
		tool     string
		argsJSON string
		asJSON   bool
		counts   int
	)
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Dry-evaluate one call against the policy",
		Long: `Ask the policy what it would do with a call, without connecting to anything.

	agentgate check --tool shopware.stock_set --args '{"stock":0}'

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
			upstream, name, _ := cfg.SplitTool(tool)
			call := &policy.Call{
				Tool:     tool,
				Upstream: upstream,
				ToolName: name,
				Args:     args,
				Counts:   policy.Counts{Session: counts, Tool: counts},
			}
			decision := policy.Evaluate(&cfg.Policy, call)

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
			}
			if decision.Action == policy.ActionDeny {
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
