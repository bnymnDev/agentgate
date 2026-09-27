package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/killswitch"
	"github.com/bnymnDev/agentgate/internal/policy"
	"github.com/bnymnDev/agentgate/internal/policytest"
)

func newCheckCmd(g *globals) *cobra.Command {
	var (
		tool     string
		argsJSON string
		asJSON   bool
		counts   int
		at       string
		repeats  int
		host     string
		labels   []string
		called   []string
		hints    map[string]string
	)
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Dry-evaluate one call against the policy",
		Long: `Ask the policy what it would do with a call, without connecting to anything.

	agentgate check --tool db.query --args '{"sql":"DROP TABLE users"}'

Rules that look at the session or the host can be tested by describing them:

	agentgate check --tool mail.send --label untrusted-input --label private-data
	agentgate check --tool shell.deploy --called shell.test --host ci-bot

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
			exposed, upstream, name := cfg.ResolveTool(tool)
			annotations, err := parseHints(hints)
			if err != nil {
				return err
			}
			call := &policy.Call{
				Tool:        exposed,
				Upstream:    upstream,
				ToolName:    name,
				Args:        args,
				Counts:      policy.Counts{Session: counts, Tool: counts, Repeats: repeats},
				At:          when,
				Frozen:      killswitch.Engaged(cfg.FreezeFile()),
				Annotations: annotations,
			}
			call.Host.Name, call.Host.Version, _ = strings.Cut(host, "/")
			for _, l := range labels {
				if !policy.ValidLabel(l) {
					return fmt.Errorf("--label %q: labels are lower-case letters, digits, - and _", l)
				}
			}
			var track policy.Tracker
			track.Earn(labels...)
			for _, c := range called {
				exposed, up, nm := cfg.ResolveTool(c)
				track.Forwarded(&policy.Call{Tool: exposed, Upstream: up, ToolName: nm}, 0, when)
			}
			call.Session = track.History()
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
					if u := cfg.Upstream(upstream); u != nil && !u.Offers(name) {
						fmt.Fprintf(cmd.OutOrStdout(), "%-9s %s\n", "offered", "no — hidden by the upstream's tools: list, so the host never sees it")
					}
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
	cmd.Flags().StringVar(&host, "host", "", "the host that opened the session, as name or name/version, to test host.* rules")
	cmd.Flags().StringArrayVar(&labels, "label", nil, "a label the session already carries (repeatable)")
	cmd.Flags().StringArrayVar(&called, "called", nil, "a tool the session already called, as upstream.tool (repeatable)")
	cmd.Flags().StringToStringVar(&hints, "annotations", nil, "what the server says about the tool, e.g. read_only=true,destructive=false")
	return cmd
}

// parseHints turns --annotations into the policy's view of a tool's hints.
func parseHints(hints map[string]string) (policy.Annotations, error) {
	var a policy.Annotations
	for k, v := range hints {
		if k == "title" {
			a.Title = v
			continue
		}
		var b bool
		switch strings.ToLower(v) {
		case "true", "yes", "1":
			b = true
		case "false", "no", "0":
		default:
			return a, fmt.Errorf("--annotations %s=%s: want true or false", k, v)
		}
		switch k {
		case "read_only":
			a.ReadOnly = &b
		case "destructive":
			a.Destructive = &b
		case "idempotent":
			a.Idempotent = &b
		case "open_world":
			a.OpenWorld = &b
		default:
			return a, fmt.Errorf("--annotations: unknown hint %q, use read_only, destructive, idempotent, open_world or title", k)
		}
	}
	return a, nil
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

// parseWhen reads --at; see policytest.ParseWhen for what it understands.
func parseWhen(s string) (time.Time, error) {
	t, err := policytest.ParseWhen(s, time.Now())
	if err != nil {
		return t, fmt.Errorf("--at: %w", err)
	}
	return t, nil
}
