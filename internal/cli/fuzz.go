package cli

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/policytest"
)

func newFuzzCmd(g *globals) *cobra.Command {
	var (
		asJSON   bool
		markdown bool
		run      string
	)
	cmd := &cobra.Command{
		Use:   "fuzz [test-file]",
		Short: "Find spellings of a stopped call that the policy lets through",
		Long: `Take every policy test that expects a call to be denied or asked about, and
try it again spelled differently but meaning the same: a shell command run
through env, sh -c or after another command, with its flags split or its
name quoted; a path with a ./ or a detour through ..; SQL in lower case,
split by comments or newlines, behind a harmless statement; a URL with the
host in capitals, a trailing dot or user info in front.

Every variant that gets a weaker decision than the test expects is a
bypass: the rule matched how the call was written, not what it does. Exits
1 when there is one, so it can guard a policy in CI next to agentgate test.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			path := policytest.DefaultPath(cfg.Path)
			if len(args) == 1 {
				path = args[0]
			}
			f, err := policytest.Load(path)
			if err != nil {
				return fmt.Errorf("%w; agentgate fuzz works from the policy tests, see agentgate test", err)
			}
			opts := policytest.Options{Config: cfg}
			if run != "" {
				if opts.Match, err = regexp.Compile(run); err != nil {
					return fmt.Errorf("--run: %w", err)
				}
			}
			rep := policytest.Fuzz(f, opts)
			out := cmd.OutOrStdout()
			switch {
			case asJSON:
				if err := writeJSON(out, rep); err != nil {
					return err
				}
			case markdown:
				fmt.Fprint(out, rep.Markdown())
			default:
				for _, b := range rep.Bypasses {
					fmt.Fprintf(out, "BYPASS  %s  (%s, %s)\n        %s: %s instead of %s\n        %q\n",
						b.Test, b.Tool, b.Arg, b.Technique, b.Got.Action, b.Expected, b.Variant)
				}
				if len(rep.Bypasses) > 0 {
					fmt.Fprintln(out)
				}
				fmt.Fprintf(out, "%d variants of %d tests that must stop a call; %d got through\n", rep.Variants, rep.Tests, len(rep.Bypasses))
			}
			if len(rep.Bypasses) > 0 {
				return errExitDenied
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	cmd.Flags().BoolVar(&markdown, "markdown", false, "print the report as Markdown")
	cmd.Flags().StringVar(&run, "run", "", "only fuzz the tests whose name matches this regex")
	return cmd
}
