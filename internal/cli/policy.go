package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/config"
)

func newPolicyCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Work with the policy file",
	}
	cmd.AddCommand(newPolicyValidateCmd(g))
	return cmd
}

func newPolicyValidateCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "validate [file]",
		Short: "Check that a config file parses and its rules make sense",
		Long: `Load a config file and report every problem it has at once.

Validation covers more than YAML syntax: unknown keys, unknown matchers,
duplicate rule ids, invalid regexes, condition paths that no call could ever
have, and rules that would match every call by accident.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) == 1 {
				path = args[0]
			} else {
				var err error
				if path, err = g.configFile(); err != nil {
					return err
				}
			}
			cfg, err := config.Load(path)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s is valid\n\n", path)
			fmt.Fprintf(out, "policy     %s\n", cfg.Policy.Summary())
			fmt.Fprintf(out, "separator  %q\n", cfg.PrefixSeparator)
			fmt.Fprintf(out, "audit      %s (retention %s, cap %d bytes per result)\n",
				cfg.Audit.Path, cfg.Audit.Retention, cfg.Audit.MaxResultBytes)
			if cfg.Policy.Budget.CallsPerSession > 0 {
				fmt.Fprintf(out, "budget     %d calls per session\n", cfg.Policy.Budget.CallsPerSession)
			}
			fmt.Fprintln(out)

			t := newTable(out, "UPSTREAM", "TRANSPORT", "PREFIX", "TIMEOUT", "TARGET")
			for i := range cfg.Upstreams {
				u := &cfg.Upstreams[i]
				prefix := "-"
				if u.Prefix == nil || *u.Prefix {
					prefix = cfg.Prefixed(u, "")
				}
				target := u.HTTP
				if target == "" && len(u.Stdio) > 0 {
					target = fmt.Sprint(u.Stdio)
				}
				t.row(u.Name, u.Transport(), prefix, cfg.Timeout(u), truncate(target, 48))
			}
			t.flush()
			return nil
		},
	}
}
