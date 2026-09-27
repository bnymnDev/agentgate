package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/packs"
	"github.com/bnymnDev/agentgate/internal/policy"
)

func newPolicyPacksCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "packs",
		Short: "List the policy packs that ship with agentgate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			t := newTable(out, "PACK", "RULES", "PARAMETERS", "WHAT IT DOES")
			for _, name := range packs.Names() {
				src, _ := packs.Get(name)
				head, err := policy.ReadPackHeader(src)
				if err != nil {
					return fmt.Errorf("pack %s: %w", name, err)
				}
				rules, labels := packSize(src, head)
				size := fmt.Sprint(rules)
				if labels > 0 {
					size += fmt.Sprintf(" +%d labels", labels)
				}
				t.row(name, size, orDash(strings.Join(paramNames(head), ", ")), truncate(firstSentence(head.Description), 72))
			}
			t.flush()
			fmt.Fprintln(out, "\nagentgate policy pack <name> shows one in full; agentgate policy add <name> switches it on.")
			return nil
		},
	}
}

func newPolicyPackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pack <name>",
		Short: "Show a policy pack: what it does, its parameters and its rules",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, ok := packs.Get(args[0])
			if !ok {
				return fmt.Errorf("unknown pack %q; agentgate policy packs lists them", args[0])
			}
			_, err := cmd.OutOrStdout().Write(src)
			return err
		},
	}
}

func newPolicyAddCmd(g *globals) *cobra.Command {
	var with map[string]string
	cmd := &cobra.Command{
		Use:   "add <pack>",
		Short: "Switch a policy pack on in the config file",
		Long: `Add a pack to policy.packs in the config file. Only the lines of the list
change; the rest of the file, comments and blank lines included, stays as it is.

	agentgate policy add baseline
	agentgate policy add filesystem --with workspace=~/code/app
	agentgate policy add ./packs/team.yaml

The edited config is validated before it is written; if the pack needs a
parameter you did not give, nothing is changed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return editConfig(cmd, g, func(raw []byte) ([]byte, error) {
				return addPackText(raw, policy.PackRef{Name: args[0], With: with})
			}, "added pack "+args[0])
		},
	}
	cmd.Flags().StringToStringVar(&with, "with", nil, "a value for one of the pack's parameters, as key=value (repeatable)")
	return cmd
}

func newPolicyRemoveCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <pack>",
		Short: "Switch a policy pack off in the config file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return editConfig(cmd, g, func(raw []byte) ([]byte, error) {
				return removePackText(raw, args[0])
			}, "removed pack "+args[0])
		},
	}
}

// editConfig applies edit to the config file, validates the result and only
// then writes it back.
func editConfig(cmd *cobra.Command, g *globals, edit func([]byte) ([]byte, error), done string) error {
	path, err := g.configFile()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out, err := edit(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := validateAt(path, out); err != nil {
		return fmt.Errorf("%s not changed: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, out, info.Mode().Perm()); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s in %s\n", done, path)
	return nil
}

// validateAt checks config bytes as if they were the file at path, so that
// pack files are found relative to it.
func validateAt(path string, raw []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agentgate-*.yaml")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := config.Load(tmp.Name()); err != nil {
		// The error names the scratch copy; the user knows the file as path.
		return errors.New(strings.TrimPrefix(err.Error(), tmp.Name()+": "))
	}
	return nil
}

func packItemName(item *yaml.Node) string {
	switch item.Kind {
	case yaml.ScalarNode:
		return item.Value
	case yaml.MappingNode:
		if v := mapValue(item, "name"); v != nil {
			return v.Value
		}
	}
	return ""
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func paramNames(head *policy.PackFile) []string {
	var out []string
	for name, p := range head.Params {
		if p.Required {
			name += " (required)"
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// packSize counts a pack's rules and label rules without expanding it.
func packSize(src []byte, head *policy.PackFile) (rules, labels int) {
	with := map[string]string{}
	for name, p := range head.Params {
		if p.Required {
			with[name] = "x"
		}
	}
	pack, err := policy.ExpandPack(src, policy.PackRef{Name: head.Name, With: with}, nil)
	if err != nil {
		return 0, 0
	}
	return len(pack.Rules), len(pack.Labels)
}

func firstSentence(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}
