package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/canary"
	"github.com/bnymnDev/agentgate/internal/config"
)

func newCanaryCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "canary",
		Short: "Plant fake credentials and catch them leaving",
		Long: `A canary is a fake secret that looks exactly like a real one: an AWS key
pair, a GitHub token, an API key, a database password. Put it where an agent
could read it. Nothing legitimate ever sends it anywhere, so a tool call that
carries it out — plain, base64, hex, URL-encoded or reversed — is an
exfiltration attempt: agentgate denies it, records it with rule canary, fires
the exfiltration webhook event, and with canaries.action: freeze stops the
whole gateway.

	agentgate canary new --kind aws --write ~/work/app/.aws-credentials.bak
	agentgate canary list
	agentgate canary rm prod-aws`,
	}
	cmd.AddCommand(newCanaryNewCmd(g), newCanaryListCmd(g), newCanaryRmCmd(g))
	return cmd
}

func canaryStore(g *globals) (*canary.Store, *config.Config, error) {
	cfg, err := g.load()
	if err != nil {
		return nil, nil, err
	}
	store, err := canary.Open(cfg.Canaries.Path)
	return store, cfg, err
}

func newCanaryNewCmd(g *globals) *cobra.Command {
	var (
		kind, label, write string
		force              bool
	)
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a canary, and optionally the decoy file that holds it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, cfg, err := canaryStore(g)
			if err != nil {
				return err
			}
			c, err := canary.Generate(kind, label)
			if err != nil {
				return err
			}
			if write != "" {
				path, err := config.ExpandPath(write)
				if err != nil {
					return err
				}
				if path, err = filepath.Abs(path); err != nil {
					return err
				}
				if _, err := os.Stat(path); err == nil && !force {
					return fmt.Errorf("%s exists; pick another path or pass --force to overwrite it", path)
				}
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(path, []byte(c.Decoy()), 0o600); err != nil {
					return err
				}
				c.File = path
			}
			if err := store.Add(c); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "canary %s (%s", c.ID, c.Kind)
			if c.Label != "" {
				fmt.Fprintf(out, ", %s", c.Label)
			}
			fmt.Fprintln(out, ")")
			for _, v := range c.Values {
				fmt.Fprintf(out, "  %s\n", v)
			}
			if c.File != "" {
				fmt.Fprintf(out, "decoy written to %s\n", c.File)
			} else {
				fmt.Fprintln(out, "\nPut it somewhere an agent could read it — a .env, a notes file, a fake credentials file —")
				fmt.Fprintln(out, "or pass --write to have the decoy file written for you.")
			}
			fmt.Fprintf(out, "\nA call carrying it out is denied%s. Canaries live in %s.\n",
				map[bool]string{true: " and freezes the gateway", false: ""}[cfg.Canaries.Action == "freeze"], store.Path())
			return nil
		},
	}
	cmd.Flags().StringVar(&kind, "kind", "aws", "what the canary looks like: "+strings.Join(canary.Kinds, ", "))
	cmd.Flags().StringVar(&label, "label", "", "a name to recognise it by in alerts")
	cmd.Flags().StringVar(&write, "write", "", "write a decoy file holding the canary to this path")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite the --write file if it exists")
	return cmd
}

func newCanaryListCmd(g *globals) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the canaries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, _, err := canaryStore(g)
			if err != nil {
				return err
			}
			list := store.List()
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), list)
			}
			if len(list) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no canaries yet; agentgate canary new plants one")
				return nil
			}
			t := newTable(cmd.OutOrStdout(), "ID", "LABEL", "KIND", "CREATED", "VALUE", "DECOY FILE")
			for _, c := range list {
				t.row(c.ID, orDash(c.Label), c.Kind, c.CreatedAt.Local().Format(time.DateOnly),
					truncate(c.Values[0], 24), orDash(c.File))
			}
			t.flush()
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON, values included")
	return cmd
}

func newCanaryRmCmd(g *globals) *cobra.Command {
	var deleteFile bool
	cmd := &cobra.Command{
		Use:     "rm <id-or-label>",
		Aliases: []string{"remove"},
		Short:   "Retire a canary",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, _, err := canaryStore(g)
			if err != nil {
				return err
			}
			gone, err := store.Remove(args[0])
			if err != nil {
				return err
			}
			for _, c := range gone {
				fmt.Fprintf(cmd.OutOrStdout(), "removed canary %s\n", c.ID)
				if deleteFile && c.File != "" {
					if err := os.Remove(c.File); err != nil && !errors.Is(err, os.ErrNotExist) {
						return err
					}
					fmt.Fprintf(cmd.OutOrStdout(), "deleted %s\n", c.File)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&deleteFile, "delete-file", false, "also delete the decoy file it was written to")
	return cmd
}
