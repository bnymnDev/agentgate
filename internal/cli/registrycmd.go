package cli

import (
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/anchor"
	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/pinning"
)

func newRegistryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Check a registry of trusted definitions against its append-only log",
		Long: `A registry that agentgate lock --publish writes keeps a log of every
publication, like Certificate Transparency: log.jsonl, append only, and
head.json, the size of the log and a Merkle root over it.

	agentgate registry verify ./mcp-registry
	agentgate registry verify https://example.com/mcp-registry --head 42:sha256:9f86...
	agentgate registry head ./mcp-registry --to ots:./registry-anchors

verify checks that every entry is what the log last recorded, that nothing
was slipped in by hand, and, given a head noted earlier, that the log only
grew since. It lists every server version published more than once with
different definitions: in a registry of trusted definitions, that is the
thing to look at.`,
	}
	cmd.AddCommand(newRegistryVerifyCmd(), newRegistryHeadCmd())
	return cmd
}

func newRegistryVerifyCmd() *cobra.Command {
	var (
		head   string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "verify <dir|url>",
		Short: "Check a registry against its log",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var prev *pinning.TreeHead
			if head != "" {
				h, err := pinning.ParseTreeHead(head)
				if err != nil {
					return err
				}
				prev = &h
			}
			rep, err := pinning.VerifyLog(cmd.Context(), args[0], prev, &http.Client{Timeout: 30 * time.Second})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				if err := writeJSON(out, rep); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(out, "%-9s %s\n", "registry", args[0])
				fmt.Fprintf(out, "%-9s %d publications, %d entries\n", "log", rep.Records, rep.Entries)
				fmt.Fprintf(out, "%-9s %s\n", "head", rep.Head)
				if prev != nil && rep.OK() {
					fmt.Fprintf(out, "%-9s the log only grew since %d records\n", "since", prev.Size)
				}
				for _, r := range rep.Rewrites {
					fmt.Fprintf(out, "%-9s %s\n", "republish", r)
				}
				fmt.Fprintln(out)
				if rep.OK() {
					fmt.Fprintln(out, "OK: every entry is what the log recorded, and nothing was added by hand.")
				} else {
					fmt.Fprintf(out, "BROKEN: %d problem(s)\n", len(rep.Problems))
					for _, p := range rep.Problems {
						fmt.Fprintf(out, "  %s\n", p)
					}
				}
			}
			if !rep.OK() {
				return errExitDenied
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&head, "head", "", "a head noted earlier, as size:root, that the log must still start with")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	return cmd
}

func newRegistryHeadCmd() *cobra.Command {
	var to []string
	cmd := &cobra.Command{
		Use:   "head <dir|url>",
		Short: "Print a registry's head, or send it somewhere it cannot be rewritten",
		Long: `Print the head of a registry's log as size:root. With --to, also send it to
the destinations agentgate anchor takes — a webhook, a file, or
OpenTimestamps — so that a later verify --head can prove the log only grew.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rep, err := pinning.VerifyLog(cmd.Context(), args[0], nil, &http.Client{Timeout: 30 * time.Second})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, rep.Head)
			st := anchor.New(audit.Link{Seq: int64(rep.Head.Size), Hash: rep.Head.Root}, args[0])
			for _, d := range to {
				dest, err := anchor.Parse(d, nil)
				if err != nil {
					return err
				}
				where, err := dest.Publish(cmd.Context(), st)
				if err != nil {
					return fmt.Errorf("%s: %w", dest, err)
				}
				fmt.Fprintf(out, "sent to %s\n", where)
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&to, "to", nil, "send the head here too: https://…, file:<path> or ots:<dir> (repeatable)")
	return cmd
}
