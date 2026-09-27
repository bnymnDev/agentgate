package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
)

func newVerifyCmd(g *globals) *cobra.Command {
	var (
		anchor string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Prove the audit log has not been edited",
		Long: `Walk the audit log's hash chain and report every break in it.

Every recorded call is linked to the one before it by a hash over its full
contents. Changing a stored call, deleting one or slipping one in breaks the
chain from that point on, and verify says where.

The one thing a chain cannot show by itself is its end being cut off. verify
prints the current head; keep it somewhere the machine cannot rewrite (a
ticket, a commit, a chat message) and pass it back later:

	agentgate verify --anchor 1234:9f86d081884c7d65...

which also proves that nothing up to that call has been touched since.

Exits 1 when the chain is broken, so it can run in CI or from cron.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			var expect *audit.Link
			if anchor != "" {
				l, err := audit.ParseLink(anchor)
				if err != nil {
					return err
				}
				expect = &l
			}
			store, err := g.openStore(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer closeStore(store)

			report, err := store.Verify(cmd.Context(), expect)
			if err != nil {
				return err
			}
			if asJSON {
				if err := writeJSON(cmd.OutOrStdout(), report); err != nil {
					return err
				}
			} else {
				out := cmd.OutOrStdout()
				fmt.Fprintf(out, "%-8s %s\n", "log", cfg.Audit.Path)
				fmt.Fprintf(out, "%-8s %d calls checked\n", "chain", report.Checked)
				if report.Anchor != nil {
					when := ""
					if at, ok, err := store.PrunedAt(cmd.Context()); err == nil && ok {
						when = " on " + at.Local().Format(time.DateOnly)
					}
					fmt.Fprintf(out, "%-8s retention removed calls up to seq %d%s; the rest links to it\n",
						"pruned", report.Anchor.Seq, when)
				}
				if report.Legacy > 0 {
					fmt.Fprintf(out, "%-8s %d calls were recorded before the chain existed and are not covered\n",
						"legacy", report.Legacy)
				}
				if report.Head.Seq > 0 {
					fmt.Fprintf(out, "%-8s %s\n", "head", report.Head)
				}
				if expect != nil && report.AnchorChecked {
					fmt.Fprintf(out, "%-8s %s is still part of the chain\n", "anchor", expect)
				}
				fmt.Fprintln(out)
				if report.OK() {
					fmt.Fprintln(out, "OK: no recorded call has been changed, removed or reordered.")
					if report.Head.Seq > 0 && expect == nil {
						fmt.Fprintln(out, "Keep the head somewhere else and pass it to --anchor next time to also catch a cut-off end.")
					}
				} else {
					fmt.Fprintf(out, "BROKEN: %d problem(s)\n", len(report.Problems))
					for _, p := range report.Problems {
						id := ""
						if p.CallID != "" {
							id = " (call " + p.CallID + ")"
						}
						fmt.Fprintf(out, "  seq %d%s %s\n", p.Seq, id, p.What)
					}
				}
			}
			if !report.OK() {
				return errExitDenied
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&anchor, "anchor", "", "a head printed by an earlier verify, as seq:hash, that must still be in the chain")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	return cmd
}
