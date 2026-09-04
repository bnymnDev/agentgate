package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/replay"
)

func newDiffCmd(g *globals) *cobra.Command {
	var (
		asJSON bool
		all    bool
	)
	cmd := &cobra.Command{
		Use:   "diff <session-a> <session-b>",
		Short: "Compare two recorded sessions",
		Long: `Compare two sessions call by call.

The two call lists are aligned on tool names, so an inserted or removed call
shows up as a single row instead of shifting everything after it. For calls that
line up, the argument and result hashes decide whether anything changed.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			store, err := g.openStore(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer closeStore(store)

			a, callsA, err := loadSession(cmd, store, args[0])
			if err != nil {
				return err
			}
			b, callsB, err := loadSession(cmd, store, args[1])
			if err != nil {
				return err
			}
			d := replay.Compare(a.ID, b.ID, callsA, callsB)
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), d)
			}
			printDiff(cmd, d, all)
			if !d.Identical() {
				return &silentError{code: 1}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the diff as JSON")
	cmd.Flags().BoolVar(&all, "all", false, "also list calls that are identical")
	return cmd
}

func loadSession(cmd *cobra.Command, store *audit.Store, id string) (*audit.Session, []*audit.Call, error) {
	sess, err := store.GetSession(cmd.Context(), id)
	if err != nil {
		return nil, nil, err
	}
	calls, err := store.ListCalls(cmd.Context(), audit.CallFilter{SessionID: sess.ID})
	if err != nil {
		return nil, nil, err
	}
	return sess, calls, nil
}

func printDiff(cmd *cobra.Command, d *replay.Diff, all bool) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "a  %s\nb  %s\n\n", d.SessionA, d.SessionB)
	t := newTable(out, "", "TOOL", "STATUS", "A", "B")
	shown := 0
	for _, r := range d.Rows {
		if r.Status == replay.StatusSame && !all {
			continue
		}
		shown++
		t.row(marker(r.Status), truncate(r.Tool, 34), r.Status, cellFor(r.A), cellFor(r.B))
	}
	t.flush()
	if shown == 0 {
		fmt.Fprintln(out, "the two sessions are identical")
	}
	summary := d.Summary()
	fmt.Fprintf(out, "\n%d same, %d different arguments, %d different results, %d different decisions, %d only in a, %d only in b\n",
		summary[replay.StatusSame], summary[replay.StatusArgs], summary[replay.StatusResult],
		summary[replay.StatusDecision], summary[replay.StatusOnlyA], summary[replay.StatusOnlyB])
}

func marker(s replay.Status) string {
	switch s {
	case replay.StatusOnlyA:
		return "-"
	case replay.StatusOnlyB:
		return "+"
	case replay.StatusSame:
		return " "
	default:
		return "~"
	}
}

func cellFor(c *audit.Call) string {
	if c == nil {
		return "-"
	}
	return fmt.Sprintf("%s %s", c.Decision, shortID(c.ResultHash))
}
