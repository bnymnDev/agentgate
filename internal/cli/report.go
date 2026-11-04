package cli

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/report"
)

func newReportCmd(g *globals) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "report <session-id | last>",
		Short: "Write one session as a self-contained HTML report",
		Long: `Write one session as a single HTML file: what the agent did, what was
stopped and why, which tools it used, what it touched, and whether the audit
chain still holds for its calls.

The file has no scripts and loads nothing from anywhere, so it can be
attached to a ticket, mailed to whoever has to sign off, or archived:

	agentgate report last -o session.html
	agentgate report 01J9Z3... > incident.html`,
		Args: cobra.ExactArgs(1),
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

			id := args[0]
			if id == "last" {
				list, err := store.ListSessions(cmd.Context(), audit.SessionFilter{Limit: 1})
				if err != nil {
					return err
				}
				if len(list) == 0 {
					return errors.New("no sessions recorded yet")
				}
				id = list[0].ID
			}
			sess, err := store.GetSession(cmd.Context(), id)
			if err != nil {
				return err
			}
			calls, err := store.ListCalls(cmd.Context(), audit.CallFilter{SessionID: sess.ID, Limit: 100000})
			if err != nil {
				return err
			}
			chain, err := store.Verify(cmd.Context(), nil)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if out != "" && out != "-" {
				f, err := os.Create(out)
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				w = f
			}
			if err := report.Write(w, report.Input{Session: sess, Calls: calls, Chain: chain, Version: version(), Now: time.Now()}); err != nil {
				return err
			}
			if out != "" && out != "-" {
				fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s (%d calls)\n", out, len(calls))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "write to this file instead of stdout")
	return cmd
}
