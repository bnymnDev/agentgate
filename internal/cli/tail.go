package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/killswitch"
	"github.com/bnymnDev/agentgate/internal/policy"
)

func newTailCmd(g *globals) *cobra.Command {
	var (
		session  string
		last     int
		noFollow bool
		asJSON   bool
		showArgs bool
	)
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Watch tool calls scroll by, live",
		Long: `Print calls as they are recorded, one line each, until interrupted.

It reads the audit database, so it works against any running gateway that
shares the config — including one launched by an editor as a subprocess, whose
stdout you could never see. Colours are on when stdout is a terminal.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			store, err := g.openStore(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer closeStore(store)

			out := cmd.OutOrStdout()
			colour := !asJSON && isatty.IsTerminal(os.Stdout.Fd()) && os.Getenv("NO_COLOR") == ""
			w := &lineWriter{out: out, colour: colour, args: showArgs, json: asJSON}

			sessionID := ""
			if session != "" {
				sess, err := store.GetSession(cmd.Context(), session)
				if err != nil {
					return err
				}
				sessionID = sess.ID
			}

			// Start with the most recent few, so the screen is not empty.
			recent, err := store.ListCalls(cmd.Context(), audit.CallFilter{SessionID: sessionID, Limit: 100000})
			if err != nil {
				return err
			}
			if last > 0 && len(recent) > last {
				recent = recent[len(recent)-last:]
			}
			lastID := ""
			for _, c := range recent {
				w.write(c)
				lastID = c.ID
			}
			if len(recent) > 0 && lastID < recent[len(recent)-1].ID {
				lastID = recent[len(recent)-1].ID
			}
			if noFollow {
				return nil
			}
			if !asJSON {
				fmt.Fprintf(out, "%s\n", w.dim("── following "+cfg.Audit.Path+" (ctrl-c to stop) ──"))
			}

			frozen := killswitch.Engaged(cfg.FreezeFile())
			if frozen && !asJSON {
				fmt.Fprintln(out, w.paint(colourRed, "the gateway is FROZEN"))
			}
			ticker := time.NewTicker(400 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-cmd.Context().Done():
					return nil
				case <-ticker.C:
				}
				fresh, err := store.ListCalls(cmd.Context(), audit.CallFilter{SessionID: sessionID, AfterID: lastID, Limit: 1000})
				if err != nil {
					return err
				}
				for _, c := range fresh {
					w.write(c)
					lastID = c.ID
				}
				if now := killswitch.Engaged(cfg.FreezeFile()); now != frozen && !asJSON {
					frozen = now
					if frozen {
						fmt.Fprintln(out, w.paint(colourRed, "the gateway is now FROZEN"))
					} else {
						fmt.Fprintln(out, w.paint(colourGreen, "the gateway is unfrozen"))
					}
				}
			}
		},
	}
	cmd.Flags().StringVar(&session, "session", "", "only calls of this session (id or prefix)")
	cmd.Flags().IntVar(&last, "last", 20, "how many recent calls to show before following")
	cmd.Flags().BoolVar(&noFollow, "no-follow", false, "print the recent calls and exit")
	cmd.Flags().BoolVar(&asJSON, "json", false, "one JSON object per line")
	cmd.Flags().BoolVar(&showArgs, "args", false, "show the arguments on every line")
	return cmd
}

const (
	colourReset  = "\033[0m"
	colourDim    = "\033[2m"
	colourRed    = "\033[31;1m"
	colourGreen  = "\033[32m"
	colourYellow = "\033[33;1m"
	colourPurple = "\033[35m"
	colourCyan   = "\033[36m"
)

type lineWriter struct {
	out    io.Writer
	colour bool
	args   bool
	json   bool
}

func (w *lineWriter) paint(code, s string) string {
	if !w.colour {
		return s
	}
	return code + s + colourReset
}

func (w *lineWriter) dim(s string) string { return w.paint(colourDim, s) }

func (w *lineWriter) write(c *audit.Call) {
	if w.json {
		_ = json.NewEncoder(w.out).Encode(c)
		return
	}
	var badge string
	switch {
	case c.RuleID == policy.RuleHoneypot:
		badge = w.paint(colourRed, "TRAP   ")
	case c.Shadow:
		badge = w.paint(colourPurple, "SHADOW ")
	case c.Decision == policy.ActionDeny:
		badge = w.paint(colourRed, "DENY   ")
	case c.Decision == policy.ActionAsk:
		badge = w.paint(colourYellow, "ASK    ")
	case c.IsError:
		badge = w.paint(colourYellow, "ERROR  ")
	default:
		badge = w.paint(colourGreen, "allow  ")
	}
	detail := c.Reason
	if c.Error != "" {
		detail = c.Error
	}
	if c.Shadow {
		detail = "would have " + string(c.Decision) + ": " + c.Reason
	}
	if detail != "" {
		detail = w.dim(truncate(detail, 70))
	}
	line := fmt.Sprintf("%s  %s %-32s %6dms  %s",
		w.dim(c.TS.Local().Format("15:04:05")), badge, w.paint(colourCyan, truncate(c.Tool, 32)), c.DurationMS, detail)
	if w.args && len(c.Args) > 0 {
		line += "\n           " + w.dim(truncate(string(c.Args), 160))
	}
	fmt.Fprintln(w.out, strings.TrimRight(line, " "))
}
