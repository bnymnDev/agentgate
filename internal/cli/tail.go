package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"golang.org/x/term"

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
		colour   string
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
			useColour, err := colourFlag(colour)
			if err != nil {
				return err
			}
			w := &lineWriter{out: out, colour: useColour && !asJSON, args: showArgs, json: asJSON,
				width: terminalWidth(), toolWidth: 20}

			sessionID := ""
			if session != "" {
				sess, err := store.GetSession(cmd.Context(), session)
				if err != nil {
					return err
				}
				sessionID = sess.ID
			}

			// Start with the most recent few, so the screen is not empty, up
			// to the head of the chain the follow loop starts from.
			head, err := store.Head(cmd.Context())
			if err != nil {
				return err
			}
			recent, err := store.ListCalls(cmd.Context(), audit.CallFilter{SessionID: sessionID, Newest: true, Limit: max(last, 1)})
			if err != nil {
				return err
			}
			if last <= 0 {
				recent = nil
			}
			for i := len(recent) - 1; i >= 0; i-- {
				if recent[i].Seq > head.Seq {
					continue // the follow loop prints it
				}
				w.write(recent[i])
			}
			// Follow the chain: every call recorded from here on, in the order
			// it was recorded, including slow ones that started earlier.
			lastSeq := head.Seq
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
				fresh, err := store.ListCalls(cmd.Context(), audit.CallFilter{SessionID: sessionID, SeqAfter: &lastSeq, Limit: 1000})
				if err != nil {
					return err
				}
				for _, c := range fresh {
					w.write(c)
					lastSeq = max(lastSeq, c.Seq)
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
	cmd.Flags().StringVar(&colour, "color", "auto", "colour the output: auto, always or never")
	return cmd
}

// colourFlag resolves a --color flag: auto means when stdout is a terminal
// and NO_COLOR is not set.
func colourFlag(mode string) (bool, error) {
	switch mode {
	case "always":
		return true, nil
	case "never":
		return false, nil
	case "auto":
		return isatty.IsTerminal(os.Stdout.Fd()) && os.Getenv("NO_COLOR") == "", nil
	default:
		return false, fmt.Errorf("--color: want auto, always or never, got %q", mode)
	}
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
	// width is the terminal's, or 0 when it is not known; a line is cut to
	// fit it.
	width int
	// toolWidth is the tool column's, which grows to fit the longest name.
	toolWidth int
}

// terminalWidth is the width of the terminal stdout is, or else $COLUMNS, or
// else 0.
func terminalWidth() int {
	if fd := int(os.Stdout.Fd()); term.IsTerminal(fd) {
		if w, _, err := term.GetSize(fd); err == nil && w > 0 {
			return w
		}
	}
	if w, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && w > 0 {
		return w
	}
	return 0
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
	case c.RuleID == policy.RuleCanary:
		badge = w.paint(colourRed, "CANARY ")
	case c.RuleID == policy.RuleQuarantine:
		badge = w.paint(colourRed, "HELD   ")
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
		detail = "would have " + pastTense(c.Decision) + ": " + c.Reason
	}
	tool := truncate(c.Tool, 48)
	w.toolWidth = max(w.toolWidth, utf8.RuneCountInString(tool))
	tool += strings.Repeat(" ", w.toolWidth-utf8.RuneCountInString(tool))
	ms := fmt.Sprintf("%6dms", c.DurationMS)
	// What is left of the line for the detail: the time, the badge, the tool
	// and the duration come first.
	room := 70
	if w.width > 0 {
		room = max(w.width-(8+2+7+1+w.toolWidth+1+len(ms)+2), 16)
	}
	if len(c.Labels) > 0 {
		// What the session learned with this call matters more than the
		// default reason it was allowed for.
		earned := "+" + strings.Join(c.Labels, " +")
		if c.RuleID == "" {
			detail = earned
		} else {
			detail = earned + "  " + detail
		}
		detail = w.paint(colourPurple, truncate(detail, room))
	} else if detail != "" {
		detail = w.dim(truncate(detail, room))
	}
	line := fmt.Sprintf("%s  %s %s %s  %s",
		w.dim(c.TS.Local().Format("15:04:05")), badge, w.paint(colourCyan, tool), ms, detail)
	if w.args && len(c.Args) > 0 {
		argRoom := 160
		if w.width > 0 {
			argRoom = max(w.width-11, 16)
		}
		line += "\n           " + w.dim(truncate(string(c.Args), argRoom))
	}
	fmt.Fprintln(w.out, strings.TrimRight(line, " "))
}

func pastTense(a policy.Action) string {
	switch a {
	case policy.ActionDeny:
		return "denied"
	case policy.ActionAsk:
		return "asked"
	default:
		return "allowed"
	}
}
