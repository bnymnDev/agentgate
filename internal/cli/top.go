package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/killswitch"
	"github.com/bnymnDev/agentgate/internal/policy"
)

func newTopCmd(g *globals) *cobra.Command {
	var (
		window   time.Duration
		interval time.Duration
		once     bool
		colour   string
	)
	cmd := &cobra.Command{
		Use:   "top",
		Short: "Watch the gateway live: sessions, tools and decisions",
		Long: `A live view of the audit log, refreshed every second: the sessions of the
last hour, the tools they call and how often they are stopped, and the most
recent decisions. It reads the log only, so it works next to any running
agentgate, on the same machine or over a copy of the database.

Press q to leave. --once prints one frame and exits, for a script or a
terminal that is not interactive.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			useColour, err := colourFlag(colour)
			if err != nil {
				return err
			}
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
			stdin := int(os.Stdin.Fd())
			interactive := !once && term.IsTerminal(stdin) && term.IsTerminal(int(os.Stdout.Fd()))
			if !interactive {
				frame, err := topFrame(cmd.Context(), cfg, store, window, useColour, terminalWidth(), 0)
				if err != nil {
					return err
				}
				_, err = io.WriteString(out, frame)
				return err
			}

			old, err := term.MakeRaw(stdin)
			if err != nil {
				return err
			}
			defer func() { _ = term.Restore(stdin, old) }()
			fmt.Fprint(out, "\x1b[?1049h\x1b[?25l")
			defer fmt.Fprint(out, "\x1b[?25h\x1b[?1049l")

			keys := make(chan byte)
			go func() {
				buf := make([]byte, 1)
				for {
					if n, err := os.Stdin.Read(buf); err != nil || n == 0 {
						close(keys)
						return
					}
					keys <- buf[0]
				}
			}()
			tick := time.NewTicker(interval)
			defer tick.Stop()
			for {
				w, h, _ := term.GetSize(int(os.Stdout.Fd()))
				frame, err := topFrame(cmd.Context(), cfg, store, window, useColour, w, h)
				if err != nil {
					frame = "agentgate top: " + err.Error() + "\n"
				}
				// Raw mode needs \r\n; the screen is redrawn from the top.
				fmt.Fprint(out, "\x1b[H\x1b[2J"+strings.ReplaceAll(frame, "\n", "\r\n"))
				select {
				case <-cmd.Context().Done():
					return nil
				case k, ok := <-keys:
					if !ok || k == 'q' || k == 'Q' || k == 3 || k == 27 {
						return nil
					}
				case <-tick.C:
				}
			}
		},
	}
	cmd.Flags().DurationVar(&window, "window", time.Hour, "how far back to look")
	cmd.Flags().DurationVar(&interval, "interval", time.Second, "how often to refresh")
	cmd.Flags().BoolVar(&once, "once", false, "print one frame and exit")
	cmd.Flags().StringVar(&colour, "color", "auto", "colour the output: auto, always or never")
	return cmd
}

// topFrame renders one screen. height 0 means no limit.
func topFrame(ctx context.Context, cfg *config.Config, store *audit.Store, window time.Duration, colour bool, width, height int) (string, error) {
	now := time.Now()
	since := now.Add(-window)
	w := &lineWriter{colour: colour}
	stats, err := store.Stats(ctx, since)
	if err != nil {
		return "", err
	}
	recent, err := store.Stats(ctx, now.Add(-time.Minute))
	if err != nil {
		return "", err
	}
	sessions, err := store.ListSessions(ctx, audit.SessionFilter{Since: since, Limit: 8})
	if err != nil {
		return "", err
	}
	tools, err := store.ToolStats(ctx, since, "")
	if err != nil {
		return "", err
	}
	calls, err := store.ListCalls(ctx, audit.CallFilter{Since: since, Newest: true, Limit: 10})
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	state := w.paint(colourGreen, "running")
	if _, frozen := killswitch.Status(cfg.FreezeFile()); frozen {
		state = w.paint(colourRed, "FROZEN")
	} else if cfg.Policy.IsShadow() {
		state = w.paint(colourPurple, "shadow")
	}
	span := strings.TrimSuffix(strings.TrimSuffix(window.String(), "0s"), "0m")
	fmt.Fprintf(&b, "agentgate top  %s  %s  last %s\n\n", state, now.Format("15:04:05"), span)
	fmt.Fprintf(&b, "calls %d  denied %s  shadow %d  quarantined %d  honeypots %d  canaries %d  errors %d  tokens %d\n",
		stats.Calls, w.paint(colourRed, fmt.Sprint(stats.Denied)), stats.Shadowed, stats.Quarantined,
		stats.Honeypots, stats.Canaries, stats.Errors, stats.Tokens)
	fmt.Fprintf(&b, "last minute: %d calls, %d denied\n\n", recent.Calls, recent.Denied)

	t := newTable(&b, "SESSION", "HOST", "STARTED", "CALLS", "DENIED", "STATE")
	for _, s := range sessions {
		st := "running"
		if s.EndedAt != nil {
			st = "ended"
		}
		t.row(shortID(s.ID), truncate(orDash(s.HostName), 22), s.StartedAt.Local().Format("15:04:05"), s.Calls, s.Denied, st)
	}
	if len(sessions) == 0 {
		t.row("-", "no sessions in this window", "", "", "", "")
	}
	t.flush()
	b.WriteString("\n")

	t = newTable(&b, "TOOL", "CALLS", "DENIED", "ASKED", "ERRORS", "AVG", "LAST RULE")
	for i, ts := range tools {
		if i == 8 {
			break
		}
		t.row(truncate(ts.Tool, 34), ts.Calls, ts.Denied, ts.Asked, ts.Errors,
			(time.Duration(ts.AvgMS) * time.Millisecond).Round(time.Millisecond), orDash(ts.LastRule))
	}
	if len(tools) == 0 {
		t.row("-", "", "", "", "", "", "")
	}
	t.flush()
	b.WriteString("\n")

	t = newTable(&b, "TIME", "TOOL", "DECISION", "WHY")
	for _, c := range calls {
		d := string(c.Decision)
		switch {
		case c.Shadow:
			d = w.paint(colourPurple, "shadow "+d)
		case c.Decision == policy.ActionDeny:
			d = w.paint(colourRed, d)
		}
		t.row(c.TS.Local().Format("15:04:05"), truncate(c.Tool, 30), d, truncate(c.Reason, max(20, width-70)))
	}
	t.flush()
	if height > 0 {
		b.WriteString("\n" + w.dim("q to quit") + "\n")
	}

	frame := b.String()
	if height > 0 {
		lines := strings.Split(frame, "\n")
		if len(lines) > height {
			frame = strings.Join(lines[:height], "\n")
		}
	}
	return frame, nil
}
