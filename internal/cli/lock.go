package cli

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/pinning"
	"github.com/bnymnDev/agentgate/internal/proxy"
)

func newLockCmd(g *globals) *cobra.Command {
	var (
		check  bool
		trust  []string
		asJSON bool
		colour string
	)
	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Review and trust the tool definitions pinned in the lockfile",
		Long: `Connect to every upstream, compare the tools they offer with the lockfile,
and scan each definition for signs of tool poisoning.

agentgate pins every tool the first time it sees it. When a server later
changes what a tool says — a rug pull — or offers a new one, or ships a
definition with instructions hidden in it, this is where you look at it:

	agentgate lock                        what changed, and what the scan found
	agentgate lock --trust fs.read_file   accept one tool as it is now
	agentgate lock --trust '*'            accept everything as it is now
	agentgate lock --check                exit 1 unless everything is pinned and clean

A running agentgate notices the lockfile change and releases a trusted tool
without a restart.`,
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
			if !cfg.Pinning.Enabled() {
				return fmt.Errorf("pinning is off in %s; set pinning.mode to warn or enforce to keep a lockfile", cfg.Path)
			}
			p, err := proxy.New(proxy.Options{
				Config:              cfg,
				Logger:              g.quietLogger(),
				DownstreamTransport: "lock",
				Pinning:             proxy.PinningInspect,
			})
			if err != nil {
				return err
			}
			if err := p.Connect(cmd.Context()); err != nil {
				return err
			}
			defer func() { _ = p.Close() }()

			for _, name := range trust {
				trusted, err := p.Trust(cmd.Context(), name)
				if err != nil {
					return err
				}
				for _, r := range trusted {
					fmt.Fprintf(cmd.OutOrStdout(), "trusted %s.%s (was %s)\n", r.Upstream, r.Tool, r.Status)
				}
			}
			if len(trust) > 0 {
				fmt.Fprintln(cmd.OutOrStdout())
			}

			reports := p.ToolReports()
			if asJSON {
				if err := writeJSON(cmd.OutOrStdout(), reports); err != nil {
					return err
				}
			} else {
				w := &lineWriter{out: cmd.OutOrStdout(), colour: useColour}
				printLock(w, cfg, reports)
			}
			if check && !lockClean(reports) {
				return errExitDenied
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "exit 1 if any tool is new, changed, removed, unpinned or flagged")
	cmd.Flags().StringArrayVar(&trust, "trust", nil, "trust a tool as it is offered now, as upstream.tool; '*' trusts everything (repeatable)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the reports as JSON")
	cmd.Flags().StringVar(&colour, "color", "auto", "colour the output: auto, always or never")
	return cmd
}

func lockClean(reports []proxy.ToolReport) bool {
	for _, r := range reports {
		if r.Status != pinning.StatusPinned || len(r.Findings) > 0 {
			return false
		}
	}
	return true
}

func printLock(w *lineWriter, cfg *config.Config, reports []proxy.ToolReport) {
	out := w.out
	fmt.Fprintf(out, "lockfile  %s (mode %s, scan %s)\n\n", cfg.Pinning.Lockfile, cfg.Pinning.Mode, cfg.Pinning.Scan)
	if len(reports) == 0 {
		fmt.Fprintln(out, "no tools offered")
		return
	}
	t := newTable(out, "UPSTREAM", "TOOL", "STATUS", "FINDINGS", "NOTE")
	for _, r := range reports {
		findings := "-"
		if n := len(r.Findings); n > 0 {
			findings = fmt.Sprint(n)
		}
		note := ""
		switch {
		case r.Reason != "":
			note = "held back: " + r.Reason
		case len(r.Accepted) > 0:
			note = fmt.Sprintf("%d finding(s) accepted", len(r.Accepted))
		case r.Status == pinning.StatusUnpinned:
			note = "pinned on first use when agentgate next runs"
		}
		t.row(r.Upstream, truncate(r.Tool, 32), r.Status, findings, truncate(note, 70))
	}
	t.flush()

	var attention []string
	for _, r := range reports {
		if r.Status != pinning.StatusChanged && r.Status != pinning.StatusNew && len(r.Findings) == 0 {
			continue
		}
		attention = append(attention, r.Upstream+"."+r.Tool)
		fmt.Fprintf(out, "\n%s  %s\n", r.Upstream+"."+r.Tool, w.paint(colourYellow, string(r.Status)))
		if r.Status == pinning.StatusChanged && r.Pinned != nil {
			printDefinitionChange(w, *r.Pinned, r.Current)
		}
		if r.Status == pinning.StatusNew {
			fmt.Fprintf(out, "  description: %s\n", w.revealed(indentText(pinning.Reveal(r.Current.Description), "               ")))
		}
		for _, f := range r.Findings {
			fmt.Fprintf(out, "  %s  %s: %s\n", w.paint(colourRed, "finding"), f.Where, f.Detail)
			if f.Excerpt != "" {
				fmt.Fprintf(out, "           %s\n", w.revealed(fmt.Sprintf("%q", pinning.Reveal(f.Excerpt))))
			}
		}
	}
	switch len(attention) {
	case 0:
	case 1:
		fmt.Fprintf(out, "\n%s\n", w.dim("If that is expected: agentgate lock --trust "+attention[0]))
	default:
		fmt.Fprintf(out, "\n%s\n", w.dim("Trust what is expected with agentgate lock --trust upstream.tool, or all of it with --trust '*'."))
	}
}

func printDefinitionChange(w *lineWriter, before, after pinning.Definition) {
	field := func(name, a, b string) {
		if a == b {
			return
		}
		fmt.Fprintf(w.out, "  %s\n    pinned: %s\n    now:    %s\n", name,
			w.revealed(indentText(pinning.Reveal(a), "            ")), w.revealed(indentText(pinning.Reveal(b), "            ")))
	}
	field("title", before.Title, after.Title)
	field("description", before.Description, after.Description)
	field("input schema", string(before.InputSchema), string(after.InputSchema))
	field("output schema", string(before.OutputSchema), string(after.OutputSchema))
	field("annotations", string(before.Annotations), string(after.Annotations))
}

// revealedSpan is what pinning.Reveal spells out: hidden text, and invisible
// characters by code point.
var revealedSpan = regexp.MustCompile(`«[^»]*»`)

// revealed paints what pinning.Reveal spelled out, so it stands out from the
// text around it.
func (w *lineWriter) revealed(s string) string {
	if !w.colour {
		return s
	}
	return revealedSpan.ReplaceAllStringFunc(s, func(m string) string { return w.paint(colourRed, m) })
}

func indentText(s, indent string) string {
	if s == "" {
		return "(empty)"
	}
	return strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n"+indent)
}

// quietLogger logs only what is worth interrupting a command's output for,
// unless a log level was asked for.
func (g *globals) quietLogger() *slog.Logger {
	if g.logLevel != "info" {
		return g.logger()
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}
