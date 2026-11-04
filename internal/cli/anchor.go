package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/anchor"
	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
)

func newAnchorCmd(g *globals) *cobra.Command {
	var (
		to     []string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "anchor",
		Short: "Send the head of the audit chain somewhere this machine cannot rewrite",
		Long: `Write a statement "the audit chain reached seq N with hash H at time T" to
every destination in audit.anchor.to, or to the ones given with --to:

	https://ntfy.sh/my-anchors   POST it as JSON; an ntfy topic, a chat webhook
	ots:./anchors                stamp it with OpenTimestamps (Bitcoin)
	file:./anchors.jsonl         append it to a file, a git repository say

The chain shows edits, deletions and insertions by itself. The one thing it
cannot show alone is its end being cut off; an anchor kept elsewhere can.
Check every anchor later with:

	agentgate verify --anchors ./anchors.jsonl --anchors ./anchors

With no destination, the statement is printed for you to keep by hand.`,
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
			head, err := store.Head(cmd.Context())
			if err != nil {
				return err
			}
			if head.Seq == 0 {
				return errors.New("the audit chain is empty; there is nothing to anchor yet")
			}
			if len(to) == 0 {
				to = cfg.Audit.Anchor.To
			}
			st := anchor.New(head, cfg.Audit.Path)
			out := cmd.OutOrStdout()
			if len(to) == 0 {
				if asJSON {
					_, err := out.Write(st.Line())
					return err
				}
				fmt.Fprintln(out, st.Link())
				return nil
			}
			var failed error
			results := []map[string]string{}
			for _, d := range to {
				dest, err := anchor.Parse(d, nil)
				if err != nil {
					return err
				}
				where, err := dest.Publish(cmd.Context(), st)
				r := map[string]string{"to": dest.String()}
				if err != nil {
					failed = errors.Join(failed, fmt.Errorf("%s: %w", dest, err))
					r["error"] = err.Error()
				} else {
					r["at"] = where
				}
				results = append(results, r)
				if !asJSON {
					if err != nil {
						fmt.Fprintf(out, "%-8s %s: %s\n", "failed", dest, err)
					} else {
						fmt.Fprintf(out, "%-8s %s\n", "sent", where)
					}
				}
			}
			if asJSON {
				if err := writeJSON(out, map[string]any{"anchor": st, "results": results}); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(out, "%-8s %s\n", "anchor", st.Link())
			}
			return failed
		},
	}
	cmd.Flags().StringArrayVar(&to, "to", nil, "a destination; repeatable, replaces audit.anchor.to")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the statement and results as JSON")
	return cmd
}

// anchorLoop sends the chain head to the configured destinations while the
// gateway runs, whenever it has grown, and once more on the way out.
func anchorLoop(ctx context.Context, cfg *config.Config, store *audit.Store, log *slog.Logger) {
	var dests []anchor.Destination
	client := &http.Client{Timeout: 20 * time.Second}
	for _, to := range cfg.Audit.Anchor.To {
		d, err := anchor.Parse(to, client)
		if err != nil {
			log.Warn("audit anchor: bad destination", "to", to, "error", err)
			continue
		}
		dests = append(dests, d)
	}
	if len(dests) == 0 || store == nil {
		return
	}
	var last audit.Link
	send := func(ctx context.Context) {
		head, err := store.Head(ctx)
		if err != nil || head.Seq == 0 || head == last {
			return
		}
		st := anchor.New(head, cfg.Audit.Path)
		for _, d := range dests {
			if _, err := d.Publish(ctx, st); err != nil {
				log.Warn("audit anchor: could not send", "to", d.String(), "error", err)
				continue
			}
			log.Debug("audit anchor sent", "to", d.String(), "anchor", head.String())
		}
		last = head
	}
	var mu sync.Mutex
	locked := func(ctx context.Context) {
		mu.Lock()
		defer mu.Unlock()
		send(ctx)
	}
	// The last head goes out once every write is in, before the log closes.
	store.BeforeClose(func(context.Context) {
		final, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		locked(final)
	})
	tick := time.NewTicker(time.Duration(cfg.Audit.Anchor.Every))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			locked(ctx)
		}
	}
}
