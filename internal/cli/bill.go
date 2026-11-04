package cli

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/proxy"
)

func newBillCmd(g *globals) *cobra.Command {
	var (
		month  string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "bill",
		Short: "What the agents' tools cost, per day and per tool, for a month",
		Long: `Price every call of a month that reached its server with the money budget's
price list — tokens through tools at policy.budget.money.per_million_tokens,
paid tools at per_call — and show the bill per day and per tool.

The prices are today's: a price changed since is applied to the whole
month, which is what you want when the list was wrong and what you do not
want when a provider changed its prices mid-month.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := g.load()
			if err != nil {
				return err
			}
			m := &cfg.Policy.Budget.Money
			if !m.Enabled() {
				return errors.New("nothing has a price; set policy.budget.money.per_million_tokens or per_call")
			}
			start := time.Now()
			start = time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.Local)
			if month != "" {
				start, err = time.ParseInLocation("2006-01", month, time.Local)
				if err != nil {
					return fmt.Errorf("--month %q: want YYYY-MM", month)
				}
			}
			end := start.AddDate(0, 1, 0)
			store, err := g.openStore(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer closeStore(store)
			calls, err := store.ForwardedSince(cmd.Context(), start)
			if err != nil {
				return err
			}
			type line struct {
				Key    string  `json:"key"`
				Calls  int     `json:"calls"`
				Tokens int     `json:"tokens_est"`
				Cost   float64 `json:"cost"`
			}
			days, tools := map[string]*line{}, map[string]*line{}
			total := line{Key: "total"}
			add := func(m map[string]*line, key string, tokens int, cost float64) {
				l := m[key]
				if l == nil {
					l = &line{Key: key}
					m[key] = l
				}
				l.Calls++
				l.Tokens += tokens
				l.Cost += cost
			}
			for _, c := range calls {
				if !c.TS.Before(end) {
					continue
				}
				cost := m.Cost(proxy.CallOf(cfg, c.Upstream, c.Tool), c.TokensEst)
				add(days, c.TS.Local().Format(time.DateOnly), c.TokensEst, cost)
				add(tools, c.Tool, c.TokensEst, cost)
				total.Calls++
				total.Tokens += c.TokensEst
				total.Cost += cost
			}
			sorted := func(m map[string]*line, byCost bool) []line {
				out := make([]line, 0, len(m))
				for _, l := range m {
					out = append(out, *l)
				}
				sort.Slice(out, func(i, j int) bool {
					if byCost && out[i].Cost != out[j].Cost {
						return out[i].Cost > out[j].Cost
					}
					return out[i].Key < out[j].Key
				})
				return out
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), map[string]any{
					"month": start.Format("2006-01"), "currency": m.Currency,
					"days": sorted(days, false), "tools": sorted(tools, true), "total": total,
				})
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "bill  %s  (%s)\n\n", start.Format("January 2006"), m.Currency)
			t := newTable(out, "DAY", "CALLS", "TOKENS", "COST")
			for _, l := range sorted(days, false) {
				t.row(l.Key, l.Calls, l.Tokens, fmt.Sprintf("%.2f", l.Cost))
			}
			t.flush()
			fmt.Fprintln(out)
			t = newTable(out, "TOOL", "CALLS", "TOKENS", "COST")
			for _, l := range sorted(tools, true) {
				t.row(truncate(l.Key, 40), l.Calls, l.Tokens, fmt.Sprintf("%.2f", l.Cost))
			}
			t.flush()
			fmt.Fprintf(out, "\ntotal %s for %d calls", m.Format(total.Cost), total.Calls)
			if b := m.PerDay; b > 0 {
				fmt.Fprintf(out, "; daily cap %s", m.Format(b))
			}
			fmt.Fprintln(out)
			return nil
		},
	}
	cmd.Flags().StringVar(&month, "month", "", "the month, as YYYY-MM; default this one")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the bill as JSON")
	return cmd
}
