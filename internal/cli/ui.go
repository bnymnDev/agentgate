package cli

import (
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/killswitch"
	"github.com/bnymnDev/agentgate/internal/ui"
)

func newUICmd(g *globals) *cobra.Command {
	var (
		addr        string
		allowRemote bool
	)
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Browse the audit log in a browser",
		Long: `Serve the web UI over the audit database.

This is the read-only half of what "agentgate run --ui" gives you: sessions,
calls and the loaded policy, but no approvals inbox and no policy reload,
because there is no proxy running behind it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := g.logger()
			cfg, err := g.load()
			if err != nil {
				return err
			}
			if err := checkUIAddr(addr, allowRemote); err != nil {
				return err
			}
			store, err := g.openStore(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer closeStore(store)

			srv, err := ui.New(ui.Options{
				Store:  store,
				Config: func() *config.Config { return cfg },
				Freeze: func(reason, by string) error {
					_, err := killswitch.Engage(cfg.FreezeFile(), reason, by)
					return err
				},
				Unfreeze: func() error { return killswitch.Release(cfg.FreezeFile()) },
				Logger:   log,
				Version:  version(),
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "agentgate ui on http://%s (audit db %s)\n", addr, cfg.Audit.Path)

			group, _ := newRunGroup(cmd.Context())
			group.serve(&http.Server{
				Addr:              addr,
				Handler:           srv.Handler(),
				ReadHeaderTimeout: 10 * time.Second,
			}, "web UI", log)
			return group.wait()
		},
	}
	cmd.Flags().StringVar(&addr, "addr", config.DefaultUIAddr, "address to listen on")
	cmd.Flags().BoolVar(&allowRemote, "allow-remote-ui", false,
		"allow binding to a non-loopback address (the UI has no authentication)")
	return cmd
}
