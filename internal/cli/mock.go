package cli

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/mock"
)

func newMockCmd(g *globals) *cobra.Command {
	var (
		httpAddr string
		strict   bool
	)
	cmd := &cobra.Command{
		Use:   "mock <session-id>",
		Short: "Serve a recorded session as a stand-in MCP server",
		Long: `Serve a recorded session as an MCP server that answers every call with what
the real server answered at the time: the same tools, the same results,
nothing real behind them.

A call is matched to the recording by tool and arguments; one that was never
made falls back to the next recorded result of the same tool, or with
--strict gets an error. That turns yesterday's session into a test fixture:
run an agent, a CI job or a new policy against it, offline and repeatably.

	agentgate mock 01JD7Z                   stdio, for an MCP host config
	agentgate mock 01JD7Z --http :3334      Streamable HTTP

Results are served as the audit log holds them: redacted, and a result that
was cut at audit.max_result_bytes cannot be served. Raise that limit for
sessions you want to mock.`,
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
			sess, err := store.GetSession(cmd.Context(), args[0])
			if err != nil {
				closeStore(store)
				return err
			}
			calls, err := store.ListCalls(cmd.Context(), audit.CallFilter{SessionID: sess.ID})
			if err != nil {
				closeStore(store)
				return err
			}
			hash := sess.CatalogHash
			for _, c := range calls {
				if c.CatalogHash != "" {
					hash = c.CatalogHash // the last catalog the session saw
				}
			}
			var catalog []byte
			if hash != "" {
				if raw, err := store.Catalog(cmd.Context(), hash); err == nil {
					catalog = raw
				}
			}
			closeStore(store)

			m, err := mock.New(calls, catalog, mock.Options{Strict: strict, Version: version()})
			if err != nil {
				return err
			}
			log := g.logger()
			log.Info("serving a recorded session", "session", sess.ID, "tools", len(m.Tools()), "calls", len(calls), "strict", strict)
			srv := m.MCP()
			if httpAddr == "" {
				return srv.Run(cmd.Context(), &mcp.StdioTransport{})
			}
			handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
			httpSrv := &http.Server{Addr: httpAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
			go func() {
				<-cmd.Context().Done()
				_ = httpSrv.Close()
			}()
			fmt.Fprintf(cmd.ErrOrStderr(), "agentgate mock: session %s on http://%s\n", shortID(sess.ID), httpAddr)
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&httpAddr, "http", "", "serve over Streamable HTTP on this address instead of stdio")
	cmd.Flags().BoolVar(&strict, "strict", false, "answer calls that were never recorded with an error instead of the tool's next recorded result")
	return cmd
}
