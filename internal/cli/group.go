package cli

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// runGroup runs the long-lived parts of "agentgate run" together: when one of
// them stops, the others are told to stop too, and the whole thing returns only
// once every part is down. No goroutine in agentgate is started without a
// context and a way out; this is where the long-lived ones get theirs.
type runGroup struct {
	ctx    context.Context
	cancel context.CancelFunc

	wg   sync.WaitGroup
	once sync.Once
	err  error
}

func newRunGroup(parent context.Context) (*runGroup, context.Context) {
	ctx, cancel := context.WithCancel(parent)
	return &runGroup{ctx: ctx, cancel: cancel}, ctx
}

// run starts fn. The first non-nil error other than errShutdown wins.
func (g *runGroup) run(fn func() error) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer g.cancel()
		if err := fn(); err != nil && !errors.Is(err, errShutdown) {
			g.once.Do(func() { g.err = err })
		}
	}()
}

// serve runs an HTTP server and shuts it down when the group stops.
func (g *runGroup) serve(srv *http.Server, what string, log *slog.Logger) {
	g.run(func() error {
		go func() {
			<-g.ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdown); err != nil {
				log.Debug("closing "+what, "error", err)
			}
		}()
		log.Info(what+" listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return errShutdown
	})
}

// wait blocks until every part has stopped and returns the first real error.
func (g *runGroup) wait() error {
	g.wg.Wait()
	g.cancel()
	return g.err
}
