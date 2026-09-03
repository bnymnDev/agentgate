// Package cli builds the agentgate command tree. It lives here rather than in
// package main so that the docs generator and the tests can construct the same
// tree the binary runs.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/bnymnDev/agentgate/internal/proxy"
)

// BuildInfo is stamped in by main at build time.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

var build = BuildInfo{Version: "dev"}

// version is the string every command reports.
func version() string { return build.Version }

// Main runs the command tree and returns the process exit code.
func Main(info BuildInfo) int {
	if info.Version != "" {
		build = info
	}
	proxy.Version = build.Version

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := NewRootCmd().ExecuteContext(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			return 0
		}
		// A silent error has already said everything it wanted to say on
		// stdout; it only carries the exit code.
		var quiet *silentError
		if errors.As(err, &quiet) {
			return quiet.code
		}
		fmt.Fprintln(os.Stderr, "agentgate: "+err.Error())
		return 1
	}
	return 0
}
