// Command echo is the demo MCP server agentgate is developed against.
//
// It lives under testdata because it is a fixture, not a product: `make dev`
// builds it, points agentgate at it and gives you a working proxy in one step.
package main

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bnymnDev/agentgate/internal/testserver"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := testserver.New().Run(ctx, &mcp.StdioTransport{})
	// The client closing stdin is how a stdio session ends; that is not an
	// error.
	if err != nil && ctx.Err() == nil && !errors.Is(err, io.EOF) {
		log.Fatalf("echo server: %v", err)
	}
}
