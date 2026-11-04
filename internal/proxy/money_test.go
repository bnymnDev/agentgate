package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// Per-call prices are charged as calls are made; the session cap stops the
// call that would cross it, and the daily cap, read from the audit log that
// every session writes, stops a fresh session too.
func TestMoneyBudget(t *testing.T) {
	h := setup(t, `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
policy:
  default: allow
  budget:
    money:
      per_call: {"demo.echo": 0.40}
      per_session: 1.00
      per_day: 1.50
`)
	ctx := context.Background()
	echo := func(c *mcp.ClientSession) *mcp.CallToolResult {
		res, err := c.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "x"}})
		require.NoError(t, err)
		return res
	}
	require.False(t, echo(h.client).IsError)
	require.False(t, echo(h.client).IsError)
	res := echo(h.client)
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), "this call costs 0.40 EUR and only 0.20 EUR of the session budget is left")

	// The day so far: 0.80 EUR. Once the log has it, the next session has
	// 0.70 EUR of the day left, enough for one call and not two.
	require.Eventually(t, func() bool {
		calls, err := h.store.ForwardedSince(ctx, midnight(time.Now()))
		return err == nil && len(calls) == 2
	}, timeoutShort, pollShort)
	h.proxy.spend.mu.Lock()
	h.proxy.spend.baseAt = time.Time{}
	h.proxy.spend.mu.Unlock()
	second := connectSecondClient(t, h)
	require.False(t, echo(second).IsError)
	res = echo(second)
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), "of the daily budget is left")
}
