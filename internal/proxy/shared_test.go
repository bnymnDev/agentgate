package proxy

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// A label one session earns counts for the next session too, so handing the
// work to another agent does not wash it off.
func TestSharedLabels(t *testing.T) {
	h := setup(t, `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
shared_labels:
  labels: [untrusted]
  within: 10m
policy:
  default: allow
  labels:
    - label: untrusted
      tool: "demo.echo"
  rules:
    - id: no-add-after-untrusted
      tool: "demo.add"
      when:
        session.labels: { includes: untrusted }
      action: deny
      reason: "nothing is computed after untrusted content"
`)
	ctx := context.Background()
	other := connectSecondClient(t, h)
	add := func(c *mcp.ClientSession) *mcp.CallToolResult {
		res, err := c.CallTool(ctx, &mcp.CallToolParams{Name: "add", Arguments: map[string]any{"a": 1, "b": 2}})
		require.NoError(t, err)
		return res
	}
	require.False(t, add(other).IsError, "nothing was read yet")

	_, err := h.client.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "a web page"}})
	require.NoError(t, err)

	res := add(other)
	require.True(t, res.IsError, "the other session inherited the label")
	require.Contains(t, textOf(t, res), "nothing is computed after untrusted content")
}
