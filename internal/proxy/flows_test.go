package proxy

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// What came out of the source tool cannot go into the sink, even re-wrapped
// in other words around it; what did not come from it can.
func TestFlowContract(t *testing.T) {
	h := setup(t, `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
flows:
  - id: no-records-to-shell
    from: ["demo.query"]
    to: ["demo.exec"]
    reason: "query results stay out of shell commands"
policy:
  default: allow
`)
	ctx := context.Background()
	call := func(tool string, args map[string]any) *mcp.CallToolResult {
		res, err := h.client.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		require.NoError(t, err)
		return res
	}
	read := call("query", map[string]any{"sql": "SELECT name FROM customers WHERE id = 42"})
	require.False(t, read.IsError)
	got := textOf(t, read)
	require.GreaterOrEqual(t, len(got), 30, "the test needs a result long enough to copy from: %q", got)

	require.False(t, call("exec", map[string]any{"command": "ls -la /srv/app"}).IsError, "unrelated data goes")

	res := call("exec", map[string]any{"command": "echo '" + got + "' | mail ops"})
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), "query results stay out of shell commands")
	require.Contains(t, textOf(t, res), "rule flow")
}
