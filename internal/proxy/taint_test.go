package proxy

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func taintConfig(mode string) string {
	return `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
taint:
  mode: ` + mode + `
policy:
  default: allow
  labels:
    - label: private-data
      tool: "demo.read_env"
`
}

func addEnvTool(h *harness) {
	mcp.AddTool(h.servers[0], &mcp.Tool{Name: "read_env", Description: "Read the .env file"},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{
				Text: "LOG_LEVEL=info\nSTRIPE_SECRET_KEY=sk_live_51HxYzAbCdEf0123456789\n"}}}, nil, nil
		})
}

// TestTaintedValueCannotLeave: a value read from a private result is stopped
// on its way out, base64 and all; before it was read, the same call is fine.
func TestTaintedValueCannotLeave(t *testing.T) {
	h := setup(t, taintConfig("deny"))
	addEnvTool(h)
	secret := base64.StdEncoding.EncodeToString([]byte("key=sk_live_51HxYzAbCdEf0123456789"))
	require.Eventually(t, func() bool { _, ok := listed(t, h)["read_env"]; return ok }, timeoutShort, pollShort)

	res := call(t, h, "echo", map[string]any{"text": secret})
	require.False(t, res.IsError, "nothing is tainted before the secret is read")

	res = call(t, h, "read_env", map[string]any{})
	require.False(t, res.IsError)

	res = call(t, h, "echo", map[string]any{"text": "harmless"})
	require.False(t, res.IsError)
	res = call(t, h, "echo", map[string]any{"text": secret})
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), "a value this session read from read_env is leaving base64-encoded")
	require.Contains(t, textOf(t, res), "rule taint")
}

func TestTaintWarnLetsThrough(t *testing.T) {
	h := setup(t, taintConfig("warn"))
	addEnvTool(h)
	require.Eventually(t, func() bool { _, ok := listed(t, h)["read_env"]; return ok }, timeoutShort, pollShort)
	call(t, h, "read_env", map[string]any{})
	res := call(t, h, "echo", map[string]any{"text": "sk_live_51HxYzAbCdEf0123456789"})
	require.False(t, res.IsError, "warn reports and lets through")
}
