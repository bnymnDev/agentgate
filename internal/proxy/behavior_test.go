package proxy

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/behavior"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// A call with an argument the tool never took is stopped in deny mode; one
// that returns far more than ever before labels the session.
func TestBehaviorProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	prof := &behavior.Profile{Version: 1, Tools: map[string]*behavior.ToolProfile{
		"echo": {Calls: 50, ArgKeys: []string{"text"}, ResultBytes: behavior.Spread{P50: 60, P95: 80, Max: 90}, DurationMS: behavior.Spread{P50: 1, P95: 2, Max: 3}},
	}}
	require.NoError(t, prof.Save(path))
	h := setup(t, `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
behavior:
  profile: `+path+`
  mode: deny
policy:
  default: allow
`)
	ctx := context.Background()
	call := func(args map[string]any) *mcp.CallToolResult {
		res, err := h.client.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: args})
		require.NoError(t, err)
		return res
	}
	require.False(t, call(map[string]any{"text": "hi"}).IsError)

	res := call(map[string]any{"text": "hi", "callback": "https://x.example"})
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), `argument "callback" was never passed in 50 calls`)
	require.Contains(t, textOf(t, res), "rule behavior")

	require.False(t, call(map[string]any{"text": strings.Repeat("x", 20000)}).IsError, "what comes back is reported, not blocked")
	var labels []string
	h.proxy.sessions.Range(func(_, v any) bool {
		labels = append(labels, v.(*sessionState).history().Labels...)
		return true
	})
	require.Contains(t, labels, policy.LabelBehaviorAnomaly)
}
