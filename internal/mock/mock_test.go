package mock_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/mock"
	"github.com/bnymnDev/agentgate/internal/policy"
)

func recorded(tool, args, result string, decision policy.Action) *audit.Call {
	return &audit.Call{ID: audit.NewID(), SessionID: "s", TS: time.Now(), Tool: tool,
		Args: json.RawMessage(args), Result: json.RawMessage(result), Decision: decision}
}

func text(s string) string {
	b, _ := json.Marshal(map[string]any{"content": []any{map[string]any{"type": "text", "text": s}}})
	return string(b)
}

func connect(t *testing.T, m *mock.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverSide, clientSide := mcp.NewInMemoryTransports()
	_, err := m.MCP().Connect(ctx, serverSide, nil)
	require.NoError(t, err)
	client, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, clientSide, nil)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	return client
}

func callText(t *testing.T, c *mcp.ClientSession, tool string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := c.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	require.NoError(t, err)
	return res.Content[0].(*mcp.TextContent).Text, res.IsError
}

func TestMockAnswersFromTheRecording(t *testing.T) {
	calls := []*audit.Call{
		recorded("fs__read_file", `{"path":"/a"}`, text("contents of a"), policy.ActionAllow),
		recorded("fs__read_file", `{"path":"/b"}`, text("contents of b"), policy.ActionAllow),
		recorded("fs__read_file", `{"path":"/a"}`, text("contents of a, later"), policy.ActionAllow),
		recorded("fs__write_file", `{"path":"/etc/passwd"}`, text("agentgate denied: no"), policy.ActionDeny),
	}
	catalog, err := json.Marshal([]audit.CatalogEntry{{
		Upstream: "fs", Exposed: "fs__read_file",
		Tool: json.RawMessage(`{"name":"read_file","description":"Read a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}`),
	}})
	require.NoError(t, err)

	m, err := mock.New(calls, catalog, mock.Options{})
	require.NoError(t, err)
	c := connect(t, m)

	tools, err := c.ListTools(context.Background(), nil)
	require.NoError(t, err)
	byName := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
	}
	require.Equal(t, "Read a file", byName["fs__read_file"].Description, "the recorded definition, under the exposed name")
	require.Contains(t, byName, "fs__write_file", "a tool seen only in calls is still offered")

	got, _ := callText(t, c, "fs__read_file", map[string]any{"path": "/a"})
	require.Equal(t, "contents of a", got)
	got, _ = callText(t, c, "fs__read_file", map[string]any{"path": "/a"})
	require.Equal(t, "contents of a, later", got, "repeated calls get the results in recorded order")
	got, _ = callText(t, c, "fs__read_file", map[string]any{"path": "/a"})
	require.Equal(t, "contents of a, later", got, "and the last one repeats")
	got, _ = callText(t, c, "fs__read_file", map[string]any{"path": "/b"})
	require.Equal(t, "contents of b", got)

	got, _ = callText(t, c, "fs__read_file", map[string]any{"path": "/never"})
	require.Contains(t, got, "contents of", "an unrecorded call falls back to the tool's recorded results")

	got, isErr := callText(t, c, "fs__write_file", map[string]any{"path": "/etc/passwd"})
	require.True(t, isErr)
	require.Contains(t, got, "never answered", "a denied call has no server result to replay")
}

func TestMockStrict(t *testing.T) {
	calls := []*audit.Call{recorded("echo", `{"text":"hi"}`, text("hi"), policy.ActionAllow)}
	m, err := mock.New(calls, nil, mock.Options{Strict: true})
	require.NoError(t, err)
	c := connect(t, m)
	got, isErr := callText(t, c, "echo", map[string]any{"text": "hi"})
	require.False(t, isErr)
	require.Equal(t, "hi", got)
	got, isErr = callText(t, c, "echo", map[string]any{"text": "other"})
	require.True(t, isErr)
	require.Contains(t, got, "--strict")
}
