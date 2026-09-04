package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
	"github.com/bnymnDev/agentgate/internal/testserver"
)

// harness is a whole agentgate in one process: a real MCP server upstream, the
// proxy in the middle, and a real MCP client downstream, wired with in-memory
// transports. Everything the proxy does is therefore exercised over the actual
// protocol rather than by calling handlers directly.
type harness struct {
	proxy  *Proxy
	client *mcp.ClientSession
	store  *audit.Store
}

func setup(t *testing.T, configYAML string) *harness {
	t.Helper()
	ctx := context.Background()

	cfg, err := config.Parse([]byte(configYAML))
	require.NoError(t, err)
	cfg.Audit.Path = filepath.Join(t.TempDir(), "audit.db")

	store, err := audit.Open(ctx, audit.Options{
		Path:           cfg.Audit.Path,
		Redactor:       audit.NewRedactor(cfg.Audit.Redactors()),
		MaxResultBytes: cfg.Audit.MaxResultBytes,
	})
	require.NoError(t, err)

	p, err := New(Options{
		Config:              cfg,
		Store:               store,
		Logger:              slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		DownstreamTransport: "test",
	})
	require.NoError(t, err)

	// Put a real MCP server behind every configured upstream.
	for _, u := range p.upstreams {
		serverSide, clientSide := mcp.NewInMemoryTransports()
		_, err := testserver.New().Connect(ctx, serverSide, nil)
		require.NoError(t, err)
		u.override = clientSide
	}
	require.NoError(t, p.Connect(ctx))

	// And a real MCP client in front of it.
	downstreamServer, downstreamClient := mcp.NewInMemoryTransports()
	_, err = p.server.Connect(ctx, downstreamServer, nil)
	require.NoError(t, err)
	client, err := mcp.NewClient(&mcp.Implementation{Name: "test-host", Version: "9.9.9"}, nil).
		Connect(ctx, downstreamClient, nil)
	require.NoError(t, err)

	t.Cleanup(func() {
		client.Close()
		p.Close()
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		store.Close(closeCtx)
	})
	return &harness{proxy: p, client: client, store: store}
}

const singleUpstream = `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
policy:
  default: allow
`

const denyPolicy = `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
    prefix: true
policy:
  default: allow
  rules:
    - id: no-rm-rf
      tool: "demo.exec"
      when:
        args.command: { regex: 'rm\s+-rf' }
      action: deny
      reason: "destructive shell command"
`

// TestSingleUpstreamIsTransparent checks the transparency promise: with one
// upstream and no matching rule, the host sees exactly what the server offers.
func TestSingleUpstreamIsTransparent(t *testing.T) {
	h := setup(t, singleUpstream)
	ctx := context.Background()

	tools, err := h.client.ListTools(ctx, nil)
	require.NoError(t, err)
	names := toolNames(tools)
	require.Contains(t, names, "echo", "a single upstream must not be prefixed")
	require.Contains(t, names, "add")
	require.NotContains(t, names, "demo__echo")

	res, err := h.client.CallTool(ctx, &mcp.CallToolParams{
		Name: "echo", Arguments: map[string]any{"text": "hello"},
	})
	require.NoError(t, err)
	require.False(t, res.IsError)
	require.Equal(t, "hello", textOf(t, res))
}

// TestStructuredResultSurvives makes sure the proxy does not flatten a
// structured tool result on its way through.
func TestStructuredResultSurvives(t *testing.T) {
	h := setup(t, singleUpstream)
	res, err := h.client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "add", Arguments: map[string]any{"a": 2, "b": 3},
	})
	require.NoError(t, err)
	require.False(t, res.IsError)
	raw, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)
	require.JSONEq(t, `{"sum":5}`, string(raw))
}

// TestResourcesAndPromptsPassThrough covers the "v0.1 governs tools only" rule.
func TestResourcesAndPromptsPassThrough(t *testing.T) {
	h := setup(t, singleUpstream)
	ctx := context.Background()

	resources, err := h.client.ListResources(ctx, nil)
	require.NoError(t, err)
	require.Len(t, resources.Resources, 1)
	require.Equal(t, "demo://readme", resources.Resources[0].URI)

	read, err := h.client.ReadResource(ctx, &mcp.ReadResourceParams{URI: "demo://readme"})
	require.NoError(t, err)
	require.Len(t, read.Contents, 1)
	require.Equal(t, "agentgate demo resource", read.Contents[0].Text)

	prompts, err := h.client.ListPrompts(ctx, nil)
	require.NoError(t, err)
	require.Len(t, prompts.Prompts, 1)

	got, err := h.client.GetPrompt(ctx, &mcp.GetPromptParams{Name: "greet"})
	require.NoError(t, err)
	require.Len(t, got.Messages, 1)

	require.NoError(t, h.client.Ping(ctx, nil))
}

// TestDenyIsAToolErrorNotATransportError pins the shape of a denial: the agent
// has to be able to read why it was blocked and adapt.
func TestDenyIsAToolErrorNotATransportError(t *testing.T) {
	h := setup(t, denyPolicy)
	res, err := h.client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "demo__exec", Arguments: map[string]any{"command": "rm -rf /"},
	})
	require.NoError(t, err, "a denied call must not fail the transport")
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), "agentgate denied: destructive shell command")
	require.Contains(t, textOf(t, res), "(rule no-rm-rf)")
}

// TestAllowedCallReachesUpstream is the other half of the same policy.
func TestAllowedCallReachesUpstream(t *testing.T) {
	h := setup(t, denyPolicy)
	res, err := h.client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "demo__exec", Arguments: map[string]any{"command": "ls -la"},
	})
	require.NoError(t, err)
	require.False(t, res.IsError)
	require.Equal(t, "would run: ls -la", textOf(t, res))
}

// TestBudgetStopsTheSession checks that a budget is a hard cap an allow rule
// cannot lift.
func TestBudgetStopsTheSession(t *testing.T) {
	h := setup(t, `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
policy:
  default: allow
  budget:
    calls_per_session: 2
  rules:
    - id: always
      tool: "*"
      action: allow
`)
	ctx := context.Background()
	for i := range 2 {
		res, err := h.client.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "x"}})
		require.NoError(t, err, "call %d", i)
		require.False(t, res.IsError, "call %d", i)
	}
	res, err := h.client.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "x"}})
	require.NoError(t, err)
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), "budget: session limit of 2 calls reached")
}

// TestAskWithoutAnApproverDenies is the documented stdio fallback.
func TestAskWithoutAnApproverDenies(t *testing.T) {
	h := setup(t, `
version: 1
approval:
  mode: deny
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
policy:
  default: allow
  rules:
    - id: confirm-writes
      tool: "demo.write_file"
      action: ask
      reason: "writes need a human"
`)
	res, err := h.client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "write_file", Arguments: map[string]any{"path": "/tmp/x"},
	})
	require.NoError(t, err)
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), "approval required")
}

// TestCallsAreAudited checks that the record written for a call carries the
// decision, the hashes and the redacted payloads.
func TestCallsAreAudited(t *testing.T) {
	h := setup(t, denyPolicy)
	ctx := context.Background()

	_, err := h.client.CallTool(ctx, &mcp.CallToolParams{Name: "demo__echo", Arguments: map[string]any{"text": "hi"}})
	require.NoError(t, err)
	_, err = h.client.CallTool(ctx, &mcp.CallToolParams{Name: "demo__exec", Arguments: map[string]any{"command": "rm -rf /"}})
	require.NoError(t, err)
	_, err = h.client.CallTool(ctx, &mcp.CallToolParams{Name: "demo__leak", Arguments: map[string]any{}})
	require.NoError(t, err)

	calls := waitForCalls(t, h.store, 3)
	require.Equal(t, policy.ActionAllow, calls[0].Decision)
	require.Equal(t, "demo__echo", calls[0].Tool)
	require.NotEmpty(t, calls[0].ArgsHash)
	require.NotEmpty(t, calls[0].ResultHash)

	require.Equal(t, policy.ActionDeny, calls[1].Decision)
	require.Equal(t, "no-rm-rf", calls[1].RuleID)
	require.True(t, calls[1].IsError)

	require.NotContains(t, string(calls[2].Result), "sk-not-a-real-key",
		"the built-in redaction patterns should have caught the fake key")
	require.Contains(t, string(calls[2].Result), audit.Placeholder)
}

// TestSessionIsRecorded checks the session row carries who connected.
func TestSessionIsRecorded(t *testing.T) {
	h := setup(t, singleUpstream)
	_, err := h.client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "echo", Arguments: map[string]any{"text": "hi"},
	})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		sessions, err := h.store.ListSessions(context.Background(), audit.SessionFilter{})
		return err == nil && len(sessions) == 1 && sessions[0].HostName == "test-host"
	}, 3*time.Second, 20*time.Millisecond)
}

// TestMultipleUpstreamsArePrefixed covers the merge and the collision guard.
func TestMultipleUpstreamsArePrefixed(t *testing.T) {
	h := setup(t, `
version: 1
upstreams:
  - name: a
    stdio: ["unused-in-tests"]
  - name: b
    stdio: ["unused-in-tests"]
policy:
  default: allow
`)
	tools, err := h.client.ListTools(context.Background(), nil)
	require.NoError(t, err)
	names := toolNames(tools)
	require.Contains(t, names, "a__echo")
	require.Contains(t, names, "b__echo")

	res, err := h.client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "b__echo", Arguments: map[string]any{"text": "from b"},
	})
	require.NoError(t, err)
	require.Equal(t, "from b", textOf(t, res))
}

// TestTimeoutBecomesAToolError: agentgate's own deadline must not look like a
// dead connection to the host.
func TestTimeoutBecomesAToolError(t *testing.T) {
	h := setup(t, `
version: 1
call_timeout: 50ms
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
policy:
  default: allow
`)
	res, err := h.client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "slow", Arguments: map[string]any{"ms": 2000},
	})
	require.NoError(t, err)
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), "did not answer within")
}

func toolNames(res *mcp.ListToolsResult) []string {
	out := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		out = append(out, tool.Name)
	}
	return out
}

func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	require.NotEmpty(t, res.Content)
	tc, ok := res.Content[0].(*mcp.TextContent)
	require.True(t, ok, "expected text content, got %T", res.Content[0])
	return tc.Text
}

// waitForCalls blocks until n calls have made it through the asynchronous
// audit writer.
func waitForCalls(t *testing.T, store *audit.Store, n int) []*audit.Call {
	t.Helper()
	var calls []*audit.Call
	require.Eventually(t, func() bool {
		var err error
		calls, err = store.ListCalls(context.Background(), audit.CallFilter{})
		return err == nil && len(calls) >= n
	}, 5*time.Second, 20*time.Millisecond, "audit records did not arrive")
	return calls
}
