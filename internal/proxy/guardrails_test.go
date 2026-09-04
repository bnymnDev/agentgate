package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/killswitch"
	"github.com/bnymnDev/agentgate/internal/policy"
)

func call(t *testing.T, h *harness, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := h.client.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	require.NoError(t, err)
	return res
}

// TestHoneypotTripsAndFreezes: a decoy is listed like a real tool, calling it
// is denied and recorded, and with action: freeze every later call is denied
// until the switch is released.
func TestHoneypotTripsAndFreezes(t *testing.T) {
	h := setup(t, `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
honeypots:
  action: freeze
  tools:
    - name: delete_all_users
      description: "Permanently delete every user account."
policy:
  default: allow
`)
	tools, err := h.client.ListTools(context.Background(), nil)
	require.NoError(t, err)
	require.Contains(t, toolNames(tools), "delete_all_users", "the decoy must be advertised like a real tool")

	res := call(t, h, "delete_all_users", map[string]any{"confirm": true})
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), "honeypot")
	require.Contains(t, textOf(t, res), "frozen")

	require.True(t, h.proxy.Frozen())
	res = call(t, h, "echo", map[string]any{"text": "still there?"})
	require.True(t, res.IsError, "a frozen gateway denies everything")
	require.Contains(t, textOf(t, res), "agentgate is frozen")

	require.NoError(t, h.proxy.Unfreeze())
	res = call(t, h, "echo", map[string]any{"text": "back"})
	require.False(t, res.IsError)
	require.Equal(t, "back", textOf(t, res))

	calls := waitForCalls(t, h.store, 3)
	require.Equal(t, policy.RuleHoneypot, calls[0].RuleID)
	require.Equal(t, policy.RuleFrozen, calls[1].RuleID)
	require.Equal(t, policy.ActionAllow, calls[2].Decision)
}

// TestFreezeFromOutsideTheProcess: the switch is a file, so anything that can
// write the file can stop every agent — that is the whole point.
func TestFreezeFromOutsideTheProcess(t *testing.T) {
	h := setup(t, singleUpstream)
	_, err := killswitch.Engage(h.proxy.Config().FreezeFile(), "operator says so", "test")
	require.NoError(t, err)
	res := call(t, h, "echo", map[string]any{"text": "x"})
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), "frozen")
	require.NoError(t, killswitch.Release(h.proxy.Config().FreezeFile()))
	require.False(t, call(t, h, "echo", map[string]any{"text": "x"}).IsError)
}

func TestLoopGuardStopsRepeats(t *testing.T) {
	h := setup(t, `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
policy:
  default: allow
  loop_guard:
    repeats: 2
`)
	same := map[string]any{"text": "again"}
	require.False(t, call(t, h, "echo", same).IsError)
	require.False(t, call(t, h, "echo", same).IsError)
	third := call(t, h, "echo", same)
	require.True(t, third.IsError)
	require.Contains(t, textOf(t, third), "loop guard")
	// A different call resets the streak.
	require.False(t, call(t, h, "echo", map[string]any{"text": "different"}).IsError)
	require.False(t, call(t, h, "echo", same).IsError)
}

func TestRateLimit(t *testing.T) {
	h := setup(t, `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
policy:
  default: allow
  budget:
    calls_per_minute: 2
`)
	require.False(t, call(t, h, "echo", map[string]any{"text": "1"}).IsError)
	require.False(t, call(t, h, "echo", map[string]any{"text": "2"}).IsError)
	res := call(t, h, "echo", map[string]any{"text": "3"})
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), "calls per minute")
}

// TestShadowModeRecordsButForwards is the onboarding story: the rule fires in
// the log, and nothing changes for the agent.
func TestShadowModeRecordsButForwards(t *testing.T) {
	h := setup(t, `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
policy:
  default: allow
  mode: shadow
  rules:
    - id: no-rm-rf
      tool: "exec"
      when:
        args.command: { regex: 'rm\s+-rf' }
      action: deny
`)
	res := call(t, h, "exec", map[string]any{"command": "rm -rf /"})
	require.False(t, res.IsError, "shadow mode must not block")
	require.Equal(t, "would run: rm -rf /", textOf(t, res))

	calls := waitForCalls(t, h.store, 1)
	require.Equal(t, policy.ActionDeny, calls[0].Decision, "the real decision is recorded")
	require.True(t, calls[0].Shadow)
	require.Equal(t, "no-rm-rf", calls[0].RuleID)
	require.False(t, calls[0].Blocked())
}

// TestRedactResultsKeepsSecretsFromTheAgent: with redact_results on, the
// filesystem tool can read the .env file and the model still never sees the key.
func TestRedactResultsKeepsSecretsFromTheAgent(t *testing.T) {
	h := setup(t, `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
policy:
  default: allow
  redact_results: true
`)
	res := call(t, h, "leak", map[string]any{})
	require.False(t, res.IsError)
	text := textOf(t, res)
	require.NotContains(t, text, "sk-not-a-real-key")
	require.Contains(t, text, "[REDACTED]")
	require.Contains(t, text, "and we are done", "only the secret goes, the rest of the text stays")
}

func TestAnnotationConditions(t *testing.T) {
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
    - id: destructive-needs-a-human
      tool: "*"
      when: { annotations.destructive: true }
      action: ask
      reason: "the server itself marks this tool as destructive"
`)
	// write_file is annotated destructive by the demo server.
	res := call(t, h, "write_file", map[string]any{"path": "/tmp/x"})
	require.True(t, res.IsError)
	require.Contains(t, textOf(t, res), "approval required")
	// read_file is annotated read-only and not destructive.
	require.False(t, call(t, h, "read_file", map[string]any{"path": "/tmp/x"}).IsError)
	// echo carries no annotations at all: the condition is missing, not false.
	require.False(t, call(t, h, "echo", map[string]any{"text": "hi"}).IsError)
}

// TestWebhooksReceiveEvents posts to a fake Slack and a fake generic endpoint
// and checks both got the denial, in their own shapes.
func TestWebhooksReceiveEvents(t *testing.T) {
	var (
		mu       sync.Mutex
		received = map[string][]string{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		mu.Lock()
		received[r.URL.Path] = append(received[r.URL.Path], string(body))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	h := setup(t, fmt.Sprintf(`
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
notify:
  webhooks:
    - url: %s/slack
      format: slack
    - url: %s/json
      events: [deny]
policy:
  default: allow
  rules:
    - id: no-rm-rf
      tool: "exec"
      when:
        args.command: { regex: 'rm\s+-rf' }
      action: deny
      reason: "destructive shell command"
`, srv.URL, srv.URL))

	require.True(t, call(t, h, "exec", map[string]any{"command": "rm -rf /"}).IsError)
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(received["/slack"]) == 1 && len(received["/json"]) == 1
	}, 5*time.Second, 20*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	var slack map[string]string
	require.NoError(t, json.Unmarshal([]byte(received["/slack"][0]), &slack))
	require.Contains(t, slack["text"], "denied")
	require.Contains(t, slack["text"], "destructive shell command")

	var generic Event
	require.NoError(t, json.Unmarshal([]byte(received["/json"][0]), &generic))
	require.Equal(t, "deny", generic.Event)
	require.Equal(t, "exec", generic.Tool)
	require.Equal(t, "no-rm-rf", generic.Decision.RuleID)
}
