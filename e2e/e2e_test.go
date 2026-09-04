//go:build e2e

// Package e2e drives the real agentgate binary, over a real transport, in front
// of a real MCP server. Nothing here is stubbed: the binary is built, launched
// as a subprocess and talked to with an MCP client, exactly as a host would.
//
// Run it with `make e2e`, or `go test -tags e2e ./e2e/...`.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

type env struct {
	dir        string
	agentgate  string
	echoServer string
	configPath string
	auditPath  string
}

// build compiles both binaries once and writes a config that wires them
// together.
func build(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{
		dir:        dir,
		agentgate:  filepath.Join(dir, exe("agentgate")),
		echoServer: filepath.Join(dir, exe("echo-server")),
		configPath: filepath.Join(dir, "agentgate.yaml"),
		auditPath:  filepath.Join(dir, "audit.db"),
	}
	goBuild(t, e.agentgate, "../cmd/agentgate")
	goBuild(t, e.echoServer, "../testdata/servers/echo")

	config := fmt.Sprintf(`
version: 1
call_timeout: 10s
approval:
  mode: deny
audit:
  path: %q
  retention: 1d
  redact:
    - '(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S+'
upstreams:
  - name: demo
    stdio: [%q]
    prefix: true
honeypots:
  action: deny
  tools:
    - name: demo__drop_database
      description: "Drop the production database. Irreversible."
policy:
  default: allow
  budget:
    calls_per_session: 20
  loop_guard:
    repeats: 3
  rules:
    - id: no-destructive-shell
      tool: "demo.exec"
      when:
        args.command: { regex: '\brm\s+-rf' }
      action: deny
      reason: "destructive shell command"
    - id: writes-need-approval
      tool: "demo.write_file"
      when:
        args.path: { not_prefix: "/srv/app/" }
      action: ask
      reason: "writes outside /srv/app need a human"
`, e.auditPath, e.echoServer)
	require.NoError(t, os.WriteFile(e.configPath, []byte(config), 0o600))
	return e
}

func goBuild(t *testing.T, out, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Run(), "building %s", pkg)
}

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// connect launches `agentgate run --stdio` and speaks MCP to it.
func (e *env) connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	cmd := exec.Command(e.agentgate, "run", "--stdio", "--config", e.configPath, "--log-level", "warn")
	cmd.Stderr = os.Stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-host", Version: "1.2.3"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	require.NoError(t, err, "agentgate did not come up")
	t.Cleanup(func() { session.Close() })
	return session
}

// run executes an agentgate subcommand and returns its stdout.
func (e *env) run(t *testing.T, args ...string) string {
	t.Helper()
	args = append(args, "--config", e.configPath)
	cmd := exec.Command(e.agentgate, args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	require.NoError(t, err, "agentgate %s", strings.Join(args, " "))
	return string(out)
}

func TestEndToEnd(t *testing.T) {
	e := build(t)
	session := e.connect(t)
	ctx := context.Background()

	t.Run("tools are merged and prefixed", func(t *testing.T) {
		tools, err := session.ListTools(ctx, nil)
		require.NoError(t, err)
		var names []string
		for _, tool := range tools.Tools {
			names = append(names, tool.Name)
		}
		require.Contains(t, names, "demo__echo")
		require.Contains(t, names, "demo__exec")
		// The upstream's schema must survive the trip untouched.
		for _, tool := range tools.Tools {
			if tool.Name == "demo__add" {
				raw, err := json.Marshal(tool.InputSchema)
				require.NoError(t, err)
				require.Contains(t, string(raw), `"a"`)
				require.Contains(t, string(raw), `"b"`)
			}
		}
	})

	t.Run("an allowed call reaches the server", func(t *testing.T) {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: "demo__echo", Arguments: map[string]any{"text": "hello e2e"},
		})
		require.NoError(t, err)
		require.False(t, res.IsError)
		require.Equal(t, "hello e2e", text(t, res))
	})

	t.Run("a denied call comes back as a readable tool error", func(t *testing.T) {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: "demo__exec", Arguments: map[string]any{"command": "rm -rf /"},
		})
		require.NoError(t, err, "a denial must not break the transport")
		require.True(t, res.IsError)
		require.Contains(t, text(t, res), "agentgate denied: destructive shell command")
	})

	t.Run("ask without an approver denies and says why", func(t *testing.T) {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: "demo__write_file", Arguments: map[string]any{"path": "/etc/passwd", "contents": "x"},
		})
		require.NoError(t, err)
		require.True(t, res.IsError)
		require.Contains(t, text(t, res), "approval required")
	})

	t.Run("secrets in a result are redacted before they are stored", func(t *testing.T) {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "demo__leak", Arguments: map[string]any{}})
		require.NoError(t, err)
		// The host still gets the real answer; only the audit copy is scrubbed.
		require.Contains(t, text(t, res), "sk-not-a-real-key")
	})

	t.Run("a honeypot is listed and trips", func(t *testing.T) {
		tools, err := session.ListTools(ctx, nil)
		require.NoError(t, err)
		var names []string
		for _, tool := range tools.Tools {
			names = append(names, tool.Name)
		}
		require.Contains(t, names, "demo__drop_database")
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "demo__drop_database", Arguments: map[string]any{}})
		require.NoError(t, err)
		require.True(t, res.IsError)
		require.Contains(t, text(t, res), "honeypot")
	})

	t.Run("the loop guard stops a stuck agent", func(t *testing.T) {
		for i := range 3 {
			res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "demo__echo", Arguments: map[string]any{"text": "loop"}})
			require.NoError(t, err)
			require.False(t, res.IsError, "call %d should still pass", i)
		}
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "demo__echo", Arguments: map[string]any{"text": "loop"}})
		require.NoError(t, err)
		require.True(t, res.IsError)
		require.Contains(t, text(t, res), "loop guard")
	})

	t.Run("the kill switch works from another process", func(t *testing.T) {
		out := e.run(t, "freeze", "e2e", "says", "stop")
		require.Contains(t, out, "frozen: e2e says stop")
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "demo__echo", Arguments: map[string]any{"text": "hi"}})
		require.NoError(t, err)
		require.True(t, res.IsError)
		require.Contains(t, text(t, res), "frozen")
		require.Contains(t, e.run(t, "status"), "FROZEN")

		require.Contains(t, e.run(t, "unfreeze"), "unfrozen")
		res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "demo__echo", Arguments: map[string]any{"text": "hi"}})
		require.NoError(t, err)
		require.False(t, res.IsError)
	})

	t.Run("resources and prompts pass through", func(t *testing.T) {
		resources, err := session.ListResources(ctx, nil)
		require.NoError(t, err)
		require.Len(t, resources.Resources, 1)
		read, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: "demo://readme"})
		require.NoError(t, err)
		require.Equal(t, "agentgate demo resource", read.Contents[0].Text)

		prompts, err := session.ListPrompts(ctx, nil)
		require.NoError(t, err)
		require.Len(t, prompts.Prompts, 1)
	})

	// Close the session so the audit writer flushes before the CLI reads it.
	require.NoError(t, session.Close())
	time.Sleep(500 * time.Millisecond)

	t.Run("the CLI can read back what happened", func(t *testing.T) {
		sessions := e.run(t, "sessions")
		require.Contains(t, sessions, "e2e-host")

		var listed []struct {
			ID   string `json:"id"`
			Host string `json:"host_name"`
		}
		require.NoError(t, json.Unmarshal([]byte(e.run(t, "sessions", "--json")), &listed))
		require.NotEmpty(t, listed)
		id := listed[0].ID

		show := e.run(t, "show", id)
		require.Contains(t, show, "demo__echo")
		require.Contains(t, show, "no-destructive-shell")

		var shown struct {
			Calls []struct {
				Tool   string          `json:"tool"`
				Result json.RawMessage `json:"result"`
			} `json:"calls"`
		}
		require.NoError(t, json.Unmarshal([]byte(e.run(t, "show", id, "--json")), &shown))
		for _, c := range shown.Calls {
			if c.Tool == "demo__leak" {
				require.NotContains(t, string(c.Result), "sk-not-a-real-key",
					"the audit copy of the result must be redacted")
				require.Contains(t, string(c.Result), "[REDACTED]")
			}
		}

		replay := e.run(t, "replay", id, "--dry-run")
		require.Contains(t, replay, "dry run, nothing is sent")
		require.Contains(t, replay, "demo__exec")

		tail := e.run(t, "tail", "--no-follow", "--last", "100")
		require.Contains(t, tail, "TRAP")
		require.Contains(t, tail, "DENY")
		require.Contains(t, tail, "demo__drop_database")

		stats := e.run(t, "stats", "--since", "")
		require.Contains(t, stats, "honeypot trips 1")
		require.Contains(t, stats, "demo__echo")
		require.Contains(t, e.run(t, "stats", "--markdown", "--since", ""), "| `demo__echo` |")

		suggested := e.run(t, "policy", "suggest", "--since", "")
		require.Contains(t, suggested, "default: deny")
		require.Contains(t, suggested, `tool: "demo__echo"`)
		require.Contains(t, suggested, "Honeypots tripped")
		// What suggest writes has to be a policy agentgate accepts.
		path := filepath.Join(e.dir, "suggested.yaml")
		require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("version: 1\nupstreams:\n  - name: demo\n    stdio: [%q]\n%s", e.echoServer, suggested)), 0o600))
		require.Contains(t, e.run(t, "policy", "validate", path), "is valid")
	})

	t.Run("check evaluates a call without connecting to anything", func(t *testing.T) {
		out := e.run(t, "check", "--tool", "demo__echo", "--args", `{"text":"hi"}`)
		require.Contains(t, out, "ALLOW")

		cmd := exec.Command(e.agentgate, "check", "--config", e.configPath,
			"--tool", "demo__exec", "--args", `{"command":"rm -rf /"}`)
		out2, err := cmd.Output()
		require.Error(t, err, "check should exit non-zero for a denied call")
		require.Contains(t, string(out2), "DENY")
		require.Contains(t, string(out2), "no-destructive-shell")
	})

	t.Run("policy validate accepts the config", func(t *testing.T) {
		require.Contains(t, e.run(t, "policy", "validate"), "is valid")
	})
}

// TestAgainstTheEverythingServer runs the same proxy in front of the reference
// MCP server from the spec repo. It needs npx and network access, so it is
// opt-in: set AGENTGATE_E2E_NPX=1.
func TestAgainstTheEverythingServer(t *testing.T) {
	if os.Getenv("AGENTGATE_E2E_NPX") == "" {
		t.Skip("set AGENTGATE_E2E_NPX=1 to run against @modelcontextprotocol/server-everything")
	}
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("npx is not installed")
	}
	e := build(t)
	config := fmt.Sprintf(`
version: 1
call_timeout: 60s
audit:
  path: %q
upstreams:
  - name: everything
    stdio: ["npx", "-y", "@modelcontextprotocol/server-everything"]
policy:
  default: allow
  rules:
    - id: no-long-running
      tool: "everything.longRunningOperation"
      action: deny
      reason: "not in a test"
`, e.auditPath)
	require.NoError(t, os.WriteFile(e.configPath, []byte(config), 0o600))

	session := e.connect(t)
	ctx := context.Background()

	tools, err := session.ListTools(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, tools.Tools, "the everything server should offer tools")

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "echo", Arguments: map[string]any{"message": "through agentgate"},
	})
	require.NoError(t, err)
	require.False(t, res.IsError)

	denied, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "longRunningOperation", Arguments: map[string]any{"duration": 1, "steps": 1},
	})
	require.NoError(t, err)
	require.True(t, denied.IsError)
	require.Contains(t, text(t, denied), "agentgate denied")
}

func text(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	require.NotEmpty(t, res.Content)
	tc, ok := res.Content[0].(*mcp.TextContent)
	require.True(t, ok, "expected text content, got %T", res.Content[0])
	return tc.Text
}
