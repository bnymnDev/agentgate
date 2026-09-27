package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/config"
)

const desktopConfig = `{
  "globalShortcut": "Alt+Space",
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/code"]
    },
    "GitHub Server": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_example<&>" }
    },
    "remote": { "url": "https://mcp.example.com/mcp", "headers": { "Authorization": "Bearer x" } },
    "old": { "command": "old-server", "disabled": true }
  },
  "preferences": { "theme": "dark" }
}
`

func testEnv(t *testing.T) (Env, string) {
	t.Helper()
	root := t.TempDir()
	env := Env{Home: filepath.Join(root, "home"), ConfigDir: filepath.Join(root, "config"), Cwd: filepath.Join(root, "project")}
	return env, filepath.Join(root, "agentgate")
}

func write(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
}

func find(cands []Candidate, name string) Candidate {
	for _, c := range cands {
		if c.Host.Name == name {
			return c
		}
	}
	return Candidate{}
}

func TestInstallAndUninstall(t *testing.T) {
	env, dir := testEnv(t)
	desktop := filepath.Join(env.ConfigDir, "Claude", "claude_desktop_config.json")
	write(t, desktop, desktopConfig)

	manifest, err := LoadManifest(dir)
	require.NoError(t, err)
	cands, err := Scan(env, manifest)
	require.NoError(t, err)
	c := find(cands, "claude-desktop")
	require.Equal(t, StatusReady, c.Status)
	require.Len(t, c.Servers, 4)
	require.Len(t, c.Wrapped, 3, "the disabled server stays where it is")
	require.Equal(t, StatusAbsent, find(cands, "cursor").Status)

	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	inst, err := Apply(c, manifest, Options{Dir: dir, Binary: "/usr/local/bin/agentgate", Now: now})
	require.NoError(t, err)

	// The host's file: our entry first, the disabled one kept, and every
	// other setting where it was.
	raw, err := os.ReadFile(desktop)
	require.NoError(t, err)
	out := string(raw)
	require.Less(t, strings.Index(out, "globalShortcut"), strings.Index(out, "mcpServers"))
	require.Less(t, strings.Index(out, "mcpServers"), strings.Index(out, "preferences"))
	var parsed struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	require.NoError(t, json.Unmarshal(raw, &parsed))
	require.Len(t, parsed.MCPServers, 2)
	require.JSONEq(t, `{"command":"/usr/local/bin/agentgate","args":["run","--config","`+inst.Config+`"]}`, string(parsed.MCPServers["agentgate"]))
	require.Contains(t, parsed.MCPServers, "old")

	// The generated config is a valid agentgate config with every server.
	cfg, err := config.Load(inst.Config)
	require.NoError(t, err)
	require.Len(t, cfg.Upstreams, 3)
	require.Equal(t, "github-server", cfg.Upstreams[1].Name)
	require.Equal(t, "ghp_example<&>", cfg.Upstreams[1].Env["GITHUB_PERSONAL_ACCESS_TOKEN"])
	require.Equal(t, "https://mcp.example.com/mcp", cfg.Upstreams[2].HTTP)
	require.True(t, cfg.Policy.IsShadow())
	info, err := os.Stat(inst.Config)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "it holds the servers' secrets")

	// Installing twice is refused.
	cands, err = Scan(env, manifest)
	require.NoError(t, err)
	require.Equal(t, StatusInstalled, find(cands, "claude-desktop").Status)

	// A server added through the host in the meantime survives uninstall.
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc["mcpServers"].(map[string]any)["added-later"] = map[string]any{"command": "new"}
	updated, _ := json.Marshal(doc)
	write(t, desktop, string(updated))

	_, err = Uninstall("claude-desktop", manifest)
	require.NoError(t, err)
	restored, err := Servers(Host{Path: desktop, Key: "mcpServers"})
	require.NoError(t, err)
	var names []string
	for _, s := range restored {
		names = append(names, s.Name)
	}
	require.Equal(t, []string{"filesystem", "GitHub Server", "remote", "old", "added-later"}, names)
	var after map[string]any
	raw, err = os.ReadFile(desktop)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &after))
	require.Equal(t, "Alt+Space", after["globalShortcut"])

	_, err = Uninstall("claude-desktop", manifest)
	require.Error(t, err, "nothing left to uninstall")
	_, err = os.Stat(inst.Backup)
	require.NoError(t, err, "the full backup stays")
}

// VS Code's file is JSONC with typed entries under "servers".
func TestVSCode(t *testing.T) {
	env, dir := testEnv(t)
	path := filepath.Join(env.Cwd, ".vscode", "mcp.json")
	write(t, path, `{
  // servers for this project
  "servers": {
    "fetch": { "type": "stdio", "command": "uvx", "args": ["mcp-server-fetch"], },
  },
  "inputs": []
}`)
	manifest, err := LoadManifest(dir)
	require.NoError(t, err)
	cands, err := Scan(env, manifest)
	require.NoError(t, err)
	c := find(cands, "vscode")
	require.Equal(t, StatusReady, c.Status)
	_, err = Apply(c, manifest, Options{Dir: dir, Binary: "/bin/agentgate", Now: time.Now()})
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"type": "stdio"`)
	require.Contains(t, string(raw), `"inputs": []`)
	require.True(t, json.Valid(raw))
}

func TestUpstreamNames(t *testing.T) {
	taken := map[string]bool{}
	require.Equal(t, "github-server", upstreamName("GitHub Server", taken))
	require.Equal(t, "github-server-2", upstreamName("github server", taken))
	require.Equal(t, "a_b", upstreamName("a__b", taken), "the prefix separator cannot appear in a name")
	require.Equal(t, "server", upstreamName("!!!", taken))
}

func TestStripJSONC(t *testing.T) {
	in := `{"a": "http://x//y", /* c */ "b": [1, 2,], // d
"c": "\"//"}`
	var v map[string]any
	require.NoError(t, json.Unmarshal(stripJSONC([]byte(in)), &v))
	require.Equal(t, "http://x//y", v["a"])
	require.Equal(t, `"//`, v["c"])
}
