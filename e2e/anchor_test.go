//go:build e2e

package e2e

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// The gateway sends the chain head out when it stops; verify then checks
// it, and catches calls cut off the end of the log afterwards.
func TestAnchor(t *testing.T) {
	e := build(t)
	anchors := filepath.Join(e.dir, "anchors.jsonl")
	cfg, err := os.ReadFile(e.configPath)
	require.NoError(t, err)
	cfg = []byte(strings.Replace(string(cfg), "  retention: 1d\n",
		"  retention: 1d\n  anchor:\n    to: [\"file:"+filepath.ToSlash(anchors)+"\"]\n", 1))
	require.NoError(t, os.WriteFile(e.configPath, cfg, 0o600))

	session := e.connect(t)
	for _, text := range []string{"one", "two", "three"} {
		_, err := session.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "demo__echo", Arguments: map[string]any{"text": text},
		})
		require.NoError(t, err)
	}
	require.NoError(t, session.Close())
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(anchors)
		return err == nil && strings.Contains(string(b), `"seq":3`)
	}, 15*time.Second, 50*time.Millisecond, "the last head was not anchored on shutdown")

	out := e.run(t, "anchor", "--to", "file:"+anchors)
	require.Contains(t, out, "anchor   3:")
	out = e.run(t, "verify", "--anchors", anchors)
	require.Contains(t, out, "2 of 2 are still part of the chain")

	// Cut the last call off: the chain is consistent, the anchor is not.
	db, err := sql.Open("sqlite", e.auditPath)
	require.NoError(t, err)
	_, err = db.Exec(`DELETE FROM calls WHERE seq = 3`)
	require.NoError(t, err)
	require.NoError(t, db.Close())
	cmd := exec.Command(e.agentgate, "verify", "--anchors", anchors, "--config", e.configPath)
	got, err := cmd.Output()
	require.Error(t, err)
	require.Contains(t, string(got), "no longer reaches the anchor")
}
