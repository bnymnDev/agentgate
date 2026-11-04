//go:build e2e

package e2e

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// probe calls the read-only tools only, finds the injection a poisoned page
// carries, and posts the report.
func TestProbe(t *testing.T) {
	e := build(t)
	out, err := exec.Command(e.agentgate, "probe", "--", e.echoServer).CombinedOutput()
	require.NoError(t, err, string(out))
	require.Contains(t, string(out), "clean    echo-server.fetch")
	require.Contains(t, string(out), "skipped  echo-server.exec: not marked read-only")

	posted := make(chan string, 1)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		posted <- string(b)
	}))
	defer hook.Close()
	cmd := exec.Command(e.agentgate, "probe", "--arg", `fetch={"url":"https://evil.example/news"}`, "--webhook", hook.URL, "--", e.echoServer)
	out, err = cmd.CombinedOutput()
	require.Error(t, err, "a finding exits 1")
	require.Contains(t, string(out), "FOUND    echo-server.fetch")
	require.True(t, strings.Contains(string(out), "Unicode tag characters") || strings.Contains(string(out), "ignore its instructions"), string(out))
	require.Contains(t, <-posted, `"findings"`)
}
