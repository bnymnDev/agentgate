package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/telemetry"
)

// TestCallsBecomeSpans: every call agentgate answers, allowed or denied,
// reaches the OTLP collector.
func TestCallsBecomeSpans(t *testing.T) {
	var (
		mu    sync.Mutex
		names []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		for _, name := range strings.Split(string(raw), `"name":"`)[1:] {
			names = append(names, name[:strings.IndexByte(name, '"')])
		}
	}))
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	exporter, err := telemetry.New(telemetry.Config{Endpoint: srv.URL}, "test", nil)
	require.NoError(t, err)

	h := setup(t, denyPolicy)
	h.proxy.telemetry = exporter
	require.False(t, call(t, h, "demo__echo", map[string]any{"text": "hi"}).IsError)
	require.True(t, call(t, h, "demo__exec", map[string]any{"command": "rm -rf /"}).IsError)
	require.NoError(t, exporter.Close(context.Background()))

	mu.Lock()
	defer mu.Unlock()
	require.Contains(t, names, "tools/call demo__echo")
	require.Contains(t, names, "tools/call demo__exec")
}
