package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
)

func newTestServer(t *testing.T) (http.Handler, *audit.Session) {
	t.Helper()
	ctx := context.Background()

	cfg, err := config.Parse([]byte(`
version: 1
upstreams:
  - name: fs
    stdio: ["true"]
policy:
  default: allow
  rules:
    - id: no-etc
      tool: "fs.write_file"
      when:
        args.path: { prefix: "/etc/" }
      action: deny
      reason: "not in /etc"
`))
	require.NoError(t, err)
	cfg.Audit.Path = filepath.Join(t.TempDir(), "audit.db")

	store, err := audit.Open(ctx, audit.Options{Path: cfg.Audit.Path})
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		store.Close(closeCtx)
	})

	sess := &audit.Session{ID: audit.NewID(), StartedAt: time.Now(), HostName: "test-host", DownstreamTransport: "stdio"}
	require.NoError(t, store.StartSession(ctx, sess))
	store.RecordCall(&audit.Call{
		SessionID: sess.ID, Tool: "fs__write_file", Upstream: "fs", Decision: policy.ActionDeny,
		RuleID: "no-etc", Reason: "not in /etc",
		Args:   json.RawMessage(`{"path":"/etc/passwd"}`),
		Result: json.RawMessage(`{"isError":true}`),
	})
	require.Eventually(t, func() bool {
		calls, err := store.ListCalls(ctx, audit.CallFilter{SessionID: sess.ID})
		return err == nil && len(calls) == 1
	}, 3*time.Second, 20*time.Millisecond)

	srv, err := New(Options{
		Store:   store,
		Config:  func() *config.Config { return cfg },
		Version: "test",
	})
	require.NoError(t, err)
	return srv.Handler(), sess
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestPagesRender(t *testing.T) {
	h, sess := newTestServer(t)
	for _, path := range []string{
		"/",
		"/sessions/" + sess.ID,
		"/partials/sessions",
		"/partials/calls?session=" + sess.ID,
		"/policy",
		"/approvals",
		"/partials/approvals",
		"/healthz",
		"/static/pico.min.css",
		"/static/htmx.min.js",
		"/static/agentgate.css",
	} {
		t.Run(path, func(t *testing.T) {
			rec := get(t, h, path)
			require.Equal(t, http.StatusOK, rec.Code)
			require.NotEmpty(t, rec.Body.String())
		})
	}
}

func TestSessionPageShowsTheDeniedCall(t *testing.T) {
	h, sess := newTestServer(t)
	body := get(t, h, "/sessions/"+sess.ID).Body.String()
	require.Contains(t, body, "fs__write_file")
	require.Contains(t, body, "not in /etc")
	require.Contains(t, body, "no-etc")
	require.Contains(t, body, "/etc/passwd")
}

func TestPolicyPageListsTheRules(t *testing.T) {
	h, _ := newTestServer(t)
	body := get(t, h, "/policy").Body.String()
	require.Contains(t, body, "no-etc")
	require.Contains(t, body, "starts with")
	require.Contains(t, body, "default allow, 1 rules")
}

func TestUnknownSessionIsNotFound(t *testing.T) {
	h, _ := newTestServer(t)
	require.Equal(t, http.StatusNotFound, get(t, h, "/sessions/does-not-exist").Code)
}

func TestReloadIsDisabledWithoutAProxy(t *testing.T) {
	h, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/policy/reload", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "no proxy to reload into")
}

// TestArgumentsAreEscaped guards against the audit log becoming an injection
// vector: a tool argument is attacker-influenced text.
func TestArgumentsAreEscaped(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.Parse([]byte("version: 1\nupstreams:\n  - name: fs\n    stdio: [\"true\"]\npolicy:\n  default: allow\n"))
	require.NoError(t, err)
	cfg.Audit.Path = filepath.Join(t.TempDir(), "audit.db")
	store, err := audit.Open(ctx, audit.Options{Path: cfg.Audit.Path})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close(ctx) })

	sess := &audit.Session{ID: audit.NewID(), StartedAt: time.Now()}
	require.NoError(t, store.StartSession(ctx, sess))
	store.RecordCall(&audit.Call{
		SessionID: sess.ID, Tool: "fs__write_file", Decision: policy.ActionAllow,
		Args: json.RawMessage(`{"path":"<script>alert(1)</script>"}`),
	})
	require.Eventually(t, func() bool {
		calls, err := store.ListCalls(ctx, audit.CallFilter{SessionID: sess.ID})
		return err == nil && len(calls) == 1
	}, 3*time.Second, 20*time.Millisecond)

	srv, err := New(Options{Store: store, Config: func() *config.Config { return cfg }})
	require.NoError(t, err)
	body := get(t, srv.Handler(), "/sessions/"+sess.ID).Body.String()
	require.NotContains(t, body, "<script>alert(1)</script>")
	// encoding/json turns < and > into \u003c / \u003e on its way out, and
	// html/template escapes whatever is left. Either way nothing executes.
	require.Contains(t, body, `\u003cscript\u003e`)
}
