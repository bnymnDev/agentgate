package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/killswitch"
	"github.com/bnymnDev/agentgate/internal/policy"
	"github.com/bnymnDev/agentgate/internal/proxy"
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

// TestFreezeFromTheBrowser: the kill switch is a form post; the banner shows
// up on every page while it is on; unfreeze clears it.
func TestFreezeFromTheBrowser(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.Parse([]byte("version: 1\nupstreams:\n  - name: fs\n    stdio: [\"true\"]\npolicy:\n  default: allow\n"))
	require.NoError(t, err)
	cfg.Audit.Path = filepath.Join(t.TempDir(), "audit.db")
	store, err := audit.Open(ctx, audit.Options{Path: cfg.Audit.Path})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close(ctx) })

	var frozenReason string
	srv, err := New(Options{
		Store:  store,
		Config: func() *config.Config { return cfg },
		Freeze: func(reason, by string) error {
			frozenReason = reason + " / " + by
			_, err := killswitch.Engage(cfg.FreezeFile(), reason, by)
			return err
		},
		Unfreeze: func() error { return killswitch.Release(cfg.FreezeFile()) },
	})
	require.NoError(t, err)
	h := srv.Handler()

	body := get(t, h, "/").Body.String()
	require.Contains(t, body, "Freeze all agents")
	require.NotContains(t, body, "The gateway is frozen")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/freeze", strings.NewReader("reason=demo+time"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "http://localhost:7777/policy")
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/policy", rec.Header().Get("Location"))
	require.Equal(t, "demo time / the web UI", frozenReason)

	body = get(t, h, "/").Body.String()
	require.Contains(t, body, "The gateway is frozen")
	require.Contains(t, body, "demo time")
	require.Contains(t, body, "Unfreeze")

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/unfreeze", nil))
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.NotContains(t, get(t, h, "/").Body.String(), "The gateway is frozen")
}

// TestReadOnlyInstanceHidesFreezeButtons: "agentgate ui" without the hooks
// must not render controls that would 404.
func TestReadOnlyInstanceHidesFreezeButtons(t *testing.T) {
	h, _ := newTestServer(t)
	require.NotContains(t, get(t, h, "/").Body.String(), "Freeze all agents")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/freeze", nil))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestApprovalButtons drives the three answers through the real inbox: the
// verb in the URL is what decides, and the waiting call sees the verdict.
func TestApprovalButtons(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.Parse([]byte("version: 1\nupstreams:\n  - name: fs\n    stdio: [\"true\"]\npolicy:\n  default: allow\n"))
	require.NoError(t, err)
	cfg.Audit.Path = filepath.Join(t.TempDir(), "audit.db")
	store, err := audit.Open(ctx, audit.Options{Path: cfg.Audit.Path})
	require.NoError(t, err)
	t.Cleanup(func() { store.Close(ctx) })

	inbox := proxy.NewInbox()
	srv, err := New(Options{Store: store, Config: func() *config.Config { return cfg }, Approvals: inbox})
	require.NoError(t, err)
	h := srv.Handler()

	for _, tc := range []struct {
		verb        string
		wantAllow   bool
		wantSession bool
	}{
		{"allow", true, false},
		{"allow-session", true, true},
		{"deny", false, false},
	} {
		t.Run(tc.verb, func(t *testing.T) {
			done := make(chan proxy.Verdict, 1)
			go func() {
				v, _ := inbox.Approve(ctx, proxy.ApprovalRequest{Tool: "fs__write_file", Decision: policy.Decision{RuleID: "ask-first"}})
				done <- v
			}()
			require.Eventually(t, func() bool { return len(inbox.Pending()) == 1 }, 3*time.Second, 10*time.Millisecond)

			page := get(t, h, "/approvals").Body.String()
			require.Contains(t, page, "Allow for this session")
			require.Contains(t, page, "fs__write_file")

			id := inbox.Pending()[0].ID
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/approvals/"+id+"/"+tc.verb, nil))
			require.Equal(t, http.StatusOK, rec.Code)

			v := <-done
			require.Equal(t, tc.wantAllow, v.Action == policy.ActionAllow)
			require.Equal(t, tc.wantSession, v.Session)
			require.Contains(t, v.Reason, "the web UI")
		})
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/approvals/x/maybe", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code, "an unknown verb is rejected, not treated as deny")
}
