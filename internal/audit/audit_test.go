package audit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/policy"
)

func openTemp(t *testing.T, opts Options) *Store {
	t.Helper()
	if opts.Path == "" {
		opts.Path = filepath.Join(t.TempDir(), "audit.db")
	}
	store, err := Open(context.Background(), opts)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		store.Close(ctx)
	})
	return store
}

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	first := openTemp(t, Options{Path: path})
	v, err := first.SchemaVersion(context.Background())
	require.NoError(t, err)
	require.Equal(t, "0001_init", v)

	// Opening the same file again must not try to re-apply anything.
	second := openTemp(t, Options{Path: path})
	v2, err := second.SchemaVersion(context.Background())
	require.NoError(t, err)
	require.Equal(t, v, v2)
}

func TestSessionAndCallRoundTrip(t *testing.T) {
	store := openTemp(t, Options{})
	ctx := context.Background()

	sess := &Session{ID: NewID(), StartedAt: time.Now(), HostName: "test", DownstreamTransport: "stdio"}
	require.NoError(t, store.StartSession(ctx, sess))

	store.RecordCall(&Call{
		SessionID: sess.ID,
		Tool:      "fs__write_file",
		Upstream:  "fs",
		Args:      json.RawMessage(`{"path":"/tmp/x"}`),
		Result:    json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`),
		Decision:  policy.ActionAllow,
	})
	store.EndSession(sess.ID, time.Now())

	var calls []*Call
	require.Eventually(t, func() bool {
		var err error
		calls, err = store.ListCalls(ctx, CallFilter{SessionID: sess.ID})
		return err == nil && len(calls) == 1
	}, 3*time.Second, 20*time.Millisecond)

	got := calls[0]
	require.Equal(t, "fs__write_file", got.Tool)
	require.Equal(t, policy.ActionAllow, got.Decision)
	require.NotEmpty(t, got.ArgsHash)
	require.NotEmpty(t, got.ResultHash)
	require.Positive(t, got.TokensEst)

	// The session must be findable by a prefix, which is what the CLI relies on.
	found, err := store.GetSession(ctx, sess.ID[:8])
	require.NoError(t, err)
	require.Equal(t, sess.ID, found.ID)
	require.Equal(t, 1, found.Calls)
}

func TestRetentionRemovesOldSessionsAndTheirCalls(t *testing.T) {
	store := openTemp(t, Options{})
	ctx := context.Background()

	old := &Session{ID: NewID(), StartedAt: time.Now().Add(-48 * time.Hour)}
	recent := &Session{ID: NewID(), StartedAt: time.Now()}
	require.NoError(t, store.StartSession(ctx, old))
	require.NoError(t, store.StartSession(ctx, recent))
	store.RecordCall(&Call{SessionID: old.ID, Tool: "gone", Decision: policy.ActionAllow})
	require.Eventually(t, func() bool {
		calls, err := store.ListCalls(ctx, CallFilter{SessionID: old.ID})
		return err == nil && len(calls) == 1
	}, 3*time.Second, 20*time.Millisecond)

	n, err := store.Prune(ctx, time.Now().Add(-24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	sessions, err := store.ListSessions(ctx, SessionFilter{})
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, recent.ID, sessions[0].ID)

	orphans, err := store.ListCalls(ctx, CallFilter{SessionID: old.ID})
	require.NoError(t, err)
	require.Empty(t, orphans, "calls of a pruned session must go with it")
}

func TestAuditFailuresNeverBlock(t *testing.T) {
	store := openTemp(t, Options{})
	// No session row exists, so every insert violates the foreign key. The
	// store must swallow that: a broken audit log cannot be allowed to break a
	// tool call.
	for range 50 {
		store.RecordCall(&Call{SessionID: "nope", Tool: "x", Decision: policy.ActionAllow})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, store.Close(ctx))
}

func TestRedaction(t *testing.T) {
	r := NewRedactor([]*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S+`),
	})
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "a member whose key looks sensitive loses its value",
			in:   `{"api_key":"sk-live-123","keep":"me"}`,
			want: `{"api_key":"[REDACTED]","keep":"me"}`,
		},
		{
			name: "a secret inside free text is cut out, the rest survives",
			in:   `{"command":"curl -H token=abc123 https://x"}`,
			want: `{"command":"curl -H [REDACTED] https://x"}`,
		},
		{
			name: "nested objects and arrays are walked",
			in:   `{"a":{"b":[{"password":"hunter2"}]}}`,
			want: `{"a":{"b":[{"password":"[REDACTED]"}]}}`,
		},
		{
			name: "documents with nothing to hide are untouched",
			in:   `{"path":"/tmp/x","n":3}`,
			want: `{"n":3,"path":"/tmp/x"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := r.Redact([]byte(tc.in))
			require.JSONEq(t, tc.want, string(got))
			// Whatever happens, the output has to stay valid JSON: the UI, the
			// diff and the replay all parse it again.
			var v any
			require.NoError(t, json.Unmarshal(got, &v))
		})
	}
}

func TestRedactionKeepsNonJSONReadable(t *testing.T) {
	r := NewRedactor([]*regexp.Regexp{regexp.MustCompile(`token=\S+`)})
	got := r.Redact([]byte("not json at all, token=abc123"))
	require.Equal(t, "not json at all, [REDACTED]", string(got))
}

func TestHashIsCanonical(t *testing.T) {
	// Key order and whitespace must not change the hash, or diff and replay
	// would report changes that never happened.
	a := Hash([]byte(`{"b":2,"a":1}`))
	b := Hash([]byte("{\n  \"a\": 1,\n  \"b\": 2\n}"))
	require.Equal(t, a, b)
	require.NotEqual(t, a, Hash([]byte(`{"a":1,"b":3}`)))
	require.Empty(t, Hash(nil), "an absent document has no hash")
}

func TestTruncateStaysValidJSON(t *testing.T) {
	big := make([]byte, 0, 4096)
	big = append(big, '"')
	for range 4000 {
		big = append(big, 'x')
	}
	big = append(big, '"')

	out, cut := Truncate(big, 100)
	require.True(t, cut)
	var v map[string]any
	require.NoError(t, json.Unmarshal(out, &v))
	require.Equal(t, true, v["_agentgate_truncated"])

	small := []byte(`{"a":1}`)
	out, cut = Truncate(small, 100)
	require.False(t, cut)
	require.Equal(t, small, out)
}

func TestStoredResultsAreCapped(t *testing.T) {
	store := openTemp(t, Options{MaxResultBytes: 64})
	ctx := context.Background()
	sess := &Session{ID: NewID(), StartedAt: time.Now()}
	require.NoError(t, store.StartSession(ctx, sess))

	long := make([]byte, 0, 600)
	long = append(long, '"')
	for range 500 {
		long = append(long, 'y')
	}
	long = append(long, '"')
	store.RecordCall(&Call{SessionID: sess.ID, Tool: "big", Decision: policy.ActionAllow, Result: long})

	var calls []*Call
	require.Eventually(t, func() bool {
		var err error
		calls, err = store.ListCalls(ctx, CallFilter{SessionID: sess.ID})
		return err == nil && len(calls) == 1
	}, 3*time.Second, 20*time.Millisecond)
	require.True(t, calls[0].ResultTruncated)
	require.Less(t, len(calls[0].Result), 200)
	// The hash is taken before truncation, so it still identifies the real result.
	require.Equal(t, Hash(long), calls[0].ResultHash)
}
