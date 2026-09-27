package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// record writes n calls to a fresh session and waits until they are stored.
func record(t *testing.T, store *Store, n int, at time.Time) *Session {
	t.Helper()
	ctx := context.Background()
	sess := &Session{ID: NewID(), StartedAt: at}
	require.NoError(t, store.StartSession(ctx, sess))
	for i := range n {
		store.RecordCall(&Call{
			SessionID: sess.ID, TS: at.Add(time.Duration(i) * time.Second),
			Tool: "fs__read_file", Upstream: "fs",
			Args:     json.RawMessage(fmt.Sprintf(`{"path":"/tmp/%d"}`, i)),
			Result:   json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`),
			Decision: policy.ActionAllow, Labels: []string{"private-data"},
		})
	}
	require.Eventually(t, func() bool {
		calls, err := store.ListCalls(ctx, CallFilter{SessionID: sess.ID})
		return err == nil && len(calls) == n
	}, 5*time.Second, 10*time.Millisecond)
	return sess
}

func TestChainVerifies(t *testing.T) {
	store := openTemp(t, Options{})
	ctx := context.Background()
	sess := record(t, store, 5, time.Now())

	report, err := store.Verify(ctx, nil)
	require.NoError(t, err)
	require.True(t, report.OK(), "%+v", report.Problems)
	require.EqualValues(t, 5, report.Checked)
	require.EqualValues(t, 5, report.Head.Seq)

	calls, err := store.ListCalls(ctx, CallFilter{SessionID: sess.ID})
	require.NoError(t, err)
	require.EqualValues(t, 1, calls[0].Seq)
	require.Empty(t, calls[0].PrevHash)
	require.Equal(t, calls[0].RowHash, calls[1].PrevHash)
	require.Equal(t, []string{"private-data"}, calls[0].Labels)

	head, err := store.Head(ctx)
	require.NoError(t, err)
	require.Equal(t, report.Head, head)
}

func TestChainCatchesEditsAndDeletes(t *testing.T) {
	ctx := context.Background()
	for name, tamper := range map[string]struct {
		sql  string
		want string
	}{
		"edited decision": {`UPDATE calls SET decision = 'deny', rule_id = 'hidden' WHERE seq = 3`, "was changed after it was written"},
		"edited args":     {`UPDATE calls SET args_json = '{"path":"/tmp/elsewhere"}' WHERE seq = 2`, "was changed after it was written"},
		"deleted row":     {`DELETE FROM calls WHERE seq = 3`, "missing before seq 4"},
		"relinked row": {
			`UPDATE calls SET prev_hash = (SELECT row_hash FROM calls WHERE seq = 1) WHERE seq = 3`,
			"does not link to the call before it",
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := openTemp(t, Options{})
			record(t, store, 5, time.Now())
			_, err := store.db.ExecContext(ctx, tamper.sql)
			require.NoError(t, err)
			report, err := store.Verify(ctx, nil)
			require.NoError(t, err)
			require.False(t, report.OK())
			require.Contains(t, fmt.Sprint(report.Problems), tamper.want)
		})
	}
}

// Cutting calls off the end of the chain leaves a shorter chain that is
// still consistent. An anchor noted earlier is what catches that.
func TestAnchorCatchesATruncatedChain(t *testing.T) {
	ctx := context.Background()
	store := openTemp(t, Options{})
	record(t, store, 5, time.Now())
	head, err := store.Head(ctx)
	require.NoError(t, err)

	report, err := store.Verify(ctx, &head)
	require.NoError(t, err)
	require.True(t, report.OK())
	require.True(t, report.AnchorChecked)

	_, err = store.db.ExecContext(ctx, `DELETE FROM calls WHERE seq >= 4`)
	require.NoError(t, err)
	report, err = store.Verify(ctx, nil)
	require.NoError(t, err)
	require.True(t, report.OK(), "without an anchor a cut-off tail is invisible")

	report, err = store.Verify(ctx, &head)
	require.NoError(t, err)
	require.False(t, report.OK())
	require.Contains(t, fmt.Sprint(report.Problems), "no longer reaches the anchor")

	wrong := Link{Seq: 2, Hash: head.Hash}
	report, err = store.Verify(ctx, &wrong)
	require.NoError(t, err)
	require.Contains(t, fmt.Sprint(report.Problems), "not the call the anchor names")
}

// Retention removes the front of the chain and leaves an anchor, so what is
// left still verifies, and new calls continue the same chain.
func TestPruneKeepsTheChainVerifiable(t *testing.T) {
	ctx := context.Background()
	store := openTemp(t, Options{})
	old := record(t, store, 3, time.Now().Add(-72*time.Hour))
	recent := record(t, store, 2, time.Now())

	n, err := store.Prune(ctx, time.Now().Add(-24*time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	_, err = store.GetSession(ctx, old.ID)
	require.ErrorIs(t, err, ErrNotFound)

	report, err := store.Verify(ctx, nil)
	require.NoError(t, err)
	require.True(t, report.OK(), "%+v", report.Problems)
	require.NotNil(t, report.Anchor)
	require.EqualValues(t, 3, report.Anchor.Seq)
	require.EqualValues(t, 2, report.Checked)

	record(t, store, 1, time.Now())
	report, err = store.Verify(ctx, nil)
	require.NoError(t, err)
	require.True(t, report.OK(), "%+v", report.Problems)
	require.EqualValues(t, 6, report.Head.Seq)

	// Pruning everything leaves only the anchor; the next call links to it.
	_, err = store.Prune(ctx, time.Now().Add(time.Hour))
	require.NoError(t, err)
	calls, err := store.ListCalls(ctx, CallFilter{SessionID: recent.ID})
	require.NoError(t, err)
	require.Empty(t, calls)
	record(t, store, 1, time.Now().Add(2*time.Hour))
	report, err = store.Verify(ctx, nil)
	require.NoError(t, err)
	require.True(t, report.OK(), "%+v", report.Problems)
	require.EqualValues(t, 7, report.Head.Seq)
}

// A long call keeps its place in the chain: retention never deletes a link
// while an earlier one is still within the period.
func TestPruneOnlyCutsAPrefix(t *testing.T) {
	ctx := context.Background()
	store := openTemp(t, Options{})
	now := time.Now()
	sess := &Session{ID: NewID(), StartedAt: now.Add(-72 * time.Hour)}
	require.NoError(t, store.StartSession(ctx, sess))
	for i, ts := range []time.Time{now.Add(-72 * time.Hour), now, now.Add(-48 * time.Hour)} {
		store.RecordCall(&Call{SessionID: sess.ID, TS: ts, Tool: fmt.Sprint("t", i), Decision: policy.ActionAllow})
		require.Eventually(t, func() bool {
			h, err := store.Head(ctx)
			return err == nil && h.Seq == int64(i+1)
		}, 3*time.Second, 10*time.Millisecond)
	}
	_, err := store.Prune(ctx, now.Add(-24*time.Hour))
	require.NoError(t, err)
	calls, err := store.ListCalls(ctx, CallFilter{SessionID: sess.ID})
	require.NoError(t, err)
	require.Len(t, calls, 2, "the old call after a recent one stays")
	report, err := store.Verify(ctx, nil)
	require.NoError(t, err)
	require.True(t, report.OK(), "%+v", report.Problems)
}

// Several agentgate processes can share one audit database. Their writes
// must still form one chain.
func TestChainAcrossProcesses(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	a := openTemp(t, Options{Path: path})
	b := openTemp(t, Options{Path: path})
	sa := &Session{ID: NewID(), StartedAt: time.Now()}
	sb := &Session{ID: NewID(), StartedAt: time.Now()}
	require.NoError(t, a.StartSession(ctx, sa))
	require.NoError(t, b.StartSession(ctx, sb))

	var wg sync.WaitGroup
	for _, w := range []struct {
		store *Store
		sess  *Session
	}{{a, sa}, {b, sb}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 40 {
				w.store.RecordCall(&Call{SessionID: w.sess.ID, Tool: fmt.Sprint("t", i), Decision: policy.ActionAllow})
			}
		}()
	}
	wg.Wait()
	require.Eventually(t, func() bool {
		h, err := a.Head(ctx)
		return err == nil && h.Seq == 80
	}, 10*time.Second, 20*time.Millisecond)
	report, err := a.Verify(ctx, nil)
	require.NoError(t, err)
	require.True(t, report.OK(), "%+v", report.Problems)
	require.EqualValues(t, 80, report.Checked)
}

// Rows written before the chain existed are counted, not verified.
func TestLegacyRowsAreReportedNotVerified(t *testing.T) {
	ctx := context.Background()
	store := openTemp(t, Options{})
	sess := record(t, store, 1, time.Now())
	_, err := store.db.ExecContext(ctx,
		`INSERT INTO calls (id, session_id, ts, tool, decision) VALUES ('legacy', ?, 1, 'x', 'allow')`, sess.ID)
	require.NoError(t, err)
	report, err := store.Verify(ctx, nil)
	require.NoError(t, err)
	require.True(t, report.OK())
	require.EqualValues(t, 1, report.Legacy)
	require.EqualValues(t, 1, report.Checked)
}

func TestParseLink(t *testing.T) {
	l, err := ParseLink(" 42:ABCDEF ")
	require.NoError(t, err)
	require.Equal(t, Link{Seq: 42, Hash: "abcdef"}, l)
	require.Equal(t, "42:abcdef", l.String())
	for _, bad := range []string{"", "42", "42:", "x:abc", "0:abc", "-1:abc"} {
		_, err := ParseLink(bad)
		require.Error(t, err, bad)
	}
}

func TestCatalogIsStoredOnce(t *testing.T) {
	ctx := context.Background()
	store := openTemp(t, Options{})
	raw := []byte(`[{"exposed":"fs__read_file","upstream":"fs","tool":{"name":"read_file"}}]`)
	h1 := store.SaveCatalog(raw)
	h2 := store.SaveCatalog([]byte(`[{"upstream":"fs","exposed":"fs__read_file","tool":{"name":"read_file"}}]`))
	require.Equal(t, h1, h2, "the hash is over the canonical form")
	require.Eventually(t, func() bool {
		got, err := store.Catalog(ctx, h1)
		return err == nil && len(got) > 0
	}, 3*time.Second, 10*time.Millisecond)
	_, err := store.Catalog(ctx, "nope")
	require.ErrorIs(t, err, ErrNotFound)
}

// Two agentgate processes upgrading the same database at once must not trip
// over each other's migrations.
func TestConcurrentMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := Open(context.Background(), Options{Path: path})
			if err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				err = s.Close(ctx)
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
}
