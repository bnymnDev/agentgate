package anchor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/audit"
)

func statement() Statement { return New(audit.Link{Seq: 7, Hash: "ab12"}, "/var/log/agentgate.db") }

func TestFileAppendsAndReadsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "anchors.jsonl")
	d, err := Parse("file:"+path, nil)
	require.NoError(t, err)
	ctx := context.Background()
	_, err = d.Publish(ctx, statement())
	require.NoError(t, err)
	s2 := statement()
	s2.Seq, s2.Hash = 9, "cd34"
	_, err = d.Publish(ctx, s2)
	require.NoError(t, err)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)
	_, _ = f.WriteString("\n# by hand\n11:ef56\n")
	require.NoError(t, f.Close())

	links, err := Read(path)
	require.NoError(t, err)
	require.Equal(t, []audit.Link{{Seq: 7, Hash: "ab12"}, {Seq: 9, Hash: "cd34"}, {Seq: 11, Hash: "ef56"}}, links)

	require.NoError(t, os.WriteFile(path, []byte("{\"seq\":0}\n"), 0o600))
	_, err = Read(path)
	require.ErrorContains(t, err, "not an anchor statement")
}

func TestWebhookPostsTheStatement(t *testing.T) {
	var got Statement
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
	}))
	defer srv.Close()
	d, err := Parse(srv.URL+"/topic?auth=secret", srv.Client())
	require.NoError(t, err)
	require.NotContains(t, d.String(), "secret")
	_, err = d.Publish(context.Background(), statement())
	require.NoError(t, err)
	require.Equal(t, statement().Link(), got.Link())

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer failing.Close()
	d, _ = Parse(failing.URL, failing.Client())
	_, err = d.Publish(context.Background(), statement())
	require.ErrorContains(t, err, "403")
}

func TestRedactURL(t *testing.T) {
	require.Equal(t, "https://host/path", redactURL("https://user:pw@host/path?token=x#f"))
	require.Equal(t, "https://host/a@b", redactURL("https://host/a@b"))
}

// The proof is the detached timestamp format the OpenTimestamps client
// reads: header, sha256 of the statement file, and one branch per calendar.
func TestOTSWritesADetachedTimestamp(t *testing.T) {
	cal := func(answer []byte) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "/digest", r.URL.Path)
			body, _ := io.ReadAll(r.Body)
			require.Len(t, body, 32)
			_, _ = w.Write(answer)
		}))
	}
	a, b := cal([]byte{0xf0, 0x01, 0xaa}), cal([]byte{0xf0, 0x01, 0xbb})
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer a.Close()
	defer b.Close()
	defer down.Close()

	dir := t.TempDir()
	o := OTS{Dir: dir, Calendars: []string{a.URL, down.URL, b.URL}}
	where, err := o.Publish(context.Background(), statement())
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "anchor-7.json.ots"), where)

	line, err := os.ReadFile(filepath.Join(dir, "anchor-7.json"))
	require.NoError(t, err)
	require.Equal(t, statement().Line(), line)
	proof, err := os.ReadFile(where)
	require.NoError(t, err)
	sum := digest(line)
	want := append(append(append([]byte{}, otsMagic...), otsVersion, otsSHA256), sum[:]...)
	want = append(want, 0xff, 0xf0, 0x01, 0xaa, 0xf0, 0x01, 0xbb)
	require.True(t, bytes.Equal(want, proof), "%x", proof)

	links, err := ReadDir(dir)
	require.NoError(t, err)
	require.Equal(t, []audit.Link{statement().Link()}, links)

	_, err = OTS{Dir: dir, Calendars: []string{down.URL}}.Publish(context.Background(), statement())
	require.ErrorContains(t, err, "no calendar took the timestamp")
}

func TestParse(t *testing.T) {
	_, err := Parse("ots:", nil)
	require.Error(t, err)
	d, err := Parse("./anchors.jsonl", nil)
	require.NoError(t, err)
	require.Equal(t, "file ./anchors.jsonl", d.String())
	d, err = Parse("opentimestamps:/tmp/x", nil)
	require.NoError(t, err)
	require.Equal(t, "OpenTimestamps into /tmp/x", d.String())
}
