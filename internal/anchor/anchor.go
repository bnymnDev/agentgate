// Package anchor writes the head of the audit chain somewhere the machine
// that keeps the log cannot rewrite. The chain shows every edit, deletion and
// insertion by itself; only a cut-off end needs an outside witness, and an
// anchor is that witness: a statement "the chain reached seq N with hash H at
// time T", kept in a file, posted to a webhook or timestamped in Bitcoin
// through OpenTimestamps. `agentgate verify --anchors` checks them all.
package anchor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bnymnDev/agentgate/internal/audit"
)

// Statement is one anchor.
type Statement struct {
	Seq  int64     `json:"seq"`
	Hash string    `json:"hash"`
	At   time.Time `json:"at"`
	Host string    `json:"host,omitempty"`
	Log  string    `json:"log,omitempty"`
}

// New makes a statement for a link, now.
func New(head audit.Link, log string) Statement {
	host, _ := os.Hostname()
	return Statement{Seq: head.Seq, Hash: head.Hash, At: time.Now().UTC().Truncate(time.Second), Host: host, Log: log}
}

// Link is the chain position the statement names.
func (s Statement) Link() audit.Link { return audit.Link{Seq: s.Seq, Hash: s.Hash} }

// Line is the statement as one line of JSON, which is what every
// destination stores and what OpenTimestamps stamps.
func (s Statement) Line() []byte {
	b, _ := json.Marshal(s)
	return append(b, '\n')
}

// Destination is where a statement goes. Parse reads one.
type Destination interface {
	Publish(ctx context.Context, s Statement) (string, error)
	String() string
}

// DefaultCalendars are the public OpenTimestamps calendars. A proof from
// any one of them is enough; asking two keeps one outage from losing it.
var DefaultCalendars = []string{"https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"}

// Parse reads a destination:
//
//	https://example.com/hook   POST the statement as JSON (an ntfy topic URL works)
//	ots:./anchors              stamp it with OpenTimestamps, keep the proof in the directory
//	file:./anchors.jsonl       append it to a file (also: a bare path)
func Parse(s string, client *http.Client) (Destination, error) {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	switch {
	case s == "":
		return nil, errors.New("anchor destination: empty")
	case strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://"):
		return webhook{url: s, client: client}, nil
	case strings.HasPrefix(s, "ots:") || strings.HasPrefix(s, "opentimestamps:"):
		_, dir, _ := strings.Cut(s, ":")
		if dir == "" {
			return nil, fmt.Errorf("anchor destination %q: name the directory the proofs go to, ots:<dir>", s)
		}
		return OTS{Dir: dir, Calendars: DefaultCalendars, Client: client}, nil
	default:
		return File{Path: strings.TrimPrefix(s, "file:")}, nil
	}
}

// File appends statements to a file, one per line. Put it in a git
// repository, a synced folder or a mounted share and it is out of reach of
// whoever edits the log.
type File struct{ Path string }

func (f File) String() string { return "file " + f.Path }

// Publish appends the statement.
func (f File) Publish(_ context.Context, s Statement) (string, error) {
	if dir := filepath.Dir(f.Path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return "", err
		}
	}
	fh, err := os.OpenFile(f.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	if _, err := fh.Write(s.Line()); err != nil {
		_ = fh.Close()
		return "", err
	}
	return f.Path, fh.Close()
}

type webhook struct {
	url    string
	client *http.Client
}

func (w webhook) String() string { return "webhook " + redactURL(w.url) }

func (w webhook) Publish(ctx context.Context, s Statement) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(s.Line()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Title", fmt.Sprintf("agentgate audit anchor %d", s.Seq))
	resp, err := w.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("%s answered %s", redactURL(w.url), resp.Status)
	}
	return redactURL(w.url), nil
}

// redactURL keeps credentials in a URL out of output.
func redactURL(u string) string {
	scheme, rest, ok := strings.Cut(u, "://")
	if !ok {
		return u
	}
	if at := strings.Index(rest, "@"); at >= 0 && at < strings.IndexAny(rest+"/", "/") {
		rest = rest[at+1:]
	}
	if q := strings.IndexAny(rest, "?#"); q >= 0 {
		rest = rest[:q]
	}
	return scheme + "://" + rest
}

// Read loads the anchors kept in a file: JSON statements one per line, or
// plain seq:hash lines as verify prints them. Blank lines and lines starting
// with # are skipped.
func Read(path string) ([]audit.Link, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var links []audit.Link
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "{") {
			var s Statement
			if err := json.Unmarshal([]byte(line), &s); err != nil || s.Seq <= 0 || s.Hash == "" {
				return nil, fmt.Errorf("%s:%d: not an anchor statement", path, n)
			}
			links = append(links, s.Link())
			continue
		}
		l, err := audit.ParseLink(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		links = append(links, l)
	}
	return links, sc.Err()
}

// ReadDir loads every anchor statement an ots: destination left in dir.
func ReadDir(dir string) ([]audit.Link, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "anchor-*.json"))
	if err != nil {
		return nil, err
	}
	var links []audit.Link
	for _, m := range matches {
		got, err := Read(m)
		if err != nil {
			return nil, err
		}
		links = append(links, got...)
	}
	return links, nil
}

// digest is what OpenTimestamps stamps: the sha256 of the statement line.
func digest(line []byte) [32]byte { return sha256.Sum256(line) }
