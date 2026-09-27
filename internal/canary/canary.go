// Package canary plants fake credentials and watches for them leaving.
//
// A canary is a value that looks exactly like a real secret — an AWS key
// pair, a GitHub token, a database password — and is worth nothing. Put it
// where an agent could read it (a decoy .env, a fake credentials file) and
// nothing legitimate will ever send it anywhere. So when a tool call carries
// it out, in plain text or base64 or hex or URL-encoded, that call is an
// exfiltration attempt, and agentgate stops it.
package canary

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Canary is one planted fake secret.
type Canary struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	Kind  string `json:"kind"`
	// Values are the strings that must never leave: an access key id and
	// its secret, a token, a password.
	Values []string `json:"values"`
	// File is the decoy written for it, if any.
	File      string    `json:"file,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Kinds of canary, each shaped like the real thing.
var Kinds = []string{"aws", "github", "openai", "stripe", "password"}

// Generate makes a new canary of a kind.
func Generate(kind, label string) (Canary, error) {
	c := Canary{ID: "cn_" + randString(alnumLower, 10), Label: label, Kind: kind, CreatedAt: time.Now().UTC()}
	switch kind {
	case "aws":
		c.Values = []string{"AKIA" + randString(upperDigits, 16), randString(base64ish, 40)}
	case "github":
		c.Values = []string{"ghp_" + randString(alnum, 36)}
	case "openai":
		c.Values = []string{"sk-proj-" + randString(alnum, 48)}
	case "stripe":
		c.Values = []string{"sk_live_" + randString(alnum, 24)}
	case "password", "":
		c.Kind = "password"
		c.Values = []string{randString(alnum, 6) + "-" + randString(alnum, 6) + "-" + randString(alnum, 6)}
	default:
		return c, fmt.Errorf("unknown canary kind %q, use one of %s", kind, strings.Join(Kinds, ", "))
	}
	return c, nil
}

// Decoy renders the canary as the file an agent would expect to find it in.
func (c Canary) Decoy() string { return c.DecoyFor("") }

// DecoyFor renders the canary for a file at path: as dotenv lines when the
// file is a .env file, and otherwise in the format the real secret usually
// lives in. A decoy that looks out of place is one an agent might not use.
func (c Canary) DecoyFor(path string) string {
	base := strings.ToLower(filepath.Base(path))
	dotenv := strings.HasPrefix(base, ".env") || strings.HasSuffix(base, ".env")
	switch c.Kind {
	case "aws":
		if dotenv {
			return fmt.Sprintf("AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nAWS_DEFAULT_REGION=us-east-1\n", c.Values[0], c.Values[1])
		}
		return fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\nregion = us-east-1\n", c.Values[0], c.Values[1])
	case "github":
		return fmt.Sprintf("GITHUB_TOKEN=%s\n", c.Values[0])
	case "openai":
		return fmt.Sprintf("OPENAI_API_KEY=%s\n", c.Values[0])
	case "stripe":
		return fmt.Sprintf("STRIPE_SECRET_KEY=%s\n", c.Values[0])
	default:
		return fmt.Sprintf("DATABASE_URL=postgres://admin:%s@db.internal:5432/production\n", c.Values[0])
	}
}

const (
	alnumLower  = "abcdefghijklmnopqrstuvwxyz0123456789"
	alnum       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	base64ish   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

func randString(alphabet string, n int) string {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		k, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err) // crypto/rand does not fail on supported platforms
		}
		out[i] = alphabet[k.Int64()]
	}
	return string(out)
}

// Store is the canaries file: canaries.json next to the audit database, so
// every agentgate process that shares a config shares its canaries.
type Store struct {
	path string

	mu       sync.Mutex
	canaries []Canary
	stamp    fileStamp
	checked  time.Time
	detector *Detector
}

type fileStamp struct {
	mod  time.Time
	size int64
}

// Open reads the store; a missing file is an empty store.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path is where the store lives.
func (s *Store) Path() string { return s.path }

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.canaries, s.stamp = nil, fileStamp{}
		s.detector = newDetector(nil)
		return nil
	}
	if err != nil {
		return err
	}
	var file struct {
		Canaries []Canary `json:"canaries"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("%s: %w", s.path, err)
	}
	s.canaries = file.Canaries
	if info, err := os.Stat(s.path); err == nil {
		s.stamp = fileStamp{mod: info.ModTime(), size: info.Size()}
	}
	s.detector = newDetector(s.canaries)
	return nil
}

func (s *Store) save() error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"canaries": s.canaries}); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	return s.load()
}

// Add stores a canary.
func (s *Store) Add(c Canary) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	s.canaries = append(s.canaries, c)
	return s.save()
}

// Remove deletes the canaries with this id or label and returns them.
func (s *Store) Remove(idOrLabel string) ([]Canary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
	var kept, gone []Canary
	for _, c := range s.canaries {
		if c.ID == idOrLabel || (c.Label != "" && c.Label == idOrLabel) {
			gone = append(gone, c)
			continue
		}
		kept = append(kept, c)
	}
	if len(gone) == 0 {
		return nil, fmt.Errorf("no canary %q", idOrLabel)
	}
	s.canaries = kept
	return gone, s.save()
}

// List returns the canaries, oldest first.
func (s *Store) List() []Canary {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	out := append([]Canary(nil), s.canaries...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Detector returns a detector for the current canaries, picking up changes
// another process made to the file at most once a second.
func (s *Store) Detector() *Detector {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	return s.detector
}

func (s *Store) refresh() {
	if time.Since(s.checked) < time.Second {
		return
	}
	s.checked = time.Now()
	info, err := os.Stat(s.path)
	var now fileStamp
	if err == nil {
		now = fileStamp{mod: info.ModTime(), size: info.Size()}
	}
	if now != s.stamp {
		// A file that fails to parse keeps the old canaries armed rather
		// than disarming all of them.
		_ = s.load()
	}
}

// Hit is a canary found in a call.
type Hit struct {
	Canary Canary
	// Encoding is how it was dressed up: plain, base64, hex, url, reversed.
	Encoding string
}

// Detector finds canary values in arbitrary text, including the common ways
// of dressing a secret up to get it past a filter.
type Detector struct {
	needles []needle
	list    []Canary
}

type needle struct {
	text     string
	canary   int
	encoding string
	fold     bool
}

func newDetector(canaries []Canary) *Detector {
	d := &Detector{list: canaries}
	for i, c := range canaries {
		for _, v := range c.Values {
			if len(v) < 8 {
				continue
			}
			d.add(i, "plain", v, false)
			d.add(i, "reversed", reverse(v), false)
			d.add(i, "hex", hex.EncodeToString([]byte(v)), true)
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
				for _, part := range base64Fragments(enc, v) {
					d.add(i, "base64", part, false)
				}
			}
		}
	}
	return d
}

func (d *Detector) add(i int, encoding, text string, fold bool) {
	if fold {
		text = strings.ToLower(text)
	}
	d.needles = append(d.needles, needle{text: text, canary: i, encoding: encoding, fold: fold})
}

// Empty reports whether there is nothing to look for.
func (d *Detector) Empty() bool { return d == nil || len(d.needles) == 0 }

// Find reports the first canary in text.
func (d *Detector) Find(text string) (Hit, bool) {
	if d.Empty() || text == "" {
		return Hit{}, false
	}
	candidates := []struct {
		text     string
		encoding string
	}{{text, ""}}
	// Percent-encoding and JSON's \u escapes both hide a value from a plain
	// substring search; undo them once.
	if strings.Contains(text, "%") {
		if u, err := url.QueryUnescape(text); err == nil && u != text {
			candidates = append(candidates, struct {
				text     string
				encoding string
			}{u, "url"})
		}
	}
	lower := ""
	for _, n := range d.needles {
		for _, c := range candidates {
			hay := c.text
			if n.fold {
				if c.encoding == "" {
					if lower == "" {
						lower = strings.ToLower(text)
					}
					hay = lower
				} else {
					hay = strings.ToLower(hay)
				}
			}
			if strings.Contains(hay, n.text) {
				enc := n.encoding
				if c.encoding != "" && enc == "plain" {
					enc = c.encoding
				}
				return Hit{Canary: d.list[n.canary], Encoding: enc}, true
			}
		}
	}
	return Hit{}, false
}

// Values returns every canary value, for callers that must leave them alone
// (the result redaction, for one).
func (d *Detector) Values() []string {
	if d == nil {
		return nil
	}
	var out []string
	for _, c := range d.list {
		out = append(out, c.Values...)
	}
	return out
}

// base64Fragments returns, for each of the three ways v can line up with
// base64's 3-byte groups when it sits inside a longer text, the part of its
// encoding that does not depend on the neighbouring bytes.
func base64Fragments(enc *base64.Encoding, v string) []string {
	var out []string
	for pad := 0; pad < 3; pad++ {
		prefix := strings.Repeat("\x00", pad)
		full := enc.EncodeToString([]byte(prefix + v))
		// Characters that mix in the prefix are unstable, and so are the
		// last ones, which mix in whatever follows.
		start := 0
		if pad > 0 {
			start = (pad*8 + 5) / 6
		}
		end := (len(prefix+v) * 8) / 6
		if end > len(full) {
			end = len(full)
		}
		if end-start >= 8 {
			out = append(out, full[start:end])
		}
	}
	return out
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// Strings flattens a decoded JSON value into its strings, keys included, one
// per line. Searching those rather than the raw JSON undoes the escapes
// (\u0041 for A) a value could otherwise hide behind.
func Strings(v any) string {
	var b strings.Builder
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			b.WriteString(t)
			b.WriteByte('\n')
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for k, e := range t {
				b.WriteString(k)
				b.WriteByte('\n')
				walk(e)
			}
		}
	}
	walk(v)
	return b.String()
}
