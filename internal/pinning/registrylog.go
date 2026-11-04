package pinning

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// A registry keeps a log of everything ever published to it, in the shape
// of Certificate Transparency (RFC 6962): log.jsonl has one record per
// publication, append only, and head.json the size of the log and the root
// of a Merkle tree over it. Whoever noted a head earlier can check that the
// log only grew since — that no publication was taken back or changed —
// and anyone can see that a server version was published twice with
// different definitions, which in a registry of trusted definitions is
// exactly the thing to look at.

// LogRecord is one publication.
type LogRecord struct {
	Index   int       `json:"index"`
	Path    string    `json:"path"`
	Server  string    `json:"server"`
	Version string    `json:"version"`
	Hash    string    `json:"hash"`
	At      time.Time `json:"at"`
}

// TreeHead is the size of the log and the root over it.
type TreeHead struct {
	Size int       `json:"size"`
	Root string    `json:"root"`
	At   time.Time `json:"at,omitempty"`
}

// String renders a head the way --head takes it: size:root.
func (h TreeHead) String() string { return fmt.Sprintf("%d:%s", h.Size, h.Root) }

// ParseTreeHead reads a head written as size:root.
func ParseTreeHead(s string) (TreeHead, error) {
	size, root, ok := strings.Cut(strings.TrimSpace(s), ":")
	var h TreeHead
	if !ok {
		return h, fmt.Errorf("head %q: want size:root", s)
	}
	if _, err := fmt.Sscanf(size, "%d", &h.Size); err != nil || h.Size < 0 {
		return h, fmt.Errorf("head %q: the size must be a number", s)
	}
	h.Root = root
	if strings.HasPrefix(root, "sha256") {
		h.Root = "sha256:" + strings.TrimPrefix(strings.TrimPrefix(root, "sha256"), ":")
	}
	return h, nil
}

const (
	logFile  = "log.jsonl"
	headFile = "head.json"
)

func fileHash(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func recordLeaf(line []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(line)
	return h.Sum(nil)
}

func treeRoot(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		sum := sha256.Sum256(nil)
		return sum[:]
	case 1:
		return leaves[0]
	}
	k := 1
	for k<<1 < len(leaves) {
		k <<= 1
	}
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(treeRoot(leaves[:k]))
	h.Write(treeRoot(leaves[k:]))
	return h.Sum(nil)
}

func rootOf(lines [][]byte) string {
	leaves := make([][]byte, len(lines))
	for i, l := range lines {
		leaves[i] = recordLeaf(l)
	}
	return "sha256:" + hex.EncodeToString(treeRoot(leaves))
}

// readLog reads the records and their exact lines.
func readLog(raw []byte) ([]LogRecord, [][]byte, error) {
	var recs []LogRecord
	var lines [][]byte
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r LogRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, nil, fmt.Errorf("%s line %d: %w", logFile, len(lines)+1, err)
		}
		recs = append(recs, r)
		lines = append(lines, line)
	}
	return recs, lines, sc.Err()
}

// appendLog records a publication, unless the latest record for the path
// already has this content, and rewrites the head.
func appendLog(dir, rel string, e Entry, content []byte) error {
	raw, err := os.ReadFile(filepath.Join(dir, logFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	recs, lines, err := readLog(raw)
	if err != nil {
		return err
	}
	hash := fileHash(content)
	for i := len(recs) - 1; i >= 0; i-- {
		if recs[i].Path == rel {
			if recs[i].Hash == hash {
				return nil
			}
			break
		}
	}
	rec := LogRecord{Index: len(recs), Path: rel, Server: e.Server, Version: e.Version, Hash: hash, At: time.Now().UTC().Truncate(time.Second)}
	line, _ := json.Marshal(rec)
	f, err := os.OpenFile(filepath.Join(dir, logFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // a registry is meant to be read
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	head := TreeHead{Size: len(lines) + 1, Root: rootOf(append(lines, line)), At: rec.At}
	hb, _ := json.MarshalIndent(head, "", "  ")
	return os.WriteFile(filepath.Join(dir, headFile), append(hb, '\n'), 0o644) //nolint:gosec // a registry is meant to be read
}

// LogReport is the outcome of checking a registry's log.
type LogReport struct {
	Head     TreeHead    `json:"head"`
	Records  int         `json:"records"`
	Entries  int         `json:"entries"`
	Rewrites []string    `json:"rewrites,omitempty"`
	Problems []string    `json:"problems,omitempty"`
	History  []LogRecord `json:"-"`
}

// OK reports whether the log holds.
func (r *LogReport) OK() bool { return len(r.Problems) == 0 }

// VerifyLog checks a registry against its log: every entry is the one the
// log last recorded for its path, nothing is in the registry that the log
// does not know, head.json is the root over the log, and, when prev is
// given, the log still starts with the prev.Size records prev was taken
// over.
func VerifyLog(ctx context.Context, source string, prev *TreeHead, client *http.Client) (*LogReport, error) {
	read := func(rel string) ([]byte, error) {
		if isURL(source) {
			return fetch(ctx, strings.TrimRight(source, "/")+"/"+rel, client)
		}
		return os.ReadFile(filepath.Join(source, filepath.FromSlash(rel)))
	}
	raw, err := read(logFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", logFile, err)
	}
	recs, lines, err := readLog(raw)
	if err != nil {
		return nil, err
	}
	rep := &LogReport{Records: len(recs), History: recs}
	rep.Head = TreeHead{Size: len(lines), Root: rootOf(lines)}
	latest := map[string]LogRecord{}
	count := map[string]int{}
	for i, r := range recs {
		if r.Index != i {
			rep.Problems = append(rep.Problems, fmt.Sprintf("record %d says it is record %d: records were removed or reordered", i, r.Index))
		}
		latest[r.Path] = r
		count[r.Path]++
	}
	paths := make([]string, 0, len(latest))
	for p := range latest {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		r := latest[p]
		if count[p] > 1 {
			rep.Rewrites = append(rep.Rewrites, fmt.Sprintf("%s was published %d times with different definitions", p, count[p]))
		}
		b, err := read(p)
		switch {
		case err != nil:
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s is in the log and gone from the registry", p))
		case fileHash(b) != r.Hash:
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s is not what the log recorded: it was changed without being published", p))
		default:
			rep.Entries++
		}
	}
	if hb, err := read(headFile); err == nil {
		var h TreeHead
		if json.Unmarshal(hb, &h) != nil || h.Size != rep.Head.Size || h.Root != rep.Head.Root {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s says %d:%s, the log is %s", headFile, h.Size, h.Root, rep.Head))
		}
	}
	if !isURL(source) {
		_ = filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
				return nil
			}
			rel, _ := filepath.Rel(source, path)
			rel = filepath.ToSlash(rel)
			if rel == headFile {
				return nil
			}
			if _, ok := latest[rel]; !ok {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%s is in the registry and not in the log: it was added by hand", rel))
			}
			return nil
		})
	}
	if prev != nil {
		switch {
		case prev.Size > len(lines):
			rep.Problems = append(rep.Problems, fmt.Sprintf("the log has %d records, fewer than the %d of the head noted before: it was cut", len(lines), prev.Size))
		case rootOf(lines[:prev.Size]) != prev.Root:
			rep.Problems = append(rep.Problems, fmt.Sprintf("the first %d records no longer hash to the head noted before: the log was rewritten", prev.Size))
		}
	}
	return rep, nil
}
