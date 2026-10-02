// Package skills pins Agent Skills the way package-lock.json pins packages.
//
// A skill is a directory with a SKILL.md in it — instructions in plain
// language, and often scripts next to them — that a coding agent loads into
// its context and follows. That makes a skill a dependency like any other,
// with one difference: its payload is prose, read by a model. A skill that was
// harmless when it was installed can be changed later, and one that ships a
// hidden instruction from the start looks, to a person, exactly like one that
// does not.
//
// This package hashes every file of a skill into a Merkle root, derives a
// label of what the skill can do (reach the network, run a shell, read
// secrets, ...), runs a set of deterministic rules for the tricks poisoned
// skills use, and keeps all of it in a lockfile. A change to any file, a new
// capability or a new finding is drift until a human approves it.
package skills

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// ManifestName is the file that makes a directory a skill.
const ManifestName = "SKILL.md"

const (
	// maxScanBytes is how much of a text file the rules and the label read.
	// Every byte is hashed regardless; only the scan is capped.
	maxScanBytes = 1 << 20
	// maxReadBytes is the largest file read into memory to be hashed with
	// its line endings normalised. Larger files are hashed as a stream,
	// byte for byte.
	maxReadBytes = 16 << 20
)

// File kinds.
const (
	KindFile    = "file"
	KindSymlink = "symlink"
	KindSpecial = "special"
)

// File is one file of a skill, as it is on disk.
type File struct {
	// Path is relative to the skill directory, with forward slashes.
	Path string `json:"path"`
	Kind string `json:"kind"`
	// Hash is the SHA-256 of the content, with CRLF line endings of a text
	// file read as LF; of a symlink, its target.
	Hash string `json:"hash"`
	Size int64  `json:"size"`
	// Target is where a symlink points.
	Target string `json:"target,omitempty"`
	// Binary is set for content that is not UTF-8 text.
	Binary bool `json:"binary,omitempty"`
	// Truncated is set when only the first part of the file was scanned.
	Truncated bool `json:"truncated,omitempty"`

	// text is the scanned content of a text file.
	text string
	// head is the first bytes of a binary file, for telling what it is.
	head []byte
}

// Skill is one skill directory, read from disk.
type Skill struct {
	// Key identifies the skill in the lockfile: its directory relative to
	// the project, or under ~ for a skill in the home directory.
	Key string `json:"key"`
	// Dir is where it is on disk.
	Dir string `json:"dir"`
	// Name is the name from the front matter, or the directory's.
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Link is where the skill directory points, when it is a symlink.
	Link  string `json:"link,omitempty"`
	Files []File `json:"files"`
	// Root is the Merkle root over every file.
	Root string `json:"root"`

	// Front is the parsed front matter of SKILL.md; FrontErr says why it
	// could not be parsed.
	Front    map[string]any `json:"-"`
	FrontErr string         `json:"-"`
}

// Manifest is the text of SKILL.md.
func (s *Skill) Manifest() string {
	for _, f := range s.Files {
		if f.Path == ManifestName {
			return f.text
		}
	}
	return ""
}

// file looks a file of the skill up by path.
func (s *Skill) file(path string) *File {
	for i := range s.Files {
		if s.Files[i].Path == path {
			return &s.Files[i]
		}
	}
	return nil
}

// Load reads a skill directory: every file is hashed, the text ones are kept
// for the scan. Symlinks inside the skill are recorded, never followed;
// named pipes and devices are recorded, never opened.
func Load(dir, key string) (*Skill, error) {
	s := &Skill{Key: key, Dir: dir, Name: filepath.Base(dir)}
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		target, _ := os.Readlink(dir)
		s.Link = filepath.ToSlash(target)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	err = filepath.WalkDir(real, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(real, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if path != real && skipDir(path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if skipFile(d.Name()) {
			return nil
		}
		f, err := readFile(path, rel, d)
		if err != nil {
			return err
		}
		s.Files = append(s.Files, f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(s.Files, func(i, j int) bool { return s.Files[i].Path < s.Files[j].Path })
	if s.file(ManifestName) == nil {
		return nil, fmt.Errorf("%s: no %s", dir, ManifestName)
	}
	s.Root = MerkleRoot(s.Files)
	s.parseFront()
	return s, nil
}

// skipDir leaves out a git checkout's own repository: its objects change on
// every fetch, and nothing in it is part of what the agent loads.
func skipDir(path, name string) bool {
	if name != ".git" {
		return false
	}
	_, err := os.Stat(filepath.Join(path, "HEAD"))
	return err == nil
}

// skipFile leaves out the litter desktop file managers leave behind.
func skipFile(name string) bool {
	return name == ".DS_Store" || name == "Thumbs.db"
}

func readFile(path, rel string, d fs.DirEntry) (File, error) {
	f := File{Path: rel, Kind: KindFile}
	info, err := d.Info()
	if err != nil {
		return f, err
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return f, err
		}
		f.Kind = KindSymlink
		f.Target = filepath.ToSlash(target)
		f.Hash = hashBytes([]byte("symlink\x00" + f.Target))
		return f, nil
	case !info.Mode().IsRegular():
		// A named pipe would block a read forever, and a device has no
		// business in a skill. Record that it is there, and what it is.
		f.Kind = KindSpecial
		f.Hash = hashBytes([]byte("special\x00" + info.Mode().Type().String()))
		return f, nil
	}
	f.Size = info.Size()
	fh, err := os.Open(path)
	if err != nil {
		return f, err
	}
	defer func() { _ = fh.Close() }()
	if f.Size > maxReadBytes {
		h := sha256.New()
		head := make([]byte, maxScanBytes)
		n, _ := io.ReadFull(fh, head)
		h.Write(head[:n])
		if _, err := io.Copy(h, fh); err != nil {
			return f, err
		}
		f.Hash = "sha256:" + hex.EncodeToString(h.Sum(nil))
		f.Truncated = true
		f.classify(head[:n], true)
		return f, nil
	}
	raw, err := io.ReadAll(fh)
	if err != nil {
		return f, err
	}
	f.Size = int64(len(raw))
	f.classify(raw, false)
	if f.Binary {
		f.Hash = hashBytes(raw)
	} else {
		f.Hash = hashBytes(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")))
	}
	return f, nil
}

// classify decides whether content is text and keeps what the scan reads.
func (f *File) classify(raw []byte, partial bool) {
	scan := raw
	if len(scan) > maxScanBytes {
		scan = scan[:maxScanBytes]
		f.Truncated = true
	}
	probe := scan
	if partial || len(scan) < len(raw) {
		// A cut can land in the middle of a character.
		for i := 0; i < utf8.UTFMax && len(probe) > 0 && !utf8.Valid(probe); i++ {
			probe = probe[:len(probe)-1]
		}
	}
	if bytes.IndexByte(scan, 0) >= 0 || !utf8.Valid(probe) {
		f.Binary = true
		f.head = append([]byte(nil), scan[:min(len(scan), 512)]...)
		return
	}
	f.text = string(probe)
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// parseFront reads the YAML front matter of SKILL.md.
func (s *Skill) parseFront() {
	front, _, ok := splitFront(s.Manifest())
	if !ok {
		s.FrontErr = "SKILL.md does not start with YAML front matter between --- lines"
		return
	}
	var m map[string]any
	if err := yaml.Unmarshal([]byte(front), &m); err != nil {
		s.FrontErr = "the front matter is not valid YAML: " + firstLine(err.Error())
		return
	}
	s.Front = m
	if name, ok := m["name"].(string); ok && strings.TrimSpace(name) != "" {
		s.Name = strings.TrimSpace(name)
	}
	if desc, ok := m["description"].(string); ok {
		s.Description = strings.TrimSpace(desc)
	}
}

// splitFront separates the front matter from the body. bodyStart is where
// the body starts in text.
func splitFront(text string) (front string, bodyStart int, ok bool) {
	off := 0
	if strings.HasPrefix(text, "\uFEFF") {
		off = len("\uFEFF")
	}
	line, next := lineAt(text, off)
	if strings.TrimRight(line, "\r \t") != "---" {
		return "", 0, false
	}
	start := next
	for p := next; p < len(text); {
		line, n := lineAt(text, p)
		if t := strings.TrimRight(line, "\r \t"); t == "---" || t == "..." {
			return text[start:p], n, true
		}
		p = n
	}
	return "", 0, false
}

// lineAt returns the line that starts at off, without its newline, and where
// the next one starts.
func lineAt(text string, off int) (string, int) {
	i := strings.IndexByte(text[off:], '\n')
	if i < 0 {
		return text[off:], len(text)
	}
	return text[off : off+i], off + i + 1
}

// frontString reads a front matter field that may be a string or a list.
func (s *Skill) frontString(key string) string {
	switch v := s.Front[key].(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, e := range v {
			parts = append(parts, fmt.Sprint(e))
		}
		return strings.Join(parts, ", ")
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
