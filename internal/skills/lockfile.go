package skills

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// LockfileVersion is the version of the lockfile format this package writes.
const LockfileVersion = 1

// DefaultLockfile is the lockfile's name in the project directory.
const DefaultLockfile = "skills.lock"

// maxInstructions caps how much of SKILL.md the lockfile keeps for the prose
// diff. The Merkle root covers all of it either way.
const maxInstructions = 256 << 10

// Lockfile is the record of every skill a human has approved.
type Lockfile struct {
	Version int `json:"version"`
	// Paths and User are where the skills were looked for, so that a check
	// on another machine looks in the same places.
	Paths  []string          `json:"paths,omitempty"`
	User   bool              `json:"user,omitempty"`
	Skills map[string]*Entry `json:"skills"`

	path string
}

// Entry is one skill as it was approved.
type Entry struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Root is the Merkle root over every file.
	Root string `json:"root"`
	// Files maps each file to the hash of its content, "-> target" for a
	// symlink, or "special" for a pipe or device.
	Files map[string]string `json:"files"`
	// Label is the capabilities the skill had when it was approved.
	Label []string `json:"label"`
	Hosts []string `json:"hosts,omitempty"`
	// Accepted are the findings a human looked at and approved.
	Accepted []string `json:"accepted_findings,omitempty"`
	// Instructions is SKILL.md as it was approved, for the prose diff.
	Instructions string    `json:"instructions"`
	ApprovedAt   time.Time `json:"approved_at"`
	ApprovedBy   string    `json:"approved_by,omitempty"`
}

// LoadLockfile reads a lockfile. A missing file is an empty lockfile; Exists
// tells the two apart.
func LoadLockfile(path string) (*Lockfile, error) {
	l := &Lockfile{Version: LockfileVersion, Skills: map[string]*Entry{}, path: path}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, l); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if l.Version != LockfileVersion {
		return nil, fmt.Errorf("%s: unsupported skills lockfile version %d", path, l.Version)
	}
	if l.Skills == nil {
		l.Skills = map[string]*Entry{}
	}
	for key, e := range l.Skills {
		if e == nil {
			return nil, fmt.Errorf("%s: skill %q has no entry", path, key)
		}
	}
	return l, nil
}

// Path is where the lockfile lives.
func (l *Lockfile) Path() string { return l.path }

// Exists reports whether the lockfile is on disk.
func (l *Lockfile) Exists() bool {
	_, err := os.Stat(l.path)
	return err == nil
}

// Save writes the lockfile atomically. Characters that render as nothing
// are written as \u escapes, so a hidden instruction stays visible in the
// lockfile's own diff.
func (l *Lockfile) Save() error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(l); err != nil {
		return err
	}
	out := escapeInvisible(buf.Bytes())
	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".skills-lock-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), l.path)
}

// escapeInvisible rewrites invisible and control characters in encoded JSON
// as \u escapes. It only ever touches the inside of strings: outside them,
// JSON has nothing but ASCII.
func escapeInvisible(b []byte) []byte {
	var out bytes.Buffer
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if invisibleRune(r) {
			if r > 0xFFFF {
				r1, r2 := utf16Pair(r)
				fmt.Fprintf(&out, `\u%04x\u%04x`, r1, r2)
			} else {
				fmt.Fprintf(&out, `\u%04x`, r)
			}
		} else {
			out.Write(b[:n])
		}
		b = b[n:]
	}
	return out.Bytes()
}

func invisibleRune(r rune) bool {
	return isTag(r) || isBidi(r) || isZeroWidth(r) || r == 0x200C || r == 0x200D ||
		(r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) ||
		(r >= 0x80 && r < 0xA0) || r == 0x7F || r == 0x2028 || r == 0x2029 ||
		(r > 0x7F && unicode.Is(unicode.Cf, r))
}

func utf16Pair(r rune) (rune, rune) {
	r -= 0x10000
	return 0xD800 + (r>>10)&0x3FF, 0xDC00 + r&0x3FF
}

// Status is how a skill on disk relates to the lockfile.
type Status string

const (
	// StatusLocked means the skill is exactly what was approved.
	StatusLocked Status = "locked"
	// StatusNew means the skill is not in the lockfile.
	StatusNew Status = "new"
	// StatusChanged means a file of the skill changed since it was approved.
	StatusChanged Status = "changed"
	// StatusRemoved means the skill is in the lockfile but gone from disk.
	StatusRemoved Status = "removed"
	// StatusRescanned means the files are unchanged, but this agentgate
	// sees capabilities or findings the lockfile does not record - after an
	// upgrade that brought new rules.
	StatusRescanned Status = "rescanned"
)

// FileChange is one file that differs from the lockfile.
type FileChange struct {
	Path string `json:"path"`
	// Change is added, removed or modified.
	Change string `json:"change"`
}

// Report is the verdict on one skill.
type Report struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Status Status `json:"status"`
	Root   string `json:"root,omitempty"`
	// LockedRoot is the approved root, when there is one.
	LockedRoot string `json:"locked_root,omitempty"`
	// Label is the skill's capabilities now.
	Label []string `json:"label"`
	// Gained and Lost compare the label with the approved one.
	Gained   []string `json:"gained,omitempty"`
	Lost     []string `json:"lost,omitempty"`
	NewHosts []string `json:"new_hosts,omitempty"`
	// Findings is everything the rules find in the skill now; Unaccepted
	// is the part of it that was not approved with the skill.
	Findings   []Finding    `json:"findings,omitempty"`
	Unaccepted []Finding    `json:"unaccepted,omitempty"`
	Files      []FileChange `json:"files,omitempty"`

	Skill    *Skill `json:"-"`
	Entry    *Entry `json:"-"`
	Labelled Label  `json:"-"`
}

// Clean reports whether the skill needs no one's attention.
func (r Report) Clean() bool { return r.Status == StatusLocked }

// Check compares the skills on disk with the lockfile.
func (l *Lockfile) Check(skills []*Skill) []Report {
	// Skills are independent of each other; scan them on every core.
	out := make([]Report, len(skills))
	present := map[string]bool{}
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	for i, s := range skills {
		present[s.Key] = true
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			out[i] = l.check(s)
		}()
	}
	wg.Wait()
	keys := make([]string, 0, len(l.Skills))
	for k := range l.Skills {
		if !present[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := l.Skills[k]
		r := Report{Key: k, Name: e.Name, Status: StatusRemoved, LockedRoot: e.Root, Label: []string{}, Lost: e.Label, Entry: e}
		for p := range e.Files {
			r.Files = append(r.Files, FileChange{p, "removed"})
		}
		sortChanges(r.Files)
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (l *Lockfile) check(s *Skill) Report {
	label := Derive(s)
	findings := Scan(s)
	r := Report{Key: s.Key, Name: s.Name, Root: s.Root, Label: label.Capabilities, Findings: findings, Skill: s, Labelled: label}
	e := l.Skills[s.Key]
	if e == nil {
		r.Status = StatusNew
		r.Gained = label.Capabilities
		r.NewHosts = label.Hosts
		r.Unaccepted = findings
		for _, f := range s.Files {
			r.Files = append(r.Files, FileChange{f.Path, "added"})
		}
		return r
	}
	r.Entry = e
	r.LockedRoot = e.Root
	r.Gained = minus(label.Capabilities, e.Label)
	r.Lost = minus(e.Label, label.Capabilities)
	r.NewHosts = minus(label.Hosts, e.Hosts)
	for _, f := range findings {
		if !contains(e.Accepted, f.Key()) {
			r.Unaccepted = append(r.Unaccepted, f)
		}
	}
	current := map[string]string{}
	for _, f := range s.Files {
		current[f.Path] = entryHash(f)
		switch old, ok := e.Files[f.Path]; {
		case !ok:
			r.Files = append(r.Files, FileChange{f.Path, "added"})
		case old != entryHash(f):
			r.Files = append(r.Files, FileChange{f.Path, "modified"})
		}
	}
	for p := range e.Files {
		if _, ok := current[p]; !ok {
			r.Files = append(r.Files, FileChange{p, "removed"})
		}
	}
	sortChanges(r.Files)
	switch {
	case e.Root != s.Root:
		r.Status = StatusChanged
	case len(r.Gained) > 0 || len(r.Unaccepted) > 0:
		r.Status = StatusRescanned
	default:
		r.Status = StatusLocked
	}
	return r
}

func entryHash(f File) string {
	switch f.Kind {
	case KindSymlink:
		return "-> " + f.Target
	case KindSpecial:
		return "special"
	case KindRepository:
		return "repository (not pinned)"
	}
	return f.Hash
}

// Approve records a skill as it is now; a removed skill is forgotten.
func (l *Lockfile) Approve(r Report, by string, now time.Time) {
	if r.Status == StatusRemoved || r.Skill == nil {
		delete(l.Skills, r.Key)
		return
	}
	s := r.Skill
	e := &Entry{Name: s.Name, Description: s.Description, Root: s.Root, Files: map[string]string{},
		Label: append([]string{}, r.Label...), Hosts: r.Labelled.Hosts, ApprovedAt: now.UTC().Truncate(time.Second), ApprovedBy: by}
	for _, f := range s.Files {
		e.Files[f.Path] = entryHash(f)
	}
	keys := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		keys = append(keys, f.Key())
	}
	e.Accepted = uniqueSorted(keys)
	e.Instructions = s.Manifest()
	if len(e.Instructions) > maxInstructions {
		cut := maxInstructions
		for cut > 0 && !utf8.RuneStart(e.Instructions[cut]) {
			cut--
		}
		e.Instructions = e.Instructions[:cut]
	}
	l.Skills[r.Key] = e
}

func minus(a, b []string) []string {
	var out []string
	for _, v := range a {
		if !contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func uniqueSorted(list []string) []string {
	sort.Strings(list)
	out := list[:0]
	for i, v := range list {
		if i == 0 || v != list[i-1] {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sortChanges(c []FileChange) {
	sort.Slice(c, func(i, j int) bool { return c[i].Path < c[j].Path })
}

// Match reports whether a name given on the command line means this skill:
// its key, its name, or the last element of its key.
func (r Report) Match(name string) bool {
	name = strings.TrimSuffix(filepathToSlash(name), "/")
	if name == r.Key || name == r.Name {
		return true
	}
	if i := strings.LastIndexByte(r.Key, '/'); i >= 0 && r.Key[i+1:] == name {
		return true
	}
	return false
}

func filepathToSlash(s string) string { return strings.ReplaceAll(s, `\`, "/") }
