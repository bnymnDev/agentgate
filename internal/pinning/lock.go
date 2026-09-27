// Package pinning keeps MCP servers from changing their tools behind the
// user's back.
//
// A tool's definition — its description above all — is read by the model as
// instructions. A server that was harmless when it was installed can start
// sending a different description later (a "rug pull"), and one that ships a
// poisoned description from the start can hide instructions in it that the
// user never sees. This package pins every tool definition in a lockfile the
// first time it is seen, reports any later change as drift, and scans
// definitions for the tricks poisoned ones use.
package pinning

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/bnymnDev/agentgate/internal/audit"
)

// Definition is the part of a tool that is pinned: everything the model reads
// and everything that decides how the tool is called. _meta and icons are
// left out; they are not shown to the model.
type Definition struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
}

// DefinitionFromJSON extracts a Definition from a tool as it travels on the
// wire.
func DefinitionFromJSON(raw []byte) (Definition, error) {
	var d Definition
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, err
	}
	d.canonicalize()
	return d, nil
}

// compact stores JSON in its canonical form, so that the lockfile does not
// change when a server merely reorders keys.
func compact(raw json.RawMessage) json.RawMessage {
	c := audit.Canonical(raw)
	if len(c) == 0 || string(c) == "null" || string(c) == "{}" {
		return nil
	}
	return c
}

// Hash identifies a definition's content.
func (d Definition) Hash() string {
	b, _ := json.Marshal(d)
	sum := sha256.Sum256(audit.Canonical(b))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Lockfile is the record of every tool definition a human has trusted,
// grouped by upstream.
type Lockfile struct {
	Version   int                  `json:"version"`
	Upstreams map[string]*Upstream `json:"upstreams"`

	path string
}

// Upstream is the pinned tools of one upstream server.
type Upstream struct {
	PinnedAt time.Time       `json:"pinned_at"`
	Tools    map[string]*Pin `json:"tools"`
}

// Pin is one tool as it was trusted.
type Pin struct {
	Hash       string     `json:"hash"`
	PinnedAt   time.Time  `json:"pinned_at"`
	Definition Definition `json:"definition"`
	// Accepted lists the scan findings a human looked at and accepted for
	// this exact definition.
	Accepted []string `json:"accepted_findings,omitempty"`
	// Drift is set when the server started offering something else under
	// this name. It stays until a human pins the tool again.
	Drift *Drift `json:"drift,omitempty"`
}

// Drift is a definition that differs from the pinned one.
type Drift struct {
	Hash       string     `json:"hash"`
	SeenAt     time.Time  `json:"seen_at"`
	Definition Definition `json:"definition"`
}

// Load reads a lockfile. A missing file is an empty lockfile.
func Load(path string) (*Lockfile, error) {
	l := &Lockfile{Version: 1, Upstreams: map[string]*Upstream{}, path: path}
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
	if l.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported lockfile version %d", path, l.Version)
	}
	if l.Upstreams == nil {
		l.Upstreams = map[string]*Upstream{}
	}
	for _, u := range l.Upstreams {
		if u.Tools == nil {
			u.Tools = map[string]*Pin{}
		}
		// The file is indented for reading; in memory a definition is in
		// canonical form, so it compares equal to one just offered.
		for _, pin := range u.Tools {
			pin.Definition.canonicalize()
			if pin.Drift != nil {
				pin.Drift.Definition.canonicalize()
			}
		}
	}
	return l, nil
}

func (d *Definition) canonicalize() {
	d.InputSchema = compact(d.InputSchema)
	d.OutputSchema = compact(d.OutputSchema)
	d.Annotations = compact(d.Annotations)
}

// Path is where the lockfile lives.
func (l *Lockfile) Path() string { return l.path }

// Save writes the lockfile atomically: a reader never sees half of it.
func (l *Lockfile) Save() error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(l); err != nil {
		return err
	}
	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".agentgate-lock-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), l.path)
}

// Known reports whether an upstream has been pinned before.
func (l *Lockfile) Known(upstream string) bool {
	_, ok := l.Upstreams[upstream]
	return ok
}

// Pinned returns the pin of one tool, if there is one.
func (l *Lockfile) Pinned(upstream, tool string) *Pin {
	u, ok := l.Upstreams[upstream]
	if !ok {
		return nil
	}
	return u.Tools[tool]
}

// Pin trusts a definition: it becomes the pinned one, any drift is cleared,
// and the given findings are recorded as accepted.
func (l *Lockfile) Pin(upstream string, d Definition, accepted []string, now time.Time) {
	u, ok := l.Upstreams[upstream]
	if !ok {
		u = &Upstream{PinnedAt: now, Tools: map[string]*Pin{}}
		l.Upstreams[upstream] = u
	}
	sort.Strings(accepted)
	u.Tools[d.Name] = &Pin{Hash: d.Hash(), PinnedAt: now, Definition: d, Accepted: accepted}
}

// Unpin forgets a tool, or a whole upstream when tool is empty.
func (l *Lockfile) Unpin(upstream, tool string) {
	if tool == "" {
		delete(l.Upstreams, upstream)
		return
	}
	if u, ok := l.Upstreams[upstream]; ok {
		delete(u.Tools, tool)
	}
}

// Status is how a tool on offer relates to the lockfile.
type Status string

const (
	// StatusPinned means the tool is exactly what was trusted.
	StatusPinned Status = "pinned"
	// StatusNew means the upstream is pinned, but this tool is not.
	StatusNew Status = "new"
	// StatusChanged means the definition differs from the pinned one.
	StatusChanged Status = "changed"
	// StatusRemoved means the tool is pinned but no longer offered.
	StatusRemoved Status = "removed"
	// StatusUnpinned means nothing about this upstream is pinned yet.
	StatusUnpinned Status = "unpinned"
)

// Report is the verdict on one tool.
type Report struct {
	Upstream string     `json:"upstream"`
	Tool     string     `json:"tool"`
	Status   Status     `json:"status"`
	Current  Definition `json:"current"`
	// Pinned is the trusted definition, for changed and removed tools.
	Pinned *Definition `json:"pinned,omitempty"`
	// Findings are what the scan found in the current definition, minus the
	// ones a human already accepted for it.
	Findings []Finding `json:"findings,omitempty"`
	// Accepted are the findings a human accepted for this definition.
	Accepted []Finding `json:"accepted,omitempty"`
}

// Check compares the tools an upstream offers with what is pinned, and scans
// each current definition. others are the tools of every other upstream,
// which a definition should have no reason to talk about.
func (l *Lockfile) Check(upstream string, defs []Definition, others []OtherTool) []Report {
	known := l.Known(upstream)
	offered := map[string]bool{}
	out := make([]Report, 0, len(defs))
	for _, d := range defs {
		offered[d.Name] = true
		r := Report{Upstream: upstream, Tool: d.Name, Current: d}
		pin := l.Pinned(upstream, d.Name)
		switch {
		case !known:
			r.Status = StatusUnpinned
		case pin == nil:
			r.Status = StatusNew
		case pin.Hash != d.Hash():
			r.Status = StatusChanged
			pinned := pin.Definition
			r.Pinned = &pinned
		default:
			r.Status = StatusPinned
		}
		var accepted []string
		if pin != nil && r.Status == StatusPinned {
			accepted = pin.Accepted
		}
		for _, f := range Scan(d, others) {
			if contains(accepted, f.Key()) {
				r.Accepted = append(r.Accepted, f)
			} else {
				r.Findings = append(r.Findings, f)
			}
		}
		out = append(out, r)
	}
	if u, ok := l.Upstreams[upstream]; ok {
		names := make([]string, 0, len(u.Tools))
		for name := range u.Tools {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if !offered[name] {
				pinned := u.Tools[name].Definition
				out = append(out, Report{Upstream: upstream, Tool: name, Status: StatusRemoved, Pinned: &pinned})
			}
		}
	}
	return out
}

// Trust pins the current definition of a report and accepts its findings.
func (l *Lockfile) Trust(r Report, now time.Time) {
	if r.Status == StatusRemoved {
		l.Unpin(r.Upstream, r.Tool)
		return
	}
	keys := make([]string, 0, len(r.Findings)+len(r.Accepted))
	for _, f := range append(append([]Finding{}, r.Findings...), r.Accepted...) {
		keys = append(keys, f.Key())
	}
	l.Pin(r.Upstream, r.Current, dedupe(keys), now)
}

// NoteDrift records that a tool changed, once per new definition. It reports
// whether this drift is news.
func (l *Lockfile) NoteDrift(r Report, now time.Time) bool {
	pin := l.Pinned(r.Upstream, r.Tool)
	if pin == nil || r.Status != StatusChanged {
		return false
	}
	h := r.Current.Hash()
	if pin.Drift != nil && pin.Drift.Hash == h {
		return false
	}
	pin.Drift = &Drift{Hash: h, SeenAt: now, Definition: r.Current}
	return true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func dedupe(list []string) []string {
	sort.Strings(list)
	out := list[:0]
	for i, v := range list {
		if i == 0 || v != list[i-1] {
			out = append(out, v)
		}
	}
	return out
}
