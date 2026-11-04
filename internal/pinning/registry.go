package pinning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// A registry is a directory, or a web server, of what MCP servers offer,
// one file per server and version, kept by people who looked at the
// definitions and trusted them. Pinning on first use trusts whatever a
// server sends the first time; comparing against a registry first means the
// first time is checked too: what this machine is offered is what everyone
// else was offered. A registry is plain files, so a git repository is one,
// and a pull request to it is how a definition gets reviewed.

// Entry is one server version as a registry keeps it. It names no local
// upstream and carries no times, so two people who trust the same server
// write the same bytes.
type Entry struct {
	Server      string               `json:"server"`
	Version     string               `json:"version"`
	Definitions map[string]EntryItem `json:"definitions"`
}

// EntryItem is one definition, keyed by its Ref in Entry.Definitions.
type EntryItem struct {
	Hash       string     `json:"hash"`
	Definition Definition `json:"definition"`
}

// NewEntry builds an entry from definitions.
func NewEntry(server, version string, defs []Definition) Entry {
	e := Entry{Server: server, Version: version, Definitions: map[string]EntryItem{}}
	for _, d := range defs {
		d.canonicalize()
		e.Definitions[d.Ref()] = EntryItem{Hash: d.Hash(), Definition: d}
	}
	return e
}

// Marshal is the entry as a registry file: indented, keys sorted.
func (e Entry) Marshal() []byte {
	b, _ := json.MarshalIndent(e, "", "  ")
	return append(b, '\n')
}

var unsafePathChar = regexp.MustCompile(`[^A-Za-z0-9._@+-]`)

// EntryPath is where an entry lives in a registry: <server>/<version>.json,
// with a scoped name like @scope/name kept as two directories and anything
// else that is not safe in a path replaced.
func EntryPath(server, version string) (string, error) {
	if server == "" {
		return "", errors.New("the server did not say its name, so it has no place in a registry")
	}
	if version == "" {
		version = "unversioned"
	}
	var parts []string
	for _, p := range strings.Split(server, "/") {
		p = unsafePathChar.ReplaceAllString(p, "_")
		if p == "" || p == "." || p == ".." {
			p = "_"
		}
		parts = append(parts, p)
	}
	v := unsafePathChar.ReplaceAllString(version, "_")
	if v == "." || v == ".." {
		v = "_"
	}
	return path.Join(append(parts, v+".json")...), nil
}

// Publish writes an entry into a registry directory and returns the file.
func Publish(dir string, e Entry) (string, error) {
	rel, err := EntryPath(e.Server, e.Version)
	if err != nil {
		return "", err
	}
	file := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(file), 0o750); err != nil {
		return "", err
	}
	return file, os.WriteFile(file, e.Marshal(), 0o644) //nolint:gosec // a registry is meant to be read
}

// ErrNotInRegistry is returned when a registry has no entry for a server
// version.
var ErrNotInRegistry = errors.New("not in the registry")

// LoadEntry finds the entry for a server version. source is a registry
// directory or base URL, or a single entry file or URL ending in .json,
// which is used whatever server it names.
func LoadEntry(ctx context.Context, source, server, version string, client *http.Client) (*Entry, error) {
	where := source
	if !strings.HasSuffix(source, ".json") {
		rel, err := EntryPath(server, version)
		if err != nil {
			return nil, err
		}
		if isURL(source) {
			where = strings.TrimRight(source, "/") + "/" + rel
		} else {
			where = filepath.Join(source, filepath.FromSlash(rel))
		}
	}
	var raw []byte
	var err error
	if isURL(where) {
		raw, err = fetch(ctx, where, client)
	} else {
		raw, err = os.ReadFile(where)
		if errors.Is(err, os.ErrNotExist) {
			err = ErrNotInRegistry
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", server, version, err)
	}
	var e Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("%s: not a registry entry: %w", where, err)
	}
	for ref, item := range e.Definitions {
		d := item.Definition
		d.canonicalize()
		if d.Ref() != ref || d.Hash() != item.Hash {
			return nil, fmt.Errorf("%s: the entry for %s does not hash to what it says; it was edited by hand", where, ref)
		}
		item.Definition = d
		e.Definitions[ref] = item
	}
	return &e, nil
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}

func fetch(ctx context.Context, url string, client *http.Client) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotInRegistry
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// Agreement is how one definition compares with a registry.
type Agreement string

// The ways a definition and a registry can relate.
const (
	AgreeSame      Agreement = "same"
	AgreeDiffers   Agreement = "differs"
	AgreeOnlyHere  Agreement = "only-here"
	AgreeOnlyThere Agreement = "only-in-registry"
)

// Comparison is one definition against the registry.
type Comparison struct {
	Ref   string      `json:"ref"`
	Agree Agreement   `json:"agree"`
	Here  *Definition `json:"here,omitempty"`
	There *Definition `json:"there,omitempty"`
}

// Compare lines up what a server offers here with a registry entry.
func Compare(here []Definition, there *Entry) []Comparison {
	seen := map[string]bool{}
	var out []Comparison
	for _, d := range here {
		d.canonicalize()
		ref := d.Ref()
		seen[ref] = true
		c := Comparison{Ref: ref, Here: &d}
		item, ok := there.Definitions[ref]
		switch {
		case !ok:
			c.Agree = AgreeOnlyHere
		case item.Hash == d.Hash():
			c.Agree = AgreeSame
		default:
			c.Agree = AgreeDiffers
			def := item.Definition
			c.There = &def
		}
		out = append(out, c)
	}
	for ref, item := range there.Definitions {
		if !seen[ref] {
			def := item.Definition
			out = append(out, Comparison{Ref: ref, Agree: AgreeOnlyThere, There: &def})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}
