// Package packs holds the policy packs that ship with agentgate: named,
// reviewed rule sets for the servers people actually run — shells, git,
// GitHub, databases, filesystems — that a policy switches on by name.
//
//	policy:
//	  packs: [baseline, secrets, lethal-trifecta]
//
// Each pack is a YAML file in this directory, embedded into the binary. A new
// pack is a new file here plus a golden test; see CONTRIBUTING.md.
package packs

import (
	"embed"
	"io/fs"
	"sort"
	"strings"
)

//go:embed *.yaml
var files embed.FS

// Get returns the source of a built-in pack.
func Get(name string) ([]byte, bool) {
	b, err := files.ReadFile(name + ".yaml")
	if err != nil {
		return nil, false
	}
	return b, true
}

// Names lists the built-in packs, sorted.
func Names() []string {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			out = append(out, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}
	sort.Strings(out)
	return out
}
