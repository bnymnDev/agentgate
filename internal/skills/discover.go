package skills

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ProjectRoots are where agents look for a project's skills, relative to the
// project directory: Claude Code in .claude/skills, Codex and the other
// agents that follow the Agent Skills layout in .agents/skills, and older
// Codex releases in .codex/skills.
var ProjectRoots = []string{".claude/skills", ".agents/skills", ".codex/skills"}

// UserRoots are where agents look for a user's own skills, relative to the
// home directory.
var UserRoots = []string{".claude/skills", ".agents/skills", ".codex/skills"}

// pluginRoot is where Claude Code keeps installed plugins; each plugin may
// bring a skills directory of its own.
const pluginRoot = ".claude/plugins"

// pluginDepth bounds the search for plugin skills directories below
// pluginRoot (marketplace, plugin, version, ...).
const pluginDepth = 6

// Options says where to look for skills.
type Options struct {
	// Dir is the project directory. Skill keys are relative to it.
	Dir string
	// Paths are more directories to look in, relative to Dir or absolute,
	// and may be globs. A path may name a skills directory or a single
	// skill.
	Paths []string
	// User also looks in the home directory, plugins included.
	User bool
	// PathsOnly looks in Paths alone, not in the project's skill
	// directories.
	PathsOnly bool
	// Home overrides the home directory, for tests.
	Home string
}

// Root is one directory skills are looked for in.
type Root struct {
	Path string
	// Scope is project, user, plugin or path.
	Scope string
}

func (o Options) home() string {
	if o.Home != "" {
		return o.Home
	}
	h, _ := os.UserHomeDir()
	return h
}

// Roots lists the directories to look in, whether they exist or not.
func (o Options) Roots() ([]Root, error) {
	dir, err := filepath.Abs(o.Dir)
	if err != nil {
		return nil, err
	}
	var out []Root
	if !o.PathsOnly {
		for _, r := range ProjectRoots {
			out = append(out, Root{filepath.Join(dir, filepath.FromSlash(r)), "project"})
		}
	}
	for _, p := range o.Paths {
		p = expandHome(p, o.home())
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		matches, err := filepath.Glob(p)
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			matches = []string{p}
		}
		for _, m := range matches {
			out = append(out, Root{m, "path"})
		}
	}
	if o.User {
		home := o.home()
		if home == "" {
			return nil, errors.New("no home directory to look for user skills in")
		}
		for _, r := range UserRoots {
			out = append(out, Root{filepath.Join(home, filepath.FromSlash(r)), "user"})
		}
		out = append(out, pluginSkillDirs(filepath.Join(home, filepath.FromSlash(pluginRoot)))...)
	}
	return out, nil
}

// pluginSkillDirs finds every directory called skills below the plugin root.
func pluginSkillDirs(root string) []Root {
	var out []Root
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		depth := len(strings.Split(rel, string(filepath.Separator)))
		if d.Name() == "skills" && path != root {
			out = append(out, Root{path, "plugin"})
			return filepath.SkipDir
		}
		if depth > pluginDepth || d.Name() == ".git" || d.Name() == "node_modules" {
			return filepath.SkipDir
		}
		return nil
	})
	return out
}

func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(home, p[2:])
	}
	return p
}

// Discover finds and loads every skill. A directory without a SKILL.md is
// not a skill and is passed over; a root that does not exist is fine.
func Discover(o Options) ([]*Skill, error) {
	roots, err := o.Roots()
	if err != nil {
		return nil, err
	}
	dir, _ := filepath.Abs(o.Dir)
	seen := map[string]bool{}
	var out []*Skill
	add := func(path string) error {
		key := keyFor(path, dir, o.home())
		if seen[key] {
			return nil
		}
		seen[key] = true
		s, err := Load(path, key)
		if err != nil {
			return err
		}
		out = append(out, s)
		return nil
	}
	for _, r := range roots {
		if isSkillDir(r.Path) {
			if err := add(r.Path); err != nil {
				return nil, err
			}
			continue
		}
		entries, err := os.ReadDir(r.Path)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) && r.Scope == "plugin" {
			continue
		}
		if err != nil {
			// A root that is a file, not a directory, holds no skills.
			if fi, serr := os.Stat(r.Path); serr == nil && !fi.IsDir() {
				continue
			}
			return nil, err
		}
		for _, e := range entries {
			path := filepath.Join(r.Path, e.Name())
			if !isSkillDir(path) {
				continue
			}
			if err := add(path); err != nil {
				return nil, err
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// isSkillDir reports whether path is a directory, or a link to one, with a
// SKILL.md in it.
func isSkillDir(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || !fi.IsDir() {
		return false
	}
	m, err := os.Lstat(filepath.Join(path, ManifestName))
	return err == nil && m.Mode().IsRegular()
}

// keyFor names a skill directory the same way on every machine: relative to
// the project, or under ~ for one in the home directory.
func keyFor(path, dir, home string) string {
	if rel, ok := under(path, dir); ok {
		return rel
	}
	if home != "" {
		if rel, ok := under(path, home); ok {
			return "~/" + rel
		}
	}
	return filepath.ToSlash(path)
}

func under(path, base string) (string, bool) {
	rel, err := filepath.Rel(base, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}
