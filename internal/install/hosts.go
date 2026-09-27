// Package install puts agentgate between an MCP host and the servers it is
// configured with, and takes it out again.
//
// Every host keeps its MCP servers in a JSON file. install reads the servers
// from it, writes an agentgate config with those servers as upstreams, and
// replaces them in the host's file with a single entry that runs agentgate.
// The original entries are kept in a manifest, so uninstall can put the file
// back exactly as it was — the rest of the host's settings are never touched.
package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Host is an MCP host and where it keeps its servers.
type Host struct {
	// Name is how the host is called on the command line.
	Name string `json:"name"`
	// Title is how it is called in prose.
	Title string `json:"title"`
	// Path is its config file.
	Path string `json:"path"`
	// Key is the member of the file that holds the servers.
	Key string `json:"key"`
	// TypedEntries is set for hosts whose entries carry "type": "stdio".
	TypedEntries bool `json:"typed_entries,omitempty"`
}

// Env is where to look: the user's home and config directories, and the
// project directory for hosts with a per-project file.
type Env struct {
	Home      string
	ConfigDir string
	Cwd       string
}

// DefaultEnv is the real environment.
func DefaultEnv() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, err
	}
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		cfgDir = filepath.Join(home, ".config")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return Env{}, err
	}
	return Env{Home: home, ConfigDir: cfgDir, Cwd: cwd}, nil
}

// Hosts lists every host agentgate knows how to install into, whether or not
// it is on this machine.
func Hosts(env Env) []Host {
	// os.UserConfigDir is ~/Library/Application Support on macOS, %AppData%
	// on Windows and the XDG config directory elsewhere, which is exactly
	// where Claude Desktop keeps its file on each.
	desktop := filepath.Join(env.ConfigDir, "Claude", "claude_desktop_config.json")
	return []Host{
		{Name: "claude-desktop", Title: "Claude Desktop", Path: desktop, Key: "mcpServers"},
		{Name: "claude-code", Title: "Claude Code (this project)", Path: filepath.Join(env.Cwd, ".mcp.json"), Key: "mcpServers"},
		{Name: "cursor", Title: "Cursor", Path: filepath.Join(env.Home, ".cursor", "mcp.json"), Key: "mcpServers"},
		{Name: "cursor-project", Title: "Cursor (this project)", Path: filepath.Join(env.Cwd, ".cursor", "mcp.json"), Key: "mcpServers"},
		{Name: "windsurf", Title: "Windsurf", Path: filepath.Join(env.Home, ".codeium", "windsurf", "mcp_config.json"), Key: "mcpServers"},
		{Name: "vscode", Title: "VS Code (this project)", Path: filepath.Join(env.Cwd, ".vscode", "mcp.json"), Key: "servers", TypedEntries: true},
		{Name: "gemini-cli", Title: "Gemini CLI", Path: filepath.Join(env.Home, ".gemini", "settings.json"), Key: "mcpServers"},
	}
}

// Server is one MCP server entry of a host's config.
type Server struct {
	Name     string
	Command  string
	Args     []string
	Env      map[string]string
	Cwd      string
	URL      string
	Headers  map[string]string
	Disabled bool
	// Raw is the entry exactly as the host's file had it.
	Raw json.RawMessage
}

// Stdio reports whether the server is a local process.
func (s Server) Stdio() bool { return s.Command != "" }

type entry struct {
	Type      string            `json:"type"`
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env"`
	Cwd       string            `json:"cwd"`
	URL       string            `json:"url"`
	HTTPURL   string            `json:"httpUrl"`
	ServerURL string            `json:"serverUrl"`
	Headers   map[string]string `json:"headers"`
	Disabled  bool              `json:"disabled"`
}

// Servers reads the servers of a host, in the order the file lists them. A
// missing file has none.
func Servers(h Host) ([]Server, error) {
	doc, err := readDoc(h.Path)
	if err != nil || doc == nil {
		return nil, err
	}
	raw, ok := doc.get(h.Key)
	if !ok || len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil, nil
	}
	servers, err := readObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %s is not an object: %w", h.Path, h.Key, err)
	}
	var out []Server
	for _, m := range servers.members {
		var e entry
		if err := json.Unmarshal(m.value, &e); err != nil {
			return nil, fmt.Errorf("%s: server %q: %w", h.Path, m.key, err)
		}
		s := Server{Name: m.key, Command: e.Command, Args: e.Args, Env: e.Env, Cwd: e.Cwd,
			Headers: e.Headers, Disabled: e.Disabled, Raw: m.value}
		for _, u := range []string{e.URL, e.HTTPURL, e.ServerURL} {
			if u != "" {
				s.URL = u
				break
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// document is a JSON object with its members in file order, each value kept
// as it was written, so a rewrite changes one member and nothing else.
type document struct {
	members []member
}

type member struct {
	key   string
	value json.RawMessage
}

func (d *document) get(key string) (json.RawMessage, bool) {
	for _, m := range d.members {
		if m.key == key {
			return m.value, true
		}
	}
	return nil, false
}

func (d *document) set(key string, value json.RawMessage) {
	for i, m := range d.members {
		if m.key == key {
			d.members[i].value = value
			return
		}
	}
	d.members = append(d.members, member{key, value})
}

func readDoc(path string) (*document, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return &document{}, nil
	}
	doc, err := readObject(stripJSONC(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}

// readObject splits a JSON object into its members without reordering them.
func readObject(raw []byte) (*document, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("expected a JSON object")
	}
	doc := &document{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("expected a member name")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		doc.members = append(doc.members, member{key, value})
	}
	return doc, nil
}

// encode writes the document with two-space indentation, which is what every
// host writes itself. There is no final newline; fileBytes adds it.
func (d *document) encode() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("{\n")
	for i, m := range d.members {
		key, _ := json.Marshal(m.key)
		var val bytes.Buffer
		if err := json.Indent(&val, m.value, "  ", "  "); err != nil {
			return nil, fmt.Errorf("member %s: %w", m.key, err)
		}
		fmt.Fprintf(&buf, "  %s: %s", key, val.Bytes())
		if i < len(d.members)-1 {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
	}
	buf.WriteString("}")
	return buf.Bytes(), nil
}

// fileBytes is the document as a file: encoded, with a final newline.
func (d *document) fileBytes() ([]byte, error) {
	out, err := d.encode()
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// stripJSONC removes // and /* */ comments and trailing commas, which VS
// Code's files may have, so the standard decoder can read them. Strings are
// left alone.
func stripJSONC(raw []byte) []byte {
	var out bytes.Buffer
	inString, escaped := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inString {
			out.WriteByte(c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(raw) && raw[i+1] == '/':
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(raw) && raw[i+1] == '*':
			i += 2
			for i+1 < len(raw) && (raw[i] != '*' || raw[i+1] != '/') {
				i++
			}
			i++
		case c == ',':
			// A comma followed only by whitespace and a closing bracket is a
			// trailing comma.
			j := i + 1
			for j < len(raw) && strings.ContainsRune(" \t\r\n", rune(raw[j])) {
				j++
			}
			if j < len(raw) && (raw[j] == '}' || raw[j] == ']') {
				continue
			}
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}

// writeFileAtomic replaces a file without a moment where it is half written,
// keeping its permissions.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agentgate-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), perm); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
