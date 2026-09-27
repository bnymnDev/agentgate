package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// EntryName is the name of the one server entry agentgate leaves in a host's
// config.
const EntryName = "agentgate"

// Manifest is ~/.agentgate/installed.json: what init changed, so uninstall
// can change it back.
type Manifest struct {
	Hosts map[string]*Installed `json:"hosts"`
	path  string
}

// Installed is one host agentgate was put in front of.
type Installed struct {
	Host Host `json:"host"`
	// Servers is the host's servers member as it was, byte for byte.
	Servers json.RawMessage `json:"servers"`
	// Config is the agentgate config written for it.
	Config string `json:"config"`
	// Backup is a copy of the whole file as it was before.
	Backup      string    `json:"backup"`
	InstalledAt time.Time `json:"installed_at"`
}

// LoadManifest reads the manifest in dir; a missing one is empty.
func LoadManifest(dir string) (*Manifest, error) {
	m := &Manifest{Hosts: map[string]*Installed{}, path: filepath.Join(dir, "installed.json")}
	raw, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, m); err != nil {
		return nil, fmt.Errorf("%s: %w", m.path, err)
	}
	if m.Hosts == nil {
		m.Hosts = map[string]*Installed{}
	}
	return m, nil
}

func (m *Manifest) save() error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(m.path, append(raw, '\n'), 0o600)
}

// Status is where a host stands.
type Status string

const (
	// StatusReady means the host has servers agentgate can be put in front of.
	StatusReady Status = "ready"
	// StatusInstalled means agentgate is already in front of it.
	StatusInstalled Status = "installed"
	// StatusEmpty means the host's config exists but lists no servers.
	StatusEmpty Status = "no servers"
	// StatusAbsent means there is no config file for the host.
	StatusAbsent Status = "not found"
)

// Candidate is a host as init sees it.
type Candidate struct {
	Host    Host
	Status  Status
	Servers []Server
	// Wrapped are the servers that will go behind agentgate; disabled ones
	// stay where they are.
	Wrapped []Server
}

// Scan looks at every known host.
func Scan(env Env, manifest *Manifest) ([]Candidate, error) {
	var out []Candidate
	for _, h := range Hosts(env) {
		c := Candidate{Host: h}
		if _, err := os.Stat(h.Path); err != nil {
			c.Status = StatusAbsent
			out = append(out, c)
			continue
		}
		servers, err := Servers(h)
		if err != nil {
			return nil, err
		}
		c.Servers = servers
		for _, s := range servers {
			if !s.Disabled && s.Name != EntryName {
				c.Wrapped = append(c.Wrapped, s)
			}
		}
		switch {
		case manifest.Hosts[h.Name] != nil || hasEntry(servers):
			c.Status = StatusInstalled
		case len(c.Wrapped) == 0:
			c.Status = StatusEmpty
		default:
			c.Status = StatusReady
		}
		out = append(out, c)
	}
	return out, nil
}

func hasEntry(servers []Server) bool {
	for _, s := range servers {
		if s.Name == EntryName {
			return true
		}
	}
	return false
}

// Options control an install.
type Options struct {
	// Dir is agentgate's home, ~/.agentgate.
	Dir string
	// Binary is the absolute path of the agentgate executable the host
	// will run.
	Binary string
	// Now stamps the generated files.
	Now time.Time
}

// Apply puts agentgate in front of one host: it writes the agentgate config,
// rewrites the host's servers member, and records both in the manifest.
func Apply(c Candidate, manifest *Manifest, opts Options) (*Installed, error) {
	if c.Status != StatusReady {
		return nil, fmt.Errorf("%s: %s", c.Host.Name, c.Status)
	}
	doc, err := readDoc(c.Host.Path)
	if err != nil {
		return nil, err
	}
	original, _ := doc.get(c.Host.Key)
	stamp := opts.Now.UTC().Format("20060102-150405")

	backup := filepath.Join(opts.Dir, "backup", fmt.Sprintf("%s-%s.json", c.Host.Name, stamp))
	raw, err := os.ReadFile(c.Host.Path)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(backup, raw, 0o600); err != nil {
		return nil, err
	}

	cfgPath := filepath.Join(opts.Dir, c.Host.Name+".yaml")
	if _, err := os.Stat(cfgPath); err == nil {
		// An earlier install left a config behind, perhaps edited since:
		// keep it and write the new one next to it.
		cfgPath = filepath.Join(opts.Dir, fmt.Sprintf("%s-%s.yaml", c.Host.Name, stamp))
	}
	if err := writeFileAtomic(cfgPath, []byte(GenerateConfig(c, opts)), 0o600); err != nil {
		return nil, err
	}

	servers, err := readObject(original)
	if err != nil {
		return nil, err
	}
	kept := &document{}
	wrapped := map[string]bool{}
	for _, s := range c.Wrapped {
		wrapped[s.Name] = true
	}
	for _, m := range servers.members {
		if !wrapped[m.key] {
			kept.members = append(kept.members, m)
		}
	}
	ours := struct {
		Type    string   `json:"type,omitempty"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}{Command: opts.Binary, Args: []string{"run", "--config", cfgPath}}
	if c.Host.TypedEntries {
		ours.Type = "stdio"
	}
	ourRaw, err := json.Marshal(ours)
	if err != nil {
		return nil, err
	}
	kept.members = append([]member{{EntryName, ourRaw}}, kept.members...)
	newServers, err := kept.encode()
	if err != nil {
		return nil, err
	}
	doc.set(c.Host.Key, newServers)
	out, err := doc.fileBytes()
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(c.Host.Path, out, 0o644); err != nil {
		return nil, err
	}

	inst := &Installed{Host: c.Host, Servers: original, Config: cfgPath, Backup: backup, InstalledAt: opts.Now}
	manifest.Hosts[c.Host.Name] = inst
	if err := manifest.save(); err != nil {
		return nil, err
	}
	return inst, nil
}

// Uninstall puts a host's servers back the way they were before init. Every
// other part of the host's file keeps whatever it has now.
func Uninstall(name string, manifest *Manifest) (*Installed, error) {
	inst := manifest.Hosts[name]
	if inst == nil {
		return nil, fmt.Errorf("agentgate was not installed into %s by agentgate init", name)
	}
	doc, err := readDoc(inst.Host.Path)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		doc = &document{}
	}
	restored := inst.Servers
	// Servers added to the host since the install are kept.
	if current, ok := doc.get(inst.Host.Key); ok {
		if now, err := readObject(current); err == nil {
			if before, err := readObject(inst.Servers); err == nil {
				for _, m := range now.members {
					if _, had := before.get(m.key); !had && m.key != EntryName {
						before.members = append(before.members, m)
					}
				}
				if merged, err := before.encode(); err == nil {
					restored = merged
				}
			}
		}
	}
	doc.set(inst.Host.Key, restored)
	out, err := doc.fileBytes()
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(inst.Host.Path, out, 0o644); err != nil {
		return nil, err
	}
	delete(manifest.Hosts, name)
	return inst, manifest.save()
}

var nameRe = regexp.MustCompile(`[^a-z0-9_-]+`)

// upstreamName turns a server name into a valid, readable upstream name.
func upstreamName(s string, taken map[string]bool) string {
	name := strings.Trim(nameRe.ReplaceAllString(strings.ToLower(s), "-"), "-_")
	name = strings.ReplaceAll(name, "__", "_")
	if name == "" {
		name = "server"
	}
	base := name
	for i := 2; taken[name]; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	taken[name] = true
	return name
}

// GenerateConfig writes the agentgate config for a host: its servers as
// upstreams, in shadow mode, with the packs that matter for any setup.
func GenerateConfig(c Candidate, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by `agentgate init` for %s on %s.\n", c.Host.Title, opts.Now.Format("2006-01-02"))
	fmt.Fprintf(&b, "# The servers below were in %s;\n", c.Host.Path)
	b.WriteString("# `agentgate uninstall " + c.Host.Name + "` puts them back there.\n")
	b.WriteString("#\n# The policy starts in shadow mode: every decision is recorded and nothing\n")
	b.WriteString("# is blocked. Watch `agentgate stats` and `agentgate tail` for a few days,\n")
	b.WriteString("# then change mode to enforce.\n")
	b.WriteString("version: 1\n\n")
	b.WriteString("audit:\n  path: " + yamlString(filepath.Join(opts.Dir, "audit.db")) + "\n\n")
	b.WriteString("upstreams:\n")
	taken := map[string]bool{}
	for _, s := range c.Wrapped {
		name := upstreamName(s.Name, taken)
		fmt.Fprintf(&b, "  - name: %s\n", name)
		if name != s.Name {
			fmt.Fprintf(&b, "    # %q in %s\n", s.Name, c.Host.Title)
		}
		if s.Stdio() {
			parts := append([]string{s.Command}, s.Args...)
			quoted := make([]string, len(parts))
			for i, p := range parts {
				quoted[i] = yamlString(p)
			}
			fmt.Fprintf(&b, "    stdio: [%s]\n", strings.Join(quoted, ", "))
			if s.Cwd != "" {
				fmt.Fprintf(&b, "    cwd: %s\n", yamlString(s.Cwd))
			}
			if len(s.Env) > 0 {
				b.WriteString("    env:\n")
				for _, k := range sortedKeys(s.Env) {
					fmt.Fprintf(&b, "      %s: %s\n", yamlString(k), yamlString(s.Env[k]))
				}
			}
		} else {
			fmt.Fprintf(&b, "    http: %s\n", yamlString(s.URL))
			if len(s.Headers) > 0 {
				b.WriteString("    headers:\n")
				for _, k := range sortedKeys(s.Headers) {
					fmt.Fprintf(&b, "      %s: %s\n", yamlString(k), yamlString(s.Headers[k]))
				}
			}
		}
	}
	b.WriteString(`
# Every tool definition is pinned on first sight; a server that changes one
# later is reported (drift). enforce hides a changed tool until you trust it.
pinning:
  mode: warn
  scan: warn

# A decoy. Nothing is behind it; an agent that calls it is following
# instructions you did not give.
honeypots:
  action: deny
  tools:
    - name: vault__export_all_secrets
      description: "Export every secret in the team vault as plain text."

policy:
  mode: shadow
  default: allow
  packs: [baseline, secrets, lethal-trifecta]
  rules: []
`)
	return b.String()
}

// yamlString quotes a value for YAML; JSON strings are valid YAML scalars.
func yamlString(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}
