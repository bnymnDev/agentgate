// Package config loads and validates agentgate.yaml.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// Defaults that apply when the config file leaves a field out.
const (
	DefaultPrefixSeparator = "__"
	DefaultCallTimeout     = 120 * time.Second
	DefaultApprovalTimeout = 60 * time.Second
	DefaultRetention       = 30 * 24 * time.Hour
	DefaultMaxResultBytes  = 256 * 1024
	DefaultAuditPath       = "~/.agentgate/audit.db"
	DefaultUIAddr          = "127.0.0.1:7777"
)

// Config is the whole of agentgate.yaml.
type Config struct {
	Version int `yaml:"version"`
	// PrefixSeparator joins the upstream name and the tool name. It defaults to
	// "__" because some MCP hosts reject dots in tool names; policy rules may
	// still be written with a dot either way.
	PrefixSeparator string        `yaml:"prefix_separator"`
	CallTimeout     Duration      `yaml:"call_timeout"`
	Approval        Approval      `yaml:"approval"`
	Audit           Audit         `yaml:"audit"`
	Upstreams       []Upstream    `yaml:"upstreams"`
	Policy          policy.Policy `yaml:"policy"`
	Honeypots       Honeypots     `yaml:"honeypots"`
	Notify          Notify        `yaml:"notify"`

	// Path is the file the config was read from. It is not part of the file.
	Path string `yaml:"-"`
}

// Approval configures what happens to calls a rule marked "ask".
type Approval struct {
	// Mode is auto, tty, ui or deny.
	//
	//	auto  use the web UI when it is running, else the TTY, else deny
	//	tty   prompt on the agentgate terminal only
	//	ui    wait for an approval in the web UI only
	//	deny  never ask, deny every "ask" decision
	Mode    string   `yaml:"mode"`
	Timeout Duration `yaml:"timeout"`
}

// Audit configures the SQLite audit store.
type Audit struct {
	// Enabled defaults to true; set it to false to run without an audit trail.
	Enabled   *bool    `yaml:"enabled"`
	Path      string   `yaml:"path"`
	Retention Duration `yaml:"retention"`
	// Redact holds regexes applied to arguments and results before they are
	// written. They are added to the built-in patterns unless BuiltinRedaction
	// is false.
	Redact           []string `yaml:"redact"`
	BuiltinRedaction *bool    `yaml:"builtin_redaction"`
	// MaxResultBytes caps how much of a result is stored. Larger results are
	// truncated and flagged.
	MaxResultBytes int `yaml:"max_result_bytes"`

	compiled []*regexp.Regexp
}

// Upstream is one real MCP server agentgate connects to.
type Upstream struct {
	Name string `yaml:"name"`
	// Stdio is the command and arguments to run, for a stdio server.
	Stdio []string `yaml:"stdio"`
	// HTTP is the endpoint of a Streamable HTTP server.
	HTTP string `yaml:"http"`
	// Env is added to the environment of a stdio server. Values may reference
	// the agentgate process environment with ${VAR}.
	Env map[string]string `yaml:"env"`
	// Cwd is the working directory of a stdio server.
	Cwd string `yaml:"cwd"`
	// Headers are sent with every request to an HTTP server.
	Headers map[string]string `yaml:"headers"`
	// Prefix controls whether this upstream's tools are exposed with a
	// "<name><sep>" prefix. It defaults to true when more than one upstream is
	// configured and to false for a single upstream.
	Prefix  *bool    `yaml:"prefix"`
	Timeout Duration `yaml:"timeout"`
}

// Transport reports how the upstream is reached.
func (u *Upstream) Transport() string {
	if u.HTTP != "" {
		return "http"
	}
	return "stdio"
}

// Load reads, expands and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	cfg.Path = abs
	return cfg, nil
}

// Parse decodes and validates config bytes. Unknown fields are an error, so a
// misspelled key is caught by "agentgate policy validate" rather than silently
// ignored at run time.
func Parse(raw []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// normalize fills in defaults, expands ${ENV} and ~, and validates.
func (c *Config) normalize() error {
	var errs []error
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Version != 1 {
		errs = append(errs, fmt.Errorf("version: unsupported config version %d, this build understands version 1", c.Version))
	}
	if c.PrefixSeparator == "" {
		c.PrefixSeparator = DefaultPrefixSeparator
	}
	if c.Approval.Mode == "" {
		c.Approval.Mode = "auto"
	}
	switch c.Approval.Mode {
	case "auto", "tty", "ui", "deny":
	default:
		errs = append(errs, fmt.Errorf("approval.mode: unknown mode %q, want auto, tty, ui or deny", c.Approval.Mode))
	}
	if c.Approval.Timeout == 0 {
		c.Approval.Timeout = Duration(DefaultApprovalTimeout)
	}
	if c.CallTimeout == 0 {
		c.CallTimeout = Duration(DefaultCallTimeout)
	}

	if c.Audit.Path == "" {
		c.Audit.Path = DefaultAuditPath
	}
	expanded, err := ExpandPath(c.Audit.Path)
	if err != nil {
		errs = append(errs, fmt.Errorf("audit.path: %w", err))
	} else {
		c.Audit.Path = expanded
	}
	if c.Audit.Retention == 0 {
		c.Audit.Retention = Duration(DefaultRetention)
	}
	if c.Audit.MaxResultBytes == 0 {
		c.Audit.MaxResultBytes = DefaultMaxResultBytes
	}
	if c.Audit.MaxResultBytes < 0 {
		errs = append(errs, errors.New("audit.max_result_bytes: must not be negative"))
	}
	if err := c.Audit.compile(); err != nil {
		errs = append(errs, err)
	}

	if len(c.Upstreams) == 0 {
		errs = append(errs, errors.New("upstreams: at least one upstream is required"))
	}
	seen := make(map[string]bool, len(c.Upstreams))
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		where := fmt.Sprintf("upstreams[%d]", i)
		if u.Name == "" {
			errs = append(errs, fmt.Errorf("%s: missing name", where))
		} else {
			where = fmt.Sprintf("upstreams[%d] (%s)", i, u.Name)
			if seen[u.Name] {
				errs = append(errs, fmt.Errorf("%s: duplicate upstream name", where))
			}
			seen[u.Name] = true
			if strings.Contains(u.Name, c.PrefixSeparator) {
				errs = append(errs, fmt.Errorf("%s: name must not contain the prefix separator %q", where, c.PrefixSeparator))
			}
		}
		switch {
		case len(u.Stdio) > 0 && u.HTTP != "":
			errs = append(errs, fmt.Errorf("%s: set either stdio or http, not both", where))
		case len(u.Stdio) == 0 && u.HTTP == "":
			errs = append(errs, fmt.Errorf("%s: needs either stdio: [command, args...] or http: <url>", where))
		}
		for j, arg := range u.Stdio {
			u.Stdio[j] = ExpandEnv(arg)
		}
		u.HTTP = ExpandEnv(u.HTTP)
		for k, v := range u.Env {
			u.Env[k] = ExpandEnv(v)
		}
		for k, v := range u.Headers {
			u.Headers[k] = ExpandEnv(v)
		}
		if u.Cwd != "" {
			if p, err := ExpandPath(u.Cwd); err != nil {
				errs = append(errs, fmt.Errorf("%s: cwd: %w", where, err))
			} else {
				u.Cwd = p
			}
		}
		if u.Prefix == nil {
			u.Prefix = boolPtr(len(c.Upstreams) > 1)
		}
	}

	if err := c.Policy.Compile(); err != nil {
		errs = append(errs, err)
	}
	if err := c.Honeypots.normalize(); err != nil {
		errs = append(errs, err)
	}
	if err := c.Notify.normalize(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// FreezeFile is the path of the kill-switch marker. It sits next to the audit
// database so that every agentgate process reading the same config agrees on
// it, and so that `agentgate freeze` works with no proxy running at all.
func (c *Config) FreezeFile() string {
	return filepath.Join(filepath.Dir(c.Audit.Path), "FROZEN")
}

// AuditEnabled reports whether calls should be recorded.
func (c *Config) AuditEnabled() bool { return c.Audit.Enabled == nil || *c.Audit.Enabled }

// Prefixed returns the name a tool of upstream u is exposed under.
func (c *Config) Prefixed(u *Upstream, tool string) string {
	if u.Prefix != nil && !*u.Prefix {
		return tool
	}
	return u.Name + c.PrefixSeparator + tool
}

// SplitTool resolves an exposed tool name back to an upstream and the name the
// upstream uses. It reports false when no configured upstream can own the name.
func (c *Config) SplitTool(exposed string) (upstream string, tool string, ok bool) {
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if u.Prefix != nil && !*u.Prefix {
			continue
		}
		prefix := u.Name + c.PrefixSeparator
		if strings.HasPrefix(exposed, prefix) {
			return u.Name, strings.TrimPrefix(exposed, prefix), true
		}
	}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if u.Prefix != nil && !*u.Prefix {
			return u.Name, exposed, true
		}
	}
	return "", exposed, false
}

// Timeout returns the per-call timeout for an upstream.
func (c *Config) Timeout(u *Upstream) time.Duration {
	return u.Timeout.Or(c.CallTimeout.Or(DefaultCallTimeout))
}

// Redactors returns the compiled redaction patterns.
func (a *Audit) Redactors() []*regexp.Regexp { return a.compiled }

func (a *Audit) compile() error {
	var errs []error
	var out []*regexp.Regexp
	if a.BuiltinRedaction == nil || *a.BuiltinRedaction {
		out = append(out, BuiltinRedactors()...)
	}
	for i, pat := range a.Redact {
		re, err := regexp.Compile(pat)
		if err != nil {
			errs = append(errs, fmt.Errorf("audit.redact[%d]: invalid regex %q: %w", i, pat, err))
			continue
		}
		out = append(out, re)
	}
	a.compiled = out
	return errors.Join(errs...)
}

// ExpandEnv replaces ${VAR} and $VAR with the value from the environment.
// Unset variables expand to the empty string, matching how MCP host configs
// behave.
func ExpandEnv(s string) string {
	if !strings.ContainsRune(s, '$') {
		return s
	}
	return os.Expand(s, func(key string) string {
		if key == "$" {
			return "$"
		}
		return os.Getenv(key)
	})
}

// ExpandPath expands ${ENV} and a leading ~ in a filesystem path.
func ExpandPath(p string) (string, error) {
	p = ExpandEnv(p)
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot resolve %q: %w", p, err)
		}
		return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/")), nil
	}
	return p, nil
}

func boolPtr(b bool) *bool { return &b }
