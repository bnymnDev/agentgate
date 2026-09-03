package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"":      0,
		"30d":   30 * 24 * time.Hour,
		"2w":    14 * 24 * time.Hour,
		"90m":   90 * time.Minute,
		"1h30m": 90 * time.Minute,
		"1w12h": 7*24*time.Hour + 12*time.Hour,
		"500ms": 500 * time.Millisecond,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		require.NoError(t, err, "parsing %q", in)
		require.Equal(t, want, got, "parsing %q", in)
	}
	_, err := ParseDuration("tomorrow")
	require.Error(t, err)
}

func TestSingleUpstreamIsNotPrefixedByDefault(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 1
upstreams:
  - name: fs
    stdio: ["true"]
policy:
  default: allow
`))
	require.NoError(t, err)
	require.False(t, *cfg.Upstreams[0].Prefix, "one upstream needs no prefix to be unambiguous")
	require.Equal(t, "read_file", cfg.Prefixed(&cfg.Upstreams[0], "read_file"))

	up, tool, ok := cfg.SplitTool("read_file")
	require.True(t, ok)
	require.Equal(t, "fs", up)
	require.Equal(t, "read_file", tool)
}

func TestSeveralUpstreamsArePrefixedByDefault(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 1
upstreams:
  - name: fs
    stdio: ["true"]
  - name: shell
    stdio: ["true"]
policy:
  default: allow
`))
	require.NoError(t, err)
	require.True(t, *cfg.Upstreams[0].Prefix)
	require.Equal(t, "fs__read_file", cfg.Prefixed(&cfg.Upstreams[0], "read_file"))

	up, tool, ok := cfg.SplitTool("shell__exec")
	require.True(t, ok)
	require.Equal(t, "shell", up)
	require.Equal(t, "exec", tool)

	_, _, ok = cfg.SplitTool("mystery__thing")
	require.False(t, ok)
}

func TestEnvExpansion(t *testing.T) {
	t.Setenv("AGENTGATE_TEST_URL", "https://shop.example.com")
	t.Setenv("AGENTGATE_TEST_TOKEN", "s3cret")
	cfg, err := Parse([]byte(`
version: 1
upstreams:
  - name: shop
    stdio: ["node", "server.js", "--url", "${AGENTGATE_TEST_URL}"]
    env:
      SHOP_TOKEN: "${AGENTGATE_TEST_TOKEN}"
      LITERAL: "no dollars here"
policy:
  default: allow
`))
	require.NoError(t, err)
	require.Equal(t, "https://shop.example.com", cfg.Upstreams[0].Stdio[3])
	require.Equal(t, "s3cret", cfg.Upstreams[0].Env["SHOP_TOKEN"])
	require.Equal(t, "no dollars here", cfg.Upstreams[0].Env["LITERAL"])
}

// TestValidationReportsEverythingAtOnce is what makes `policy validate` worth
// running: one pass, every problem. Errors that the YAML decoder raises (an
// unknown key, an unknown matcher) still abort at the first one — see
// TestUnknownKeysAreRejected — but everything semantic is collected.
func TestValidationReportsEverythingAtOnce(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
upstreams:
  - name: a
  - name: a
    stdio: ["true"]
    http: "https://example.com/mcp"
policy:
  default: maybe
  rules:
    - id: dup
      tool: "a.*"
      action: allow
    - id: dup
      tool: "/([/"
      action: nope
`))
	require.Error(t, err)
	msg := err.Error()
	for _, want := range []string{
		"needs either stdio",
		"duplicate upstream name",
		"set either stdio or http",
		"unknown action \"maybe\"",
		"duplicate rule id",
		"invalid regex",
		"unknown action \"nope\"",
	} {
		require.Contains(t, msg, want)
	}
}

func TestUnknownKeysAreRejected(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
upstreams:
  - name: a
    stdio: ["true"]
    stdioo: ["typo"]
policy:
  default: allow
`))
	require.ErrorContains(t, err, "stdioo")
}

func TestUnknownMatcherIsRejected(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
upstreams:
  - name: a
    stdio: ["true"]
policy:
  default: allow
  rules:
    - id: typo
      tool: "a.*"
      when:
        args.path: { not_prefixx: "/tmp" }
      action: deny
`))
	require.ErrorContains(t, err, "not_prefixx")
}

func TestCatchAllRuleNeedsToBeExplicit(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
upstreams:
  - name: a
    stdio: ["true"]
policy:
  default: allow
  rules:
    - id: oops
      action: deny
`))
	require.ErrorContains(t, err, "would match every call")
}

func TestDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 1
upstreams:
  - name: a
    stdio: ["true"]
`))
	require.NoError(t, err)
	require.Equal(t, DefaultPrefixSeparator, cfg.PrefixSeparator)
	require.Equal(t, DefaultCallTimeout, cfg.Timeout(&cfg.Upstreams[0]))
	require.Equal(t, DefaultMaxResultBytes, cfg.Audit.MaxResultBytes)
	require.Equal(t, DefaultRetention, cfg.Audit.Retention.Duration())
	require.True(t, cfg.AuditEnabled())
	require.NotEmpty(t, cfg.Audit.Redactors(), "the built-in redaction patterns are on by default")
}

func TestBuiltinRedactionCanBeTurnedOff(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 1
audit:
  builtin_redaction: false
upstreams:
  - name: a
    stdio: ["true"]
`))
	require.NoError(t, err)
	require.Empty(t, cfg.Audit.Redactors())
}
