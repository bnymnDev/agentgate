package policy_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// compile parses the policy: section of a config and compiles it.
func compile(t *testing.T, src string) (*policy.Policy, error) {
	t.Helper()
	var p policy.Policy
	if err := yaml.Unmarshal([]byte(src), &p); err != nil {
		return nil, err
	}
	return &p, p.Compile()
}

func mustCompile(t *testing.T, src string) *policy.Policy {
	t.Helper()
	p, err := compile(t, src)
	require.NoError(t, err)
	return p
}

func TestNotRegex(t *testing.T) {
	p := mustCompile(t, `
rules:
  - id: unscoped-delete
    tool: "*"
    when:
      - args.sql: { regex: '(?i)^\s*delete\b' }
      - args.sql: { not_regex: '(?i)\bwhere\b' }
    action: deny
`)
	eval := func(sql string) string {
		return policy.Evaluate(p, &policy.Call{Tool: "db__query", Args: map[string]any{"sql": sql}}).RuleID
	}
	require.Equal(t, "unscoped-delete", eval("DELETE FROM users"))
	require.Equal(t, "", eval("DELETE FROM users WHERE id = 1"))
	require.Equal(t, "", eval("SELECT 1"))

	// Like every matcher but exists, not_regex on a missing path is false.
	require.Equal(t, "", policy.Evaluate(p, &policy.Call{Tool: "db__query", Args: map[string]any{}}).RuleID)
}

func TestIncludesExcludes(t *testing.T) {
	p := mustCompile(t, `
rules:
  - id: tests-first
    tool: "shell.deploy"
    when:
      session.called: { excludes: "shell.test" }
    action: ask
  - id: tagged-prod
    tool: "*"
    when:
      args.tags: { includes: prod }
    action: deny
`)
	deploy := func(called ...string) string {
		return policy.Evaluate(p, &policy.Call{
			Tool: "shell__deploy", Upstream: "shell", ToolName: "deploy",
			Session: policy.History{Called: called},
		}).RuleID
	}
	require.Equal(t, "tests-first", deploy(), "nothing called means the tests were not called")
	require.Equal(t, "tests-first", deploy("shell__exec", "shell.exec"))
	require.Equal(t, "", deploy("shell__exec", "shell.exec", "shell__test", "shell.test"))

	tagged := func(tags any) string {
		return policy.Evaluate(p, &policy.Call{Tool: "x", Args: map[string]any{"tags": tags}}).RuleID
	}
	require.Equal(t, "tagged-prod", tagged([]any{"dev", "prod"}), "a list is opened up without [*]")
	require.Equal(t, "", tagged([]any{"dev"}))
	require.Equal(t, "tagged-prod", tagged("prod"))

	_, err := compile(t, `
rules:
  - id: bad
    tool: "*"
    when:
      session.called: { excludes: [a, b] }
    action: deny
`)
	require.ErrorContains(t, err, "excludes takes a single value")
}

func TestListFormWhen(t *testing.T) {
	p := mustCompile(t, `
rules:
  - id: outside
    tool: "fs.write_file"
    when:
      - args.path: { prefix: "/" }
      - args.path: { not_prefix: "/home/me/repo/" }
    action: deny
`)
	write := func(path string) policy.Action {
		return policy.Evaluate(p, &policy.Call{
			Tool: "fs__write_file", Upstream: "fs", ToolName: "write_file",
			Args: map[string]any{"path": path},
		}).Action
	}
	require.Equal(t, policy.ActionDeny, write("/etc/passwd"))
	require.Equal(t, policy.ActionAllow, write("/home/me/repo/main.go"))
	require.Equal(t, policy.ActionAllow, write("relative.txt"))

	for _, bad := range []string{
		"rules:\n  - id: x\n    tool: '*'\n    when: [args.path]\n    action: deny\n",
		"rules:\n  - id: x\n    tool: '*'\n    when: args.path\n    action: deny\n",
	} {
		_, err := compile(t, bad)
		require.ErrorContains(t, err, "when:")
	}
}

func TestAlternation(t *testing.T) {
	p := mustCompile(t, `
rules:
  - id: rm
    tool: "*"
    when:
      "args.{command,cmd}": { regex: '^rm\b' }
    action: deny
  - id: first-arg
    tool: "*"
    when:
      "args.{argv,args}[0]": { equals: "shutdown" }
    action: deny
`)
	eval := func(args map[string]any) string {
		return policy.Evaluate(p, &policy.Call{Tool: "shell__exec", Args: args}).RuleID
	}
	require.Equal(t, "rm", eval(map[string]any{"command": "rm -rf x"}))
	require.Equal(t, "rm", eval(map[string]any{"cmd": "rm -rf x"}))
	require.Equal(t, "rm", eval(map[string]any{"command": "ls", "cmd": "rm x"}), "any alternative may match")
	require.Equal(t, "", eval(map[string]any{"script": "rm -rf x"}))
	require.Equal(t, "first-arg", eval(map[string]any{"args": []any{"shutdown", "-h"}}))
	require.Equal(t, "", eval(map[string]any{"argv": []any{"ls", "shutdown"}}))

	for src, want := range map[string]string{
		`"args.{command,cmd": { equals: x }`: "unterminated",
		`"args.{command,}": { equals: x }`:   "empty name",
		`"args.{a,b}c": { equals: x }`:       "after {alternation}",
	} {
		_, err := compile(t, "rules:\n  - id: x\n    tool: '*'\n    when:\n      "+src+"\n    action: deny\n")
		require.ErrorContains(t, err, want, src)
	}
}

func TestHostAndSessionSelectors(t *testing.T) {
	p := mustCompile(t, `
rules:
  - id: ci
    tool: "*"
    when:
      host.name: { equals: ci-bot }
      host.version: { prefix: "1." }
    action: deny
  - id: tainted
    tool: "*"
    when:
      session.labels: { includes: untrusted-input }
    action: ask
  - id: not-reviewed
    tool: "git.merge"
    when:
      session.label.reviewed: false
    action: ask
  - id: busy
    tool: "*"
    when:
      session.calls: { gt: 99 }
    action: ask
`)
	eval := func(c policy.Call) string {
		if c.Tool == "" {
			c.Tool, c.Upstream, c.ToolName = "fs__read_file", "fs", "read_file"
		}
		return policy.Evaluate(p, &c).RuleID
	}
	require.Equal(t, "ci", eval(policy.Call{Host: policy.Host{Name: "ci-bot", Version: "1.4.0"}}))
	require.Equal(t, "", eval(policy.Call{Host: policy.Host{Name: "ci-bot", Version: "2.0.0"}}))
	require.Equal(t, "", eval(policy.Call{}), "an unknown host matches no host condition")
	require.Equal(t, "tainted", eval(policy.Call{Session: policy.History{Labels: []string{"private-data", "untrusted-input"}}}))
	merge := policy.Call{Tool: "git__merge", Upstream: "git", ToolName: "merge"}
	require.Equal(t, "not-reviewed", eval(merge))
	merge.Session.Labels = []string{"reviewed"}
	require.Equal(t, "", eval(merge))
	require.Equal(t, "busy", eval(policy.Call{Counts: policy.Counts{Session: 100}}))
	require.Equal(t, "", eval(policy.Call{Counts: policy.Counts{Session: 99}}))

	for src, want := range map[string]string{
		"host.os":               "unknown host field",
		"session.history":       "unknown session field",
		"session.label.Not_Ok":  "invalid label name",
		"session.label.":        "invalid label name",
		"hosts.name":            "unknown condition root",
		"annotations.dangerous": "unknown annotation",
	} {
		_, err := compile(t, "rules:\n  - id: x\n    tool: '*'\n    when:\n      "+src+": { exists: true }\n    action: deny\n")
		require.ErrorContains(t, err, want, src)
	}
}

func TestLabelsFor(t *testing.T) {
	p := mustCompile(t, `
labels:
  - label: untrusted-input
    tool: "web.*"
  - label: private-data
    tool: "*"
    when:
      args.path: { regex: '\.env$' }
  - label: untrusted-input
    tool: "mail.read"
  - label: touched-env
    tool: "fs.*"
    when:
      args.path: { regex: '\.env$' }
`)
	labels := func(tool, upstream, name string, args map[string]any) []string {
		return policy.LabelsFor(p, &policy.Call{Tool: tool, Upstream: upstream, ToolName: name, Args: args})
	}
	require.Equal(t, []string{"untrusted-input"}, labels("web__fetch", "web", "fetch", nil))
	require.Equal(t, []string{"private-data", "touched-env"}, labels("fs__read_file", "fs", "read_file", map[string]any{"path": "/app/.env"}))
	require.Empty(t, labels("fs__read_file", "fs", "read_file", map[string]any{"path": "/app/main.go"}))
	require.Nil(t, policy.LabelsFor(nil, &policy.Call{Tool: "x"}))

	_, err := compile(t, "labels:\n  - label: Bad Label\n    tool: '*'\n")
	require.ErrorContains(t, err, "must be lower-case")
	_, err = compile(t, "labels:\n  - label: everything\n")
	require.ErrorContains(t, err, "would label every session")
}

func TestValidLabel(t *testing.T) {
	for _, ok := range []string{"a", "private-data", "touched_prod", "0day"} {
		require.True(t, policy.ValidLabel(ok), ok)
	}
	for _, bad := range []string{"", "-x", "_x", "Upper", "with space", "dots.are.paths", string(make([]byte, 65))} {
		require.False(t, policy.ValidLabel(bad), bad)
	}
}
