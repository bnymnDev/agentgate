package policy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/policy"
)

func lintChecks(t *testing.T, src string, ctx policy.LintContext) map[string]string {
	t.Helper()
	p := mustCompile(t, src)
	out := map[string]string{}
	for _, f := range policy.Lint(p, ctx) {
		out[f.Check+" "+f.Rule] = f.Message
	}
	return out
}

func TestLint(t *testing.T) {
	got := lintChecks(t, `
default: allow
labels:
  - label: tainted
    tool: "web.*"
rules:
  - id: everything-in-fs
    tool: "fs.*"
    action: ask
  - id: shadowed
    tool: "fs.write_file"
    when: { args.path: { prefix: "/tmp/" } }
    action: deny
  - id: any-path-in-repo
    tool: "git.add"
    when: { "args.paths[*]": { prefix: "/home/me/repo/" } }
    action: allow
  - id: loose
    tool: "shell.exec"
    when: { args.command: { regex: 'git status' } }
    action: allow
  - id: sibling
    tool: "shell.exec"
    when: { args.cwd: { not_prefix: "/home/me/repo" } }
    action: deny
  - id: trusting
    tool: "*"
    when: { annotations.read_only: true }
    action: allow
  - id: typo-label
    tool: "*"
    when: { session.label.tainnted: true }
    action: deny
  - id: fine-label
    tool: "*"
    when: { session.label.tainted: true }
    action: ask
  - id: canary-label
    tool: "*"
    when: { session.label.canary-read: true }
    action: ask
  - id: never-called
    tool: "deploy"
    when: { session.called: { not_equals: "test" } }
    action: ask
  - id: typo-tool
    tool: "gihtub.*"
    action: deny
`, policy.LintContext{Tools: []string{"fs__write_file", "fs.write_file", "github__merge", "github.merge"}, ApprovalMode: "deny"})

	require.Contains(t, got, "unreachable shadowed")
	require.Contains(t, got["unreachable shadowed"], "everything-in-fs")
	require.Contains(t, got, "allow-any-value any-path-in-repo")
	require.Contains(t, got, "unanchored-allow loose")
	require.Contains(t, got, "prefix-without-slash sibling")
	require.Contains(t, got, "trusts-annotations trusting")
	require.Contains(t, got, "unknown-label typo-label")
	require.NotContains(t, got, "unknown-label fine-label")
	require.NotContains(t, got, "unknown-label canary-label", "agentgate attaches canary-read itself")
	require.Contains(t, got, "not-equals-on-a-list never-called")
	require.Contains(t, got, "unknown-tool typo-tool")
	require.NotContains(t, got, "unknown-tool shadowed")
	require.Contains(t, got, "ask-without-approvals ")
}

func TestLintQuietOnAGoodPolicy(t *testing.T) {
	got := lintChecks(t, `
default: deny
rules:
  - id: reads
    tool: "fs.read_file"
    when: { args.path: { prefix: "/home/me/repo/" } }
    action: allow
  - id: tests
    tool: "shell.exec"
    when: { args.command: { regex: '^go test ' } }
    action: allow
`, policy.LintContext{})
	require.Empty(t, got)
}

func TestLintIgnoresPackRules(t *testing.T) {
	p := mustCompile(t, `
default: allow
rules:
  - id: catch-all
    tool: "*"
    action: allow
`)
	p.Packs = []policy.PackRef{{Name: "baseline"}}
	var checks []string
	for _, f := range policy.Lint(p, policy.LintContext{}) {
		checks = append(checks, f.Check)
	}
	require.Contains(t, strings.Join(checks, " "), "packs-unreachable")
}
