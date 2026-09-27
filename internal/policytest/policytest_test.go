package policytest

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
)

const testConfig = `
version: 1
upstreams:
  - name: shell
    stdio: [x]
  - name: mail
    stdio: [x]
  - name: web
    stdio: [x]
policy:
  default: allow
  budget:
    calls_per_tool: { shell.exec: 3 }
  loop_guard:
    repeats: 4
  labels:
    - label: tests-passed
      tool: "shell.test"
      when: { result.is_error: false }
    - label: untrusted-input
      tool: "web.fetch"
  rules:
    - id: no-rm-rf
      tool: "shell.exec"
      when: { args.command: { regex: 'rm\s+-rf' } }
      action: deny
      reason: "destructive shell command"
    - id: deploy-after-green-tests
      tool: "shell.deploy"
      when: { session.label.tests-passed: false }
      action: deny
      reason: "run the tests, and make them pass, before deploying"
    - id: mail-after-web-asks
      tool: "mail.*"
      when: { session.label.untrusted-input: true }
      action: ask
    - id: friday
      tool: "shell.release"
      when: { time.weekday: { equals: friday } }
      action: deny
    - id: ci-only
      tool: "shell.publish"
      when: { host.name: { not_equals: ci-bot } }
      action: deny
    - id: no-destructive
      tool: "*"
      when: { annotations.destructive: true }
      action: ask
`

func run(t *testing.T, tests string) []Outcome {
	t.Helper()
	cfg, err := config.Parse([]byte(testConfig))
	require.NoError(t, err)
	f, err := Parse([]byte(tests))
	require.NoError(t, err)
	return Run(f, Options{Config: cfg, Now: time.Date(2026, 9, 28, 10, 0, 0, 0, time.Local)})
}

func TestPassingTests(t *testing.T) {
	out := run(t, `
tests:
  - name: exposed name
    call: { tool: shell__exec, args: { command: "rm -rf /" } }
    expect: deny
  - name: dotted name
    call: { tool: shell.exec, args: { command: "rm -rf /" } }
    expect: { action: deny, rule: no-rm-rf, reason: destructive }
  - name: result labels
    before:
      - tool: shell.test
        result: { is_error: false }
    call: { tool: shell.deploy }
    expect: allow
  - name: a failed run earns nothing
    before:
      - tool: shell.test
        result: { text: "2 failed", is_error: true }
    call: { tool: shell.deploy }
    expect: { action: deny, rule: deploy-after-green-tests }
  - name: labels the call earns
    call: { tool: web.fetch, args: { url: "https://example.com" } }
    expect: { action: allow, labels: [untrusted-input] }
  - name: labels from before
    before: [{ tool: web.fetch }]
    call: { tool: mail.send }
    expect: ask
  - name: labels given
    labels: [untrusted-input]
    call: { tool: mail.send }
    expect: ask
  - name: budgets count the repeats
    before:
      - { tool: shell.exec, args: { command: ls }, repeat: 3 }
    call: { tool: shell.exec, args: { command: pwd } }
    expect: { action: deny, rule: budget }
  - name: a denied call in before does not count
    before:
      - { tool: shell.exec, args: { command: "rm -rf /" }, repeat: 5 }
    call: { tool: shell.exec, args: { command: pwd } }
    expect: allow
  - name: the loop guard sees denied calls too
    before:
      - { tool: shell.exec, args: { command: "rm -rf /" }, repeat: 5 }
    call: { tool: shell.exec, args: { command: "rm -rf /" } }
    expect: { action: deny, rule: loop-guard }
  - name: time
    at: "friday 17:00"
    call: { tool: shell.release }
    expect: { action: deny, rule: friday }
  - name: host
    host: ci-bot/2.1
    call: { tool: shell.publish }
    expect: allow
  - name: another host
    host: laptop
    call: { tool: shell.publish }
    expect: { action: deny, rule: ci-only }
  - name: annotations
    call: { tool: shell.anything, annotations: { destructive: true } }
    expect: { action: ask, rule: no-destructive }
`)
	require.Len(t, out, 14)
	for _, o := range out {
		require.True(t, o.Passed, "%s: %v (got %+v)", o.Name, o.Problems, o.Got)
	}
	require.Equal(t, []string{"untrusted-input"}, out[4].Labels)
}

func TestFailingTestsSayWhy(t *testing.T) {
	out := run(t, `
tests:
  - name: wrong action and rule
    call: { tool: shell.exec, args: { command: "rm -rf /" } }
    expect: { action: allow, rule: something-else }
  - name: wrong reason
    call: { tool: shell.exec, args: { command: "rm -rf /" } }
    expect: { action: deny, reason: "no such words" }
  - name: missing label
    call: { tool: shell.test, result: { is_error: true } }
    expect: { action: allow, labels: [tests-passed] }
  - name: default decided
    call: { tool: shell.ls }
    expect: { action: allow, rule: some-rule }
  - name: another rule decided
    call: { tool: shell.exec, args: { command: "rm -rf /" } }
    expect: { action: deny, rule: some-rule }
`)
	require.Len(t, out, 5)
	for _, o := range out {
		require.False(t, o.Passed, o.Name)
	}
	require.Equal(t, []string{"want allow, got deny: destructive shell command (rule no-rm-rf)"}, out[0].Problems,
		"a different action already names the rule")
	require.Equal(t, []string{`want a reason containing "no such words", got "destructive shell command"`}, out[1].Problems)
	require.Equal(t, []string{"want the session labelled tests-passed after the call; it is not"}, out[2].Problems)
	require.Equal(t, []string{"want rule some-rule, got no rule (the default decided)"}, out[3].Problems)
	require.Equal(t, []string{"want rule some-rule, got no-rm-rf"}, out[4].Problems)
}

// A test written as steps is a whole session: every step with an expect is
// checked, in order, in one session.
func TestSteps(t *testing.T) {
	out := run(t, `
tests:
  - name: a session
    host: laptop
    steps:
      - tool: web.fetch
        args: { url: "https://example.com" }
        expect: { action: allow, labels: [untrusted-input] }
      - tool: mail.send
        expect: ask
      - tool: shell.test
        result: { is_error: false }
      - tool: shell.deploy
        expect: allow
      - tool: shell.release
        at: friday 17:00
        expect: { action: deny, rule: friday }
  - name: a session gone wrong
    steps:
      - tool: shell.deploy
        expect: allow
      - tool: shell.exec
        args: { command: "rm -rf /" }
        expect: allow
`)
	require.Len(t, out, 2)
	require.True(t, out[0].Passed, "%v", out[0].Problems)
	require.Equal(t, 4, out[0].Checked)

	require.False(t, out[1].Passed)
	require.Equal(t, 2, out[1].Checked)
	require.Equal(t, []string{
		"step 1 (shell.deploy, line 20): want allow, got deny: run the tests, and make them pass, before deploying (rule deploy-after-green-tests)",
		"step 2 (shell.exec, line 22): want allow, got deny: destructive shell command (rule no-rm-rf)",
	}, out[1].Problems)
}

func TestMatchSelectsTests(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig))
	require.NoError(t, err)
	f, err := Parse([]byte(`
tests:
  - { name: one, call: { tool: shell.ls }, expect: allow }
  - { name: two, call: { tool: shell.ls }, expect: allow }
`))
	require.NoError(t, err)
	require.Len(t, Run(f, Options{Config: cfg}), 2)
	require.Len(t, Run(f, Options{Config: cfg, Match: regexpMust("^tw")}), 1)
}

func TestParseRejectsMistakes(t *testing.T) {
	for _, tc := range []struct{ name, file, err string }{
		{"empty", ``, "no tests: the file is empty"},
		{"no tests", `tests: []`, "no tests"},
		{"unknown field", "tests:\n  - name: a\n    cal: { tool: x }\n    expect: allow\n", "field cal not found"},
		{"unknown expect field", "tests:\n  - name: a\n    call: { tool: x }\n    expect: { acton: allow }\n", `expect has no field "acton"`},
		{"missing name", "tests:\n  - call: { tool: x }\n    expect: allow\n", "line 2: missing name"},
		{"duplicate name", "tests:\n  - { name: a, call: { tool: x }, expect: allow }\n  - { name: a, call: { tool: x }, expect: allow }\n", `line 3: "a" is also the name of the test on line 2`},
		{"no tool", "tests:\n  - { name: a, call: {}, expect: allow }\n", "call: needs a tool"},
		{"no expectation", "tests:\n  - { name: a, call: { tool: x } }\n", "expect needs an action"},
		{"bad action", "tests:\n  - { name: a, call: { tool: x }, expect: block }\n", `expect "block": want allow, deny or ask`},
		{"repeat on the call", "tests:\n  - { name: a, call: { tool: x, repeat: 2 }, expect: allow }\n", "repeat is for the calls in before"},
		{"bad label", "tests:\n  - { name: a, labels: [Bad], call: { tool: x }, expect: allow }\n", `label "Bad"`},
		{"bad time", "tests:\n  - { name: a, at: someday, call: { tool: x }, expect: allow }\n", `at: cannot parse "someday"`},
		{"before without tool", "tests:\n  - { name: a, before: [{}], call: { tool: x }, expect: allow }\n", "before[0]: needs a tool"},
		{"no call", "tests:\n  - { name: a, expect: allow }\n", "a test needs a call and what it has to get, or steps"},
		{"expect inside the call", "tests:\n  - { name: a, call: { tool: x, expect: allow }, expect: allow }\n", "expect goes next to call"},
		{"expect in before", "tests:\n  - { name: a, before: [{ tool: x, expect: deny }], call: { tool: x }, expect: allow }\n", "an expect in before is not checked"},
		{"both forms", "tests:\n  - { name: a, steps: [{ tool: x, expect: allow }], call: { tool: x }, expect: allow }\n", "either steps, or call and expect"},
		{"steps without expect", "tests:\n  - { name: a, steps: [{ tool: x }, { tool: y }] }\n", "no step has an expect"},
		{"repeat with expect", "tests:\n  - { name: a, steps: [{ tool: x, repeat: 3, expect: allow }] }\n", "a step with an expect is made once"},
		{"bad step time", "tests:\n  - { name: a, steps: [{ tool: x, at: never, expect: allow }] }\n", `steps[0]: at: cannot parse "never"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.file))
			require.ErrorContains(t, err, tc.err)
		})
	}
}

func TestLoadAndDefaultPath(t *testing.T) {
	require.Equal(t, "/etc/agentgate/agentgate.test.yaml", DefaultPath("/etc/agentgate/agentgate.yaml"))
	require.Equal(t, "cursor.test.yml", DefaultPath("cursor.yml"))
	require.Equal(t, "odd.test.yaml", DefaultPath("odd"))

	path := filepath.Join(t.TempDir(), "agentgate.test.yaml")
	require.NoError(t, os.WriteFile(path, []byte("tests:\n  - { name: a, call: { tool: x }, expect: allow }\n"), 0o600))
	f, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, path, f.Path)
	require.Equal(t, 2, f.Tests[0].Line)
	require.Equal(t, policy.ActionAllow, f.Tests[0].Expect.Action)

	_, err = Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)
}

func TestParseWhen(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.Local) // a Monday
	at, err := ParseWhen("friday 17:00", now)
	require.NoError(t, err)
	require.Equal(t, time.Friday, at.Weekday())
	require.Equal(t, 17, at.Hour())
	at, err = ParseWhen("monday 09:00", now)
	require.NoError(t, err)
	require.Equal(t, now.Day(), at.Day(), "today counts as the coming monday")
	at, err = ParseWhen("08:30", now)
	require.NoError(t, err)
	require.Equal(t, 8, at.Hour())
	_, err = ParseWhen("2026-10-01 12:00", now)
	require.NoError(t, err)
}

func regexpMust(s string) *regexp.Regexp { return regexp.MustCompile(s) }
