package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/policy"
)

func TestPacksComeAfterYourOwnRules(t *testing.T) {
	cfg, err := Parse([]byte(`
upstreams:
  - name: shell
    stdio: ["true"]
policy:
  packs: [baseline]
  rules:
    - id: my-scratch-dir
      tool: "*"
      when:
        args.command: { equals: "rm -rf /" }
      action: ask
`))
	require.NoError(t, err)
	require.Equal(t, "my-scratch-dir", cfg.Policy.Rules[0].ID)
	require.Equal(t, "baseline", cfg.Policy.Rules[1].Pack)
	d := policy.Evaluate(&cfg.Policy, &policy.Call{Tool: "exec", Args: map[string]any{"command": "rm -rf /"}})
	require.Equal(t, "my-scratch-dir", d.RuleID, "your own rules get the first say")
	d = policy.Evaluate(&cfg.Policy, &policy.Call{Tool: "exec", Args: map[string]any{"command": "rm -rf / --no-preserve-root"}})
	require.Equal(t, "baseline/rm-rf-root", d.RuleID)
}

func TestPackFileIsRelativeToTheConfig(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "packs"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packs", "team.yaml"), []byte(`
name: team
description: What the team agreed on.
params:
  branch:
    description: the protected branch
    default: main
rules:
  - id: no-push
    tool: "*"
    when:
      args.branch: { equals: "{{branch}}" }
    action: deny
    reason: "{{branch}} is protected"
`), 0o644))
	cfgPath := filepath.Join(dir, "agentgate.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
upstreams:
  - name: git
    stdio: ["true"]
policy:
  packs:
    - name: ./packs/team.yaml
      with: { branch: release }
`), 0o644))
	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, "team", cfg.Policy.Packs[0].Name, "a pack file is known by its name once loaded")
	d := policy.Evaluate(&cfg.Policy, &policy.Call{Tool: "push", Args: map[string]any{"branch": "release"}})
	require.Equal(t, "team/no-push", d.RuleID)
	require.Equal(t, "release is protected", d.Reason)
}

func TestPackErrors(t *testing.T) {
	for name, tc := range map[string]struct{ packs, want string }{
		"unknown":        {"[no-such-pack]", `unknown pack "no-such-pack"`},
		"twice":          {"[baseline, baseline]", "listed twice"},
		"missing param":  {"[filesystem]", `needs the parameter "workspace"`},
		"missing file":   {"[./nope.yaml]", "reading pack file"},
		"empty name":     {`[{name: ""}]`, "missing pack name"},
		"unknown option": {`[{name: filesystem, with: {workspace: /x, root: /y}}]`, `has no parameter "root"`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte("upstreams:\n  - name: a\n    stdio: [\"true\"]\npolicy:\n  packs: " + tc.packs + "\n"))
			require.ErrorContains(t, err, tc.want)
		})
	}
}
