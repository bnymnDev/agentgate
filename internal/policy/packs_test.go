package policy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/bnymnDev/agentgate/internal/policy"
)

func TestPackRefUnmarshal(t *testing.T) {
	var refs []policy.PackRef
	require.NoError(t, yaml.Unmarshal([]byte(`
- baseline
- name: filesystem
  with: { workspace: /home/me/repo }
- ./packs/company.yaml
`), &refs))
	require.Equal(t, []policy.PackRef{
		{Name: "baseline"},
		{Name: "filesystem", With: map[string]string{"workspace": "/home/me/repo"}},
		{Name: "./packs/company.yaml"},
	}, refs)
	require.False(t, refs[0].IsFile())
	require.False(t, refs[1].IsFile())
	require.True(t, refs[2].IsFile())
	require.True(t, policy.PackRef{Name: "company.yml"}.IsFile())

	require.ErrorContains(t, yaml.Unmarshal([]byte("- name: x\n  params: {}\n"), &refs), `unknown pack field "params"`)
	require.ErrorContains(t, yaml.Unmarshal([]byte("- [a, b]\n"), &refs), "a pack is a name")
}

const testPack = `
name: demo
description: A pack for tests.
params:
  root:
    description: the directory to stay in
    required: true
    path: true
  limit:
    description: how many
    default: "5"
labels:
  - label: outside
    tool: "*"
    when:
      args.path: { not_prefix: "{{root}}/" }
rules:
  - id: stay-inside
    tool: "fs.*"
    when:
      args.path: { not_prefix: "{{ root }}/" }
    action: deny
    reason: "stay in {{root}}"
  - id: not-too-many
    tool: "*"
    when:
      args.count: { gt: "{{limit}}" }
    action: ask
`

func TestExpandPack(t *testing.T) {
	clean := func(p string) (string, error) { return strings.TrimSuffix(p, "/"), nil }
	pack, err := policy.ExpandPack([]byte(testPack), policy.PackRef{Name: "demo", With: map[string]string{"root": "/srv/app/"}}, clean)
	require.NoError(t, err)
	require.Len(t, pack.Rules, 2)
	require.Equal(t, "demo/stay-inside", pack.Rules[0].ID)
	require.Equal(t, "demo", pack.Rules[0].Pack)
	require.Equal(t, "stay in /srv/app", pack.Rules[0].Reason)
	require.Equal(t, "/srv/app/", *pack.Rules[0].When[0].Matcher.NotPrefix)
	require.Equal(t, 5.0, *pack.Rules[1].When[0].Matcher.Gt, "a whole-value placeholder takes the type of its value")
	require.Len(t, pack.Labels, 1)
	require.Equal(t, "outside", pack.Labels[0].Label, "label names are shared, not prefixed")
	require.Equal(t, "demo", pack.Labels[0].Pack)

	p := &policy.Policy{Rules: pack.Rules, Labels: pack.Labels}
	require.NoError(t, p.Compile())
	d := policy.Evaluate(p, &policy.Call{Tool: "fs__write_file", Upstream: "fs", ToolName: "write_file", Args: map[string]any{"path": "/etc/passwd"}})
	require.Equal(t, policy.ActionDeny, d.Action)
	require.Equal(t, "demo/stay-inside", d.RuleID)
}

func TestExpandPackErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		src  string
		with map[string]string
		want string
	}{
		"missing required":  {testPack, nil, `needs the parameter "root"`},
		"unknown parameter": {testPack, map[string]string{"root": "/x", "rooot": "/y"}, `has no parameter "rooot"`},
		"unknown placeholder": {
			"name: p\ndescription: d\nrules:\n  - id: r\n    tool: '{{nope}}'\n    action: deny\n", nil,
			`unknown parameter "nope"`,
		},
		"bad name":      {"name: Not OK\ndescription: d\n", nil, "must be lower-case"},
		"unknown field": {"name: p\ndescription: d\nrules:\n  - id: r\n    tool: '*'\n    action: deny\n    severity: high\n", nil, "severity"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := policy.ExpandPack([]byte(tc.src), policy.PackRef{Name: "p", With: tc.with}, nil)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// A parameter value is substituted into one scalar of the parsed pack. It
// can never add a rule, however much YAML it contains.
func TestExpandPackValuesCannotChangeStructure(t *testing.T) {
	evil := "/x/\"\n  - id: allow-all\n    tool: \"*\"\n    action: allow\n#"
	pack, err := policy.ExpandPack([]byte(testPack), policy.PackRef{Name: "demo", With: map[string]string{"root": evil}}, nil)
	require.NoError(t, err)
	require.Len(t, pack.Rules, 2)
	require.Equal(t, evil+"/", *pack.Rules[0].When[0].Matcher.NotPrefix)
	for _, r := range pack.Rules {
		require.NotEqual(t, policy.ActionAllow, r.Action)
	}
}

func TestReadPackHeader(t *testing.T) {
	head, err := policy.ReadPackHeader([]byte(testPack))
	require.NoError(t, err)
	require.Equal(t, "demo", head.Name)
	require.Equal(t, "A pack for tests.", head.Description)
	require.True(t, head.Params["root"].Required)
	require.Equal(t, "5", head.Params["limit"].Default)
	require.Empty(t, head.Rules, "the header does not expand anything")
}
