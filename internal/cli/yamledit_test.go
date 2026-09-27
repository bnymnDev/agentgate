package cli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/policy"
)

func TestAddPackText(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		ref  policy.PackRef
		want string
	}{
		"no policy section": {
			in:   "version: 1\nupstreams:\n  - name: fs\n    stdio: [x]\n",
			ref:  policy.PackRef{Name: "baseline"},
			want: "version: 1\nupstreams:\n  - name: fs\n    stdio: [x]\npolicy:\n  packs:\n    - baseline\n",
		},
		"no trailing newline": {
			in:   "version: 1",
			ref:  policy.PackRef{Name: "baseline"},
			want: "version: 1\npolicy:\n  packs:\n    - baseline\n",
		},
		"packs goes before the rules, with the comment kept on the rules": {
			in: `policy:
  default: allow

  # the important part
  rules:
    - id: x
      tool: "*"
      action: deny
`,
			ref: policy.PackRef{Name: "baseline"},
			want: `policy:
  default: allow

  packs:
    - baseline

  # the important part
  rules:
    - id: x
      tool: "*"
      action: deny
`,
		},
		"append to a block list, blank line and next key untouched": {
			in: `policy:
  packs:
    - baseline   # first
    - name: filesystem
      with: { workspace: /x }

  rules:
    - id: a
      tool: "*"
      action: deny
`,
			ref: policy.PackRef{Name: "secrets"},
			want: `policy:
  packs:
    - baseline   # first
    - name: filesystem
      with: { workspace: /x }
    - secrets

  rules:
    - id: a
      tool: "*"
      action: deny
`,
		},
		"list at key indentation, last in the file": {
			in:   "policy:\n  packs:\n  - baseline\n",
			ref:  policy.PackRef{Name: "secrets"},
			want: "policy:\n  packs:\n  - baseline\n  - secrets\n",
		},
		"flow list": {
			in:   "policy:\n  packs: [baseline]   # on\n  default: allow\n",
			ref:  policy.PackRef{Name: "filesystem", With: map[string]string{"workspace": "~/code/app"}},
			want: "policy:\n  packs: [baseline, { name: filesystem, with: { workspace: ~/code/app } }]   # on\n  default: allow\n",
		},
		"empty flow list": {
			in:   "policy:\n  packs: []\n",
			ref:  policy.PackRef{Name: "baseline"},
			want: "policy:\n  packs: [baseline]\n",
		},
		"empty packs key": {
			in:   "policy:\n  packs:\n  default: allow\n",
			ref:  policy.PackRef{Name: "baseline"},
			want: "policy:\n  packs:\n    - baseline\n  default: allow\n",
		},
		"parameters": {
			in:   "policy:\n  default: allow\n",
			ref:  policy.PackRef{Name: "business-hours", With: map[string]string{"last_hour": "18", "first_hour": "7"}},
			want: "policy:\n  default: allow\n  packs:\n    - name: business-hours\n      with: { first_hour: \"7\", last_hour: \"18\" }\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := addPackText([]byte(tc.in), tc.ref)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(out))
		})
	}

	_, err := addPackText([]byte("policy:\n  packs: [baseline]\n"), policy.PackRef{Name: "baseline"})
	require.ErrorContains(t, err, "already")
	_, err = addPackText([]byte("policy: {default: allow}\n"), policy.PackRef{Name: "baseline"})
	require.ErrorContains(t, err, "by hand")
}

func TestRemovePackText(t *testing.T) {
	for name, tc := range map[string]struct {
		in, pack, want string
	}{
		"block list, middle item with parameters": {
			in: `policy:
  packs:
    - baseline
    - name: filesystem
      with: { workspace: /x }
    - secrets

  rules: []
`,
			pack: "filesystem",
			want: `policy:
  packs:
    - baseline
    - secrets

  rules: []
`,
		},
		"last item takes the key with it": {
			in:   "policy:\n  default: allow\n  packs:\n    - baseline\n\n  rules: []\n",
			pack: "baseline",
			want: "policy:\n  default: allow\n\n  rules: []\n",
		},
		"last in the list": {
			in:   "policy:\n  packs:\n    - baseline\n    - secrets\n",
			pack: "secrets",
			want: "policy:\n  packs:\n    - baseline\n",
		},
		"flow list": {
			in:   "policy:\n  packs: [baseline, secrets, lethal-trifecta]  # on\n",
			pack: "secrets",
			want: "policy:\n  packs: [baseline, lethal-trifecta]  # on\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := removePackText([]byte(tc.in), tc.pack)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(out))
		})
	}
	_, err := removePackText([]byte("policy:\n  packs: [baseline]\n"), "secrets")
	require.ErrorContains(t, err, "not in policy.packs")
}

func TestYAMLScalar(t *testing.T) {
	require.Equal(t, "baseline", yamlScalar("baseline"))
	require.Equal(t, `"7"`, yamlScalar("7"))
	require.Equal(t, `"true"`, yamlScalar("true"))
	require.Equal(t, `"a, b"`, yamlScalar("a, b"))
	require.Equal(t, "./packs/team.yaml", yamlScalar("./packs/team.yaml"))
}
