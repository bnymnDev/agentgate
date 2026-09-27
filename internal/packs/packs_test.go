package packs_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/packs"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// Every pack that ships must expand with its defaults (and a value for each
// required parameter), compile, and describe itself.
func TestBuiltinPacks(t *testing.T) {
	names := packs.Names()
	require.NotEmpty(t, names)
	require.Contains(t, names, "baseline")

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			src, ok := packs.Get(name)
			require.True(t, ok)
			head, err := policy.ReadPackHeader(src)
			require.NoError(t, err)
			require.Equal(t, name, head.Name, "the file name and the pack name must agree")
			require.NotEmpty(t, head.Description)

			with := map[string]string{}
			for param, spec := range head.Params {
				require.NotEmpty(t, spec.Description, "parameter %s needs a description", param)
				if spec.Required {
					with[param] = "/home/me/repo"
				}
			}
			pack, err := policy.ExpandPack(src, policy.PackRef{Name: name, With: with}, nil)
			require.NoError(t, err)
			require.True(t, len(pack.Rules)+len(pack.Labels) > 0, "a pack must contribute something")

			p := &policy.Policy{Rules: pack.Rules, Labels: pack.Labels}
			require.NoError(t, p.Compile())
			for _, r := range pack.Rules {
				require.NotEmpty(t, r.Reason, "rule %s needs a reason: it is what the agent is told", r.ID)
			}
		})
	}

	_, ok := packs.Get("no-such-pack")
	require.False(t, ok)
}
