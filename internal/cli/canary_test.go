package cli

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/canary"
)

// What canary new and canary list print must not read as a credential: not
// to a secret scanner, not to anyone looking at a screenshot of it.
func TestCanaryValuesAreMasked(t *testing.T) {
	awsKey := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	for _, kind := range canary.Kinds {
		c, err := canary.Generate(kind, "")
		require.NoError(t, err)
		for _, v := range c.Values {
			m := masked(v)
			require.NotContains(t, m, v[6:len(v)-4], kind)
			require.Equal(t, v[:6], m[:6], "recognisable by its start")
			require.False(t, awsKey.MatchString(m))
		}
	}
	require.Equal(t, "abc…", masked("abcdefgh"))
	require.Equal(t, "…", masked(""))
}
