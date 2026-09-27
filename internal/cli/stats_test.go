package cli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/audit"
)

func TestThresholds(t *testing.T) {
	totals := &audit.Stats{Calls: 120, Denied: 3, Canaries: 1}
	rules := []*audit.RuleStat{{RuleID: "baseline/rm-rf-root", Calls: 2}, {RuleID: "baseline/rm-rf-root", Calls: 1}}

	crossed, err := checkThresholds("canary>0, honeypot>0, denied>=3, rule:baseline/rm-rf-root>2, calls<100", totals, rules)
	require.NoError(t, err)
	require.Equal(t, []string{"canary>0 (is 1)", "denied>=3 (is 3)", "rule:baseline/rm-rf-root>2 (is 3)"}, crossed)

	crossed, err = checkThresholds("denied=0", &audit.Stats{}, nil)
	require.NoError(t, err)
	require.Len(t, crossed, 1)

	_, err = checkThresholds("denied>lots", totals, nil)
	require.Error(t, err)
	_, err = checkThresholds("weird>1", totals, nil)
	require.ErrorContains(t, err, "unknown counter")
}
