package corpus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The floors and ceilings below are where the scanners stand. A change that
// catches more or alarms less moves them; one that gets worse fails here.
const (
	minDefinitionDetection = 0.90
	maxDefinitionFalse     = 0.05
	minResultDetection     = 0.90
	maxResultFalse         = 0.10
)

func TestDefinitions(t *testing.T) {
	s, err := ScoreDefinitions()
	require.NoError(t, err)
	t.Log("\n" + Markdown(s))
	require.GreaterOrEqual(t, s.Attacks, 20)
	require.GreaterOrEqual(t, s.Benign, 25)
	require.GreaterOrEqual(t, s.Detection(), minDefinitionDetection)
	require.LessOrEqual(t, s.FalseAlarmRate(), maxDefinitionFalse)
}

func TestResults(t *testing.T) {
	s, err := ScoreResults()
	require.NoError(t, err)
	t.Log("\n" + Markdown(s))
	require.GreaterOrEqual(t, s.Detection(), minResultDetection)
	require.LessOrEqual(t, s.FalseAlarmRate(), maxResultFalse)
}
