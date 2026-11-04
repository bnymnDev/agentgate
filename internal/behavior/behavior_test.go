package behavior

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/audit"
)

func calls(n int) []*audit.Call {
	var out []*audit.Call
	start := time.Now().Add(-time.Hour)
	for i := range n {
		out = append(out, &audit.Call{Tool: "fs__read", Decision: "allow", TS: start.Add(time.Duration(i) * time.Second),
			Args:   json.RawMessage(fmt.Sprintf(`{"path":"/srv/%d"}`, i)),
			Result: json.RawMessage(fmt.Sprintf(`{"content":[{"type":"text","text":"%0*d"}]}`, 100+i%50, 0)), DurationMS: int64(5 + i%10)})
	}
	out = append(out, &audit.Call{Tool: "fs__read", Decision: "deny", Args: json.RawMessage(`{"evil":1}`)})
	return out
}

func TestLearnAndCompare(t *testing.T) {
	p := Learn(calls(100))
	tp := p.Tools["fs__read"]
	require.Equal(t, 100, tp.Calls, "denied calls say nothing about the tool")
	require.Equal(t, []string{"path"}, tp.ArgKeys)
	require.Positive(t, tp.ResultBytes.P95)

	path := filepath.Join(t.TempDir(), "p.json")
	require.NoError(t, p.Save(path))
	back, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, tp.ResultBytes, back.Tools["fs__read"].ResultBytes)

	th := Thresholds{MinCalls: 20, Factor: 4}
	require.Empty(t, tp.Before(json.RawMessage(`{"path":"/x"}`), th))
	got := tp.Before(json.RawMessage(`{"path":"/x","webhook":"https://x"}`), th)
	require.Len(t, got, 1)
	require.Equal(t, KindNewArgument, got[0].Kind)

	require.Empty(t, tp.After(tp.ResultBytes.Max, 10, nil, th))
	got = tp.After(200_000, 10, []string{"private-data"}, th)
	require.Len(t, got, 2)
	require.Equal(t, KindResultSize, got[0].Kind)
	require.Equal(t, KindNewLabel, got[1].Kind)
	require.Equal(t, KindDuration, tp.After(10, 60_000, nil, th)[0].Kind)
	require.Empty(t, tp.After(10, 300, nil, th), "40 ms is not slow, whatever the profile says")

	young := Learn(calls(5)).Tools["fs__read"]
	require.Empty(t, young.Before(json.RawMessage(`{"new":1}`), th), "five calls are not a normal")

	none, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	require.NoError(t, err)
	require.Nil(t, none)
}
