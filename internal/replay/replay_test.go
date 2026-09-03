package replay

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
)

func recorded(tool, upstream string, args string, decision policy.Action) *audit.Call {
	return &audit.Call{
		ID: audit.NewID(), SessionID: "s", TS: time.Now(), Tool: tool, Upstream: upstream,
		Args: json.RawMessage(args), ArgsHash: audit.Hash([]byte(args)), Decision: decision,
	}
}

func mustPolicy(t *testing.T, yaml string) *policy.Policy {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	require.NoError(t, err)
	return &cfg.Policy
}

// TestDryRunShowsWhatANewPolicyWouldHaveDone is the feature the whole package
// exists for: point a stricter policy at yesterday's session and see what it
// would have blocked, without sending anything anywhere.
func TestDryRunShowsWhatANewPolicyWouldHaveDone(t *testing.T) {
	calls := []*audit.Call{
		recorded("fs__read_file", "fs", `{"path":"/etc/hosts"}`, policy.ActionAllow),
		recorded("fs__write_file", "fs", `{"path":"/etc/passwd"}`, policy.ActionAllow),
		recorded("fs__write_file", "fs", `{"path":"/srv/app/x"}`, policy.ActionAllow),
	}
	stricter := mustPolicy(t, `
version: 1
upstreams:
  - name: fs
    stdio: ["true"]
policy:
  default: allow
  rules:
    - id: stay-in-app
      tool: "fs.write_file"
      when:
        args.path: { not_prefix: "/srv/app/" }
      action: deny
      reason: "writes are confined to /srv/app"
`)
	report, err := Run(context.Background(), "s", calls, Options{Policy: stricter})
	require.NoError(t, err)
	require.True(t, report.DryRun)
	require.Len(t, report.Entries, 3)

	changed := report.Changed()
	require.Len(t, changed, 1)
	require.Equal(t, "fs__write_file", changed[0].Call.Tool)
	require.Equal(t, policy.ActionAllow, changed[0].Was.Action)
	require.Equal(t, policy.ActionDeny, changed[0].Now.Action)
	require.Equal(t, "stay-in-app", changed[0].Now.RuleID)

	for _, e := range report.Entries {
		require.False(t, e.Sent, "a dry run must not send anything")
	}
}

// TestBudgetsAreSimulated: a budget added after the fact should show up in the
// replay exactly where the session would have run out.
func TestBudgetsAreSimulated(t *testing.T) {
	var calls []*audit.Call
	for range 4 {
		calls = append(calls, recorded("fs__read_file", "fs", `{}`, policy.ActionAllow))
	}
	report, err := Run(context.Background(), "s", calls, Options{Policy: mustPolicy(t, `
version: 1
upstreams:
  - name: fs
    stdio: ["true"]
policy:
  default: allow
  budget:
    calls_per_session: 2
`)})
	require.NoError(t, err)
	require.Equal(t, policy.ActionAllow, report.Entries[0].Now.Action)
	require.Equal(t, policy.ActionAllow, report.Entries[1].Now.Action)
	require.Equal(t, policy.ActionDeny, report.Entries[2].Now.Action)
	require.Contains(t, report.Entries[2].Now.Reason, "budget")
}

func TestOnlyAllowedSkipsRecordedDenials(t *testing.T) {
	calls := []*audit.Call{
		recorded("fs__read_file", "fs", `{}`, policy.ActionAllow),
		recorded("fs__write_file", "fs", `{}`, policy.ActionDeny),
	}
	report, err := Run(context.Background(), "s", calls, Options{
		Policy:      mustPolicy(t, "version: 1\nupstreams:\n  - name: fs\n    stdio: [\"true\"]\npolicy:\n  default: allow\n"),
		OnlyAllowed: true,
	})
	require.NoError(t, err)
	require.False(t, report.Entries[0].Skipped)
	require.True(t, report.Entries[1].Skipped)
}

// fakeForwarder stands in for the live upstreams.
type fakeForwarder struct {
	results map[string]string
	sent    []string
}

func (f *fakeForwarder) ForwardJSON(_ context.Context, tool string, _ json.RawMessage) (json.RawMessage, error) {
	f.sent = append(f.sent, tool)
	if body, ok := f.results[tool]; ok {
		return json.RawMessage(body), nil
	}
	return json.RawMessage(`{"content":[]}`), nil
}

func TestLiveReplayComparesResults(t *testing.T) {
	same := `{"content":[{"type":"text","text":"same"}]}`
	before := recorded("demo__echo", "demo", `{}`, policy.ActionAllow)
	before.ResultHash = audit.Hash([]byte(same))
	drifted := recorded("demo__add", "demo", `{}`, policy.ActionAllow)
	drifted.ResultHash = audit.Hash([]byte(`{"content":[{"type":"text","text":"old"}]}`))

	f := &fakeForwarder{results: map[string]string{
		"demo__echo": same,
		"demo__add":  `{"content":[{"type":"text","text":"new"}]}`,
	}}
	report, err := Run(context.Background(), "s", []*audit.Call{before, drifted}, Options{
		Policy:    mustPolicy(t, "version: 1\nupstreams:\n  - name: demo\n    stdio: [\"true\"]\npolicy:\n  default: allow\n"),
		Forwarder: f,
	})
	require.NoError(t, err)
	require.False(t, report.DryRun)
	require.Equal(t, []string{"demo__echo", "demo__add"}, f.sent)
	require.False(t, report.Entries[0].ResultChanged())
	require.True(t, report.Entries[1].ResultChanged())
}

func TestDiffAlignsAroundInsertions(t *testing.T) {
	a := []*audit.Call{
		recorded("echo", "d", `{"text":"1"}`, policy.ActionAllow),
		recorded("add", "d", `{"a":1}`, policy.ActionAllow),
	}
	b := []*audit.Call{
		recorded("echo", "d", `{"text":"1"}`, policy.ActionAllow),
		recorded("exec", "d", `{"command":"ls"}`, policy.ActionAllow),
		recorded("add", "d", `{"a":2}`, policy.ActionAllow),
	}
	// Same result for the calls that line up, so only the arguments differ.
	a[0].ResultHash, b[0].ResultHash = "h1", "h1"

	d := Compare("a", "b", a, b)
	require.Len(t, d.Rows, 3)
	require.Equal(t, StatusSame, d.Rows[0].Status)
	require.Equal(t, StatusOnlyB, d.Rows[1].Status)
	require.Equal(t, "exec", d.Rows[1].Tool)
	require.Equal(t, StatusArgs, d.Rows[2].Status)
	require.False(t, d.Identical())
}

func TestDiffOfASessionWithItselfIsIdentical(t *testing.T) {
	calls := []*audit.Call{recorded("echo", "d", `{"text":"1"}`, policy.ActionAllow)}
	d := Compare("a", "a", calls, calls)
	require.True(t, d.Identical())
	require.Equal(t, 1, d.Summary()[StatusSame])
}

func TestToolNameStripsThePrefix(t *testing.T) {
	require.Equal(t, "write_file", toolName(&audit.Call{Tool: "fs__write_file", Upstream: "fs"}))
	require.Equal(t, "write_file", toolName(&audit.Call{Tool: "fs.write_file", Upstream: "fs"}))
	require.Equal(t, "write_file", toolName(&audit.Call{Tool: "write_file", Upstream: "fs"}))
}
