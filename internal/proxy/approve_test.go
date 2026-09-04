package proxy

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// scriptedApprover answers every question the same way and counts how often
// it was asked.
type scriptedApprover struct {
	verdict Verdict
	asked   atomic.Int32
}

func (s *scriptedApprover) Approve(context.Context, ApprovalRequest) (Verdict, error) {
	s.asked.Add(1)
	return s.verdict, nil
}

const askPolicy = `
version: 1
upstreams:
  - name: demo
    stdio: ["unused-in-tests"]
policy:
  default: allow
  rules:
    - id: writes-need-a-human
      tool: "write_file"
      action: ask
      reason: "writes need a human"
`

// TestAllowForSessionIsRemembered: after "allow for this session" the same
// tool is not asked about again, while a different ask rule still is.
func TestAllowForSessionIsRemembered(t *testing.T) {
	h := setup(t, askPolicy)
	approver := &scriptedApprover{verdict: Verdict{
		Decision: policy.Decision{Action: policy.ActionAllow, Reason: "approved for the session"},
		Session:  true,
	}}
	h.proxy.approver = approver

	for i := range 3 {
		res := call(t, h, "write_file", map[string]any{"path": "/tmp/x"})
		require.False(t, res.IsError, "call %d", i)
	}
	require.Equal(t, int32(1), approver.asked.Load(), "the human is asked once, not three times")

	calls := waitForCalls(t, h.store, 3)
	require.Contains(t, calls[0].Reason, "approved for the session")
	require.Contains(t, calls[1].Reason, "approved earlier for the rest of this session")
	require.Equal(t, "writes-need-a-human", calls[1].RuleID, "the rule that asked is still recorded")
}

// TestAllowOnceAsksAgain is the other half: a plain allow does not stick.
func TestAllowOnceAsksAgain(t *testing.T) {
	h := setup(t, askPolicy)
	approver := &scriptedApprover{verdict: Verdict{
		Decision: policy.Decision{Action: policy.ActionAllow, Reason: "approved once"},
	}}
	h.proxy.approver = approver
	require.False(t, call(t, h, "write_file", map[string]any{"path": "/tmp/x"}).IsError)
	require.False(t, call(t, h, "write_file", map[string]any{"path": "/tmp/y"}).IsError)
	require.Equal(t, int32(2), approver.asked.Load())
}

// TestSessionApprovalDoesNotLeakAcrossSessions: a second host connection
// starts with a clean slate.
func TestSessionApprovalDoesNotLeakAcrossSessions(t *testing.T) {
	h := setup(t, askPolicy)
	approver := &scriptedApprover{verdict: Verdict{
		Decision: policy.Decision{Action: policy.ActionAllow, Reason: "approved for the session"},
		Session:  true,
	}}
	h.proxy.approver = approver
	require.False(t, call(t, h, "write_file", map[string]any{"path": "/tmp/x"}).IsError)

	second := connectSecondClient(t, h)
	params := mcpCallParams("write_file", map[string]any{"path": "/tmp/x"})
	res, err := second.CallTool(context.Background(), &params)
	require.NoError(t, err)
	require.False(t, res.IsError)
	require.Equal(t, int32(2), approver.asked.Load(), "the new session is asked on its own")
}

// TestInboxChoices covers the three buttons of the web UI.
func TestInboxChoices(t *testing.T) {
	inbox := NewInbox()
	ask := func(choice Choice) Verdict {
		done := make(chan Verdict, 1)
		go func() {
			v, _ := inbox.Approve(context.Background(), ApprovalRequest{Tool: "x"})
			done <- v
		}()
		require.Eventually(t, func() bool { return len(inbox.Pending()) == 1 }, timeoutShort, pollShort)
		require.True(t, inbox.Resolve(inbox.Pending()[0].ID, choice, "test"))
		return <-done
	}
	v := ask(ChoiceAllow)
	require.Equal(t, policy.ActionAllow, v.Action)
	require.False(t, v.Session)

	v = ask(ChoiceAllowSession)
	require.Equal(t, policy.ActionAllow, v.Action)
	require.True(t, v.Session)

	v = ask(ChoiceDeny)
	require.Equal(t, policy.ActionDeny, v.Action)
}
