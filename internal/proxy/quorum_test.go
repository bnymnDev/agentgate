package proxy

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/policy"
)

func (f *fakeTelegram) pressAs(update int, user int64, name, data string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.presses = append(f.presses, map[string]any{"update_id": update, "callback_query": map[string]any{
		"id": "cq", "data": data, "from": map[string]any{"id": user, "username": name},
		"message": map[string]any{"chat": map[string]any{"id": 42}},
	}})
}

func (f *fakeTelegram) lastEdit() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.edited) == 0 {
		return ""
	}
	return f.edited[len(f.edited)-1]
}

func quorumSetup(t *testing.T) (*fakeTelegram, FanoutApprover, context.Context) {
	fake := &fakeTelegram{}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	tg := &TelegramApprover{Token: "1:a", ChatID: 42, API: srv.URL}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tg.Run(ctx)
	return fake, FanoutApprover{tg}, ctx
}

func ask(ctx context.Context, f FanoutApprover, quorum int) chan Verdict {
	got := make(chan Verdict, 1)
	go func() {
		v, _ := f.Approve(ctx, ApprovalRequest{Tool: "db__drop", Quorum: quorum,
			Decision: policy.Decision{Action: policy.ActionAsk, Reason: "two people", RuleID: "two-person"}})
		got <- v
	}()
	return got
}

// Two different people in one chat make a quorum of two; the same person
// pressing twice does not.
func TestQuorumOfTwoInOneChat(t *testing.T) {
	fake, fan, ctx := quorumSetup(t)
	got := ask(ctx, fan, 2)
	require.Eventually(t, func() bool { return fake.sentCount() == 1 }, time.Second, 10*time.Millisecond)
	allow := fake.button(t, "Allow")
	fake.pressAs(1, 7, "alice", allow)
	fake.pressAs(2, 7, "alice", allow)
	select {
	case v := <-got:
		t.Fatalf("one person decided a two-person rule: %+v", v)
	case <-time.After(1500 * time.Millisecond):
	}
	fake.pressAs(3, 8, "bob", allow)
	select {
	case v := <-got:
		require.Equal(t, policy.ActionAllow, v.Action)
		require.Contains(t, v.Reason, "approved by 2 people")
		require.Contains(t, v.Reason, "@alice on Telegram")
		require.Contains(t, v.Reason, "@bob on Telegram")
	case <-time.After(5 * time.Second):
		t.Fatal("no verdict")
	}
	require.Eventually(t, func() bool { return fake.lastEdit() != "" }, 5*time.Second, 20*time.Millisecond)
	require.Contains(t, fake.lastEdit(), "approved by 2 people")
}

// One no is enough.
func TestQuorumDeniedByOne(t *testing.T) {
	fake, fan, ctx := quorumSetup(t)
	got := ask(ctx, fan, 2)
	require.Eventually(t, func() bool { return fake.sentCount() == 1 }, time.Second, 10*time.Millisecond)
	fake.pressAs(1, 7, "alice", fake.button(t, "Allow"))
	fake.pressAs(2, 8, "bob", fake.button(t, "Deny"))
	select {
	case v := <-got:
		require.Equal(t, policy.ActionDeny, v.Action)
		require.Contains(t, v.Reason, "rejected by @bob")
	case <-time.After(5 * time.Second):
		t.Fatal("no verdict")
	}
}

// A quorum that does not gather in time denies, and says how far it got.
func TestQuorumTimesOut(t *testing.T) {
	fake, fan, ctx := quorumSetup(t)
	short, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	got := ask(short, fan, 2)
	require.Eventually(t, func() bool { return fake.sentCount() == 1 }, time.Second, 10*time.Millisecond)
	fake.pressAs(1, 7, "alice", fake.button(t, "Allow"))
	v := <-got
	require.Equal(t, policy.ActionDeny, v.Action)
	require.Contains(t, v.Reason, "approval timed out with 1 of 2 approvals")
}
