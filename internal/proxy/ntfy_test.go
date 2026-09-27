package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// fakeNtfy is just enough of an ntfy server: JSON publishing, publishing a
// raw body to a topic, and a JSON subscription stream.
type fakeNtfy struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	published []map[string]any
	subs      map[string][]chan string
	// dropAfter closes a subscription after this many messages, to test
	// reconnecting. Zero keeps it open.
	dropAfter int
	auth      []string
}

func newFakeNtfy(t *testing.T) *fakeNtfy {
	f := &fakeNtfy{t: t, subs: map[string][]chan string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNtfy) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.mu.Unlock()
	topic := strings.Trim(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodPost && topic == "":
		var msg map[string]any
		require.NoError(f.t, json.NewDecoder(r.Body).Decode(&msg))
		f.mu.Lock()
		f.published = append(f.published, msg)
		f.mu.Unlock()
		fmt.Fprint(w, `{"id":"x"}`)
	case r.Method == http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		subs := f.subs[topic]
		f.mu.Unlock()
		for _, s := range subs {
			s <- string(body)
		}
		fmt.Fprint(w, `{"id":"y"}`)
	case r.Method == http.MethodGet && strings.HasSuffix(topic, "/json"):
		topic = strings.TrimSuffix(topic, "/json")
		ch := make(chan string, 8)
		f.mu.Lock()
		f.subs[topic] = append(f.subs[topic], ch)
		f.mu.Unlock()
		defer func() {
			f.mu.Lock()
			list := f.subs[topic]
			for i, c := range list {
				if c == ch {
					f.subs[topic] = append(list[:i], list[i+1:]...)
					break
				}
			}
			f.mu.Unlock()
		}()
		flusher := w.(http.Flusher)
		fmt.Fprintln(w, `{"event":"open"}`)
		flusher.Flush()
		sent := 0
		for {
			select {
			case <-r.Context().Done():
				return
			case msg := <-ch:
				line, _ := json.Marshal(map[string]string{"event": "message", "message": msg})
				fmt.Fprintln(w, string(line))
				flusher.Flush()
				sent++
				if f.dropAfter > 0 && sent >= f.dropAfter {
					return
				}
			}
		}
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeNtfy) subscribers(topic string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs[topic])
}

func (f *fakeNtfy) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.published)
}

// waitAsked waits until the approver has published its next question.
func (f *fakeNtfy) waitAsked(t *testing.T, before int) {
	t.Helper()
	require.Eventually(t, func() bool { return f.count() > before }, timeoutShort, pollShort, "no question was published")
}

func (f *fakeNtfy) lastPublished() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.published) == 0 {
		return nil
	}
	return f.published[len(f.published)-1]
}

// press does what the phone does when a button is tapped.
func (f *fakeNtfy) press(t *testing.T, label string) {
	t.Helper()
	msg := f.lastPublished()
	require.NotNil(t, msg)
	for _, a := range msg["actions"].([]any) {
		action := a.(map[string]any)
		if action["label"] != label {
			continue
		}
		req, err := http.NewRequest(action["method"].(string), action["url"].(string), bytes.NewBufferString(action["body"].(string)))
		require.NoError(t, err)
		if headers, ok := action["headers"].(map[string]any); ok {
			for k, v := range headers {
				req.Header.Set(k, v.(string))
			}
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return
	}
	t.Fatalf("no button %q", label)
}

func phoneApprover(t *testing.T, f *fakeNtfy) (*NtfyApprover, context.CancelFunc) {
	t.Helper()
	n := &NtfyApprover{Server: f.srv.URL, Topic: "agentgate-test-topic-0123456789", Token: "tk_secret"}
	ctx, cancel := context.WithCancel(context.Background())
	go n.Run(ctx)
	t.Cleanup(cancel)
	require.Eventually(t, func() bool { return f.subscribers(n.answersTopic()) > 0 }, timeoutShort, pollShort)
	return n, cancel
}

func askPhone(n Approver, timeout time.Duration) chan Verdict {
	out := make(chan Verdict, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		v, err := n.Approve(ctx, ApprovalRequest{
			Tool: "shell__exec", Upstream: "shell", Args: json.RawMessage(`{"command":"git push --force"}`),
			Decision: policy.Decision{Action: policy.ActionAsk, Reason: "force push", RuleID: "git-safety/push-main"},
			Timeout:  timeout,
		})
		if err != nil {
			v = Verdict{Decision: policy.Decision{Action: policy.ActionDeny, Reason: "error: " + err.Error()}}
		}
		out <- v
	}()
	return out
}

func TestNtfyApproval(t *testing.T) {
	f := newFakeNtfy(t)
	n, _ := phoneApprover(t, f)

	for label, want := range map[string]struct {
		action  policy.Action
		session bool
	}{
		"Allow":             {policy.ActionAllow, false},
		"Allow for session": {policy.ActionAllow, true},
		"Deny":              {policy.ActionDeny, false},
	} {
		t.Run(label, func(t *testing.T) {
			before := f.count()
			answer := askPhone(n, 5*time.Second)
			f.waitAsked(t, before)
			msg := f.lastPublished()
			require.Equal(t, "agentgate: allow shell__exec?", msg["title"])
			require.Contains(t, msg["message"], "git push --force")
			require.Len(t, msg["actions"], 3)
			f.press(t, label)
			v := <-answer
			require.Equal(t, want.action, v.Action)
			require.Equal(t, want.session, v.Session)
			require.Contains(t, v.Reason, "phone")
		})
	}
	f.mu.Lock()
	auth := append([]string(nil), f.auth...)
	f.mu.Unlock()
	for _, a := range auth {
		require.Equal(t, "Bearer tk_secret", a, "every request carries the token, the buttons included")
	}
}

// An answer is only accepted with the nonce of the question it answers.
func TestNtfyForgedAnswerIsIgnored(t *testing.T) {
	f := newFakeNtfy(t)
	n, _ := phoneApprover(t, f)
	answer := askPhone(n, 5*time.Second)
	f.waitAsked(t, 0)
	id := n.pendingIDs()[0]

	forge := func(body string) {
		resp, err := http.Post(f.srv.URL+"/"+n.answersTopic(), "text/plain", strings.NewReader(body))
		require.NoError(t, err)
		resp.Body.Close()
	}
	forge("allow " + id + " 00000000000000000000000000000000")
	forge("allow " + id)
	forge("allow nope 1234")
	select {
	case v := <-answer:
		t.Fatalf("a forged answer was accepted: %+v", v)
	case <-time.After(200 * time.Millisecond):
	}
	f.press(t, "Deny")
	require.Equal(t, policy.ActionDeny, (<-answer).Action)
}

func TestNtfyTimeout(t *testing.T) {
	f := newFakeNtfy(t)
	n, _ := phoneApprover(t, f)
	v := <-askPhone(n, 100*time.Millisecond)
	require.Equal(t, policy.ActionDeny, v.Action)
	require.Equal(t, "approval timed out", v.Reason)
	require.Empty(t, n.pendingIDs())
}

// The subscription reconnects after the server drops it.
func TestNtfyReconnects(t *testing.T) {
	f := newFakeNtfy(t)
	f.dropAfter = 1
	n, _ := phoneApprover(t, f)
	first := askPhone(n, 5*time.Second)
	f.waitAsked(t, 0)
	f.press(t, "Allow")
	require.Equal(t, policy.ActionAllow, (<-first).Action)

	require.Eventually(t, func() bool { return f.subscribers(n.answersTopic()) > 0 }, 5*time.Second, pollShort)
	second := askPhone(n, 5*time.Second)
	f.waitAsked(t, 1)
	f.press(t, "Deny")
	require.Equal(t, policy.ActionDeny, (<-second).Action)
}

// Fanout: the first channel to answer wins, the others are withdrawn, and a
// channel that cannot ask is skipped.
func TestFanoutFirstAnswerWins(t *testing.T) {
	f := newFakeNtfy(t)
	n, _ := phoneApprover(t, f)
	inbox := NewInbox()
	fan := FanoutApprover{inbox, n, brokenApprover{}}

	answer := askPhone(fan, 5*time.Second)
	f.waitAsked(t, 0)
	require.Eventually(t, func() bool { return len(inbox.Pending()) == 1 }, timeoutShort, pollShort)
	require.True(t, inbox.Resolve(inbox.Pending()[0].ID, ChoiceAllow, "tester"))
	v := <-answer
	require.Equal(t, policy.ActionAllow, v.Action)
	require.Contains(t, v.Reason, "web UI")
	require.Eventually(t, func() bool { return len(n.pendingIDs()) == 0 }, timeoutShort, pollShort, "the phone question is withdrawn")

	// Now the phone answers first.
	answer = askPhone(fan, 5*time.Second)
	f.waitAsked(t, 1)
	f.press(t, "Deny")
	require.Equal(t, policy.ActionDeny, (<-answer).Action)
	require.Eventually(t, func() bool { return len(inbox.Pending()) == 0 }, timeoutShort, pollShort)

	_, err := FanoutApprover{brokenApprover{}}.Approve(context.Background(), ApprovalRequest{})
	require.Error(t, err)
}

type brokenApprover struct{}

func (brokenApprover) Approve(context.Context, ApprovalRequest) (Verdict, error) {
	return Verdict{}, fmt.Errorf("cannot ask")
}
