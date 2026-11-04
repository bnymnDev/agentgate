package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// fakeTelegram is enough of the Bot API: it keeps the messages sent and hands
// out the button presses a test queues.
type fakeTelegram struct {
	mu      sync.Mutex
	sent    []map[string]any
	edited  []string
	presses []map[string]any
	answers []string
}

func (f *fakeTelegram) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var params map[string]any
	_ = json.NewDecoder(r.Body).Decode(&params)
	method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(result any) { _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result}) }
	switch method {
	case "sendMessage":
		f.sent = append(f.sent, params)
		reply(map[string]any{"message_id": len(f.sent)})
	case "editMessageText":
		f.edited = append(f.edited, params["text"].(string))
		reply(true)
	case "answerCallbackQuery":
		f.answers = append(f.answers, params["text"].(string))
		reply(true)
	case "getUpdates":
		out := f.presses
		f.presses = nil
		reply(out)
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "description": "no such method"})
	}
}

// button returns the payload of a button of the last question sent.
func (f *fakeTelegram) button(t *testing.T, label string) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.sent)
	kb := f.sent[len(f.sent)-1]["reply_markup"].(map[string]any)["inline_keyboard"].([]any)[0].([]any)
	for _, b := range kb {
		if b.(map[string]any)["text"] == label {
			return b.(map[string]any)["callback_data"].(string)
		}
	}
	t.Fatalf("no button %q", label)
	return ""
}

func (f *fakeTelegram) press(update int, chat, user int64, data string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.presses = append(f.presses, map[string]any{"update_id": update, "callback_query": map[string]any{
		"id": "cq", "data": data, "from": map[string]any{"id": user, "username": "me"},
		"message": map[string]any{"chat": map[string]any{"id": chat}},
	}})
}

func (f *fakeTelegram) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func TestTelegramApprover(t *testing.T) {
	fake := &fakeTelegram{}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	tg := &TelegramApprover{Token: "123:abc", ChatID: 42, Approvers: []int64{7}, API: srv.URL}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tg.Run(ctx)

	got := make(chan Verdict, 1)
	go func() {
		v, err := tg.Approve(ctx, ApprovalRequest{Tool: "shell__exec", Args: json.RawMessage(`{"command":"make deploy"}`),
			Decision: policy.Decision{Action: policy.ActionAsk, Reason: "deploys need a human", RuleID: "deploy"}})
		require.NoError(t, err)
		got <- v
	}()
	require.Eventually(t, func() bool { return fake.sentCount() == 1 }, time.Second, 10*time.Millisecond)
	fake.mu.Lock()
	require.Contains(t, fake.sent[0]["text"], "agentgate: allow shell__exec?")
	require.Contains(t, fake.sent[0]["text"], "make deploy")
	fake.mu.Unlock()

	allow := fake.button(t, "Allow for session")
	choice, id, _, _ := parseChatPayload(allow)
	fake.press(1, 99, 7, allow)                                       // another chat
	fake.press(2, 42, 8, allow)                                       // someone not in approvers
	fake.press(3, 42, 7, chatPayload(choice, id, "0000000000000000")) // a guessed nonce
	fake.press(4, 42, 7, allow)                                       // the real thing
	select {
	case v := <-got:
		require.Equal(t, policy.ActionAllow, v.Action)
		require.True(t, v.Session)
		require.Contains(t, v.Reason, "@me on Telegram")
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
	require.Eventually(t, func() bool {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return len(fake.edited) == 1 && strings.Contains(fake.edited[0], "Allowed")
	}, time.Second, 10*time.Millisecond, "the buttons are replaced by the outcome")
}

func TestSlackApprover(t *testing.T) {
	var mu sync.Mutex
	var posted map[string]any
	var updated []string
	acks := make(chan string, 4)
	press := make(chan []byte, 4)
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/chat.postMessage", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer xoxb-bot", r.Header.Get("Authorization"))
		mu.Lock()
		_ = json.NewDecoder(r.Body).Decode(&posted)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "channel": "C1", "ts": "1.2"})
	})
	mux.HandleFunc("/chat.update", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		updated = append(updated, "update")
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	mux.HandleFunc("/apps.connections.open", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer xapp-app", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "url": "ws" + strings.TrimPrefix(srv.URL, "http") + "/socket"})
	})
	mux.HandleFunc("/socket", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		ctx := r.Context()
		go func() {
			for {
				_, data, err := c.Read(ctx)
				if err != nil {
					return
				}
				acks <- string(data)
			}
		}()
		for {
			select {
			case msg := <-press:
				if err := c.Write(ctx, websocket.MessageText, msg); err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	sl := &SlackApprover{BotToken: "xoxb-bot", AppToken: "xapp-app", Channel: "C1", Approvers: []string{"U1"}, API: srv.URL}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sl.Run(ctx)

	got := make(chan Verdict, 1)
	go func() {
		v, err := sl.Approve(ctx, ApprovalRequest{Tool: "github__merge_pull_request",
			Decision: policy.Decision{Action: policy.ActionAsk, Reason: "merging needs a human"}})
		require.NoError(t, err)
		got <- v
	}()
	var value string
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		if posted == nil {
			return false
		}
		actions := posted["blocks"].([]any)[1].(map[string]any)["elements"].([]any)
		value = actions[2].(map[string]any)["value"].(string) // Deny
		return true
	}, 2*time.Second, 10*time.Millisecond)

	envelope := func(id, user, channel string) []byte {
		raw, _ := json.Marshal(map[string]any{"envelope_id": id, "type": "interactive", "payload": map[string]any{
			"type": "block_actions", "user": map[string]any{"id": user, "username": "ana"}, "channel": map[string]any{"id": channel},
			"actions": []any{map[string]any{"action_id": "agentgate_deny", "value": value}},
		}})
		return raw
	}
	press <- envelope("e1", "U2", "C1") // not an approver
	press <- envelope("e2", "U1", "C9") // another channel
	press <- envelope("e3", "U1", "C1")
	select {
	case v := <-got:
		require.Equal(t, policy.ActionDeny, v.Action)
		require.Contains(t, v.Reason, "rejected by ana on Slack")
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
	for _, want := range []string{"e1", "e2", "e3"} {
		select {
		case a := <-acks:
			require.Contains(t, a, want, "every envelope is acknowledged")
		case <-time.After(2 * time.Second):
			t.Fatal("no ack")
		}
	}
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(updated) == 1
	}, time.Second, 10*time.Millisecond)
}
