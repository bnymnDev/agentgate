package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// TelegramApprover asks in a Telegram chat. The question is a message with
// Allow / Allow for session / Deny buttons; the presses are read with long
// polling (getUpdates), a request agentgate makes, so it works behind any
// NAT. Only presses in the configured chat — and, if approvers are set, by
// those users — count, and each carries the question's one-time nonce.
type TelegramApprover struct {
	Token     string
	ChatID    int64
	Approvers []int64
	// API defaults to https://api.telegram.org.
	API    string
	Redact func([]byte) []byte
	Client *http.Client
	Log    *slog.Logger

	questions chatQuestions
	offset    int64
}

func (t *TelegramApprover) client() *http.Client {
	if t.Client != nil {
		return t.Client
	}
	return http.DefaultClient
}

func (t *TelegramApprover) log() *slog.Logger {
	if t.Log != nil {
		return t.Log
	}
	return slog.New(slog.DiscardHandler)
}

// call invokes a Bot API method and decodes its result into out.
func (t *TelegramApprover) call(ctx context.Context, method string, params, out any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	api := t.API
	if api == "" {
		api = "https://api.telegram.org"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(api, "/")+"/bot"+t.Token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client().Do(req)
	if err != nil {
		// The error would name the URL, which carries the token.
		return fmt.Errorf("telegram %s: %w", method, unwrapURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	var env struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("telegram %s: %s", method, resp.Status)
	}
	if !env.OK {
		return fmt.Errorf("telegram %s: %s", method, env.Description)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// Approve posts the question and waits for a press, or ctx.
func (t *TelegramApprover) Approve(ctx context.Context, req ApprovalRequest) (Verdict, error) {
	id, nonce, answer, done := t.questions.open()
	defer done()
	title, body := chatText(req, t.Redact)
	button := func(label string, c Choice) map[string]string {
		return map[string]string{"text": label, "callback_data": chatPayload(c, id, nonce)}
	}
	var msg struct {
		MessageID int64 `json:"message_id"`
	}
	err := t.call(ctx, "sendMessage", map[string]any{
		"chat_id": t.ChatID,
		"text":    title + "\n\n" + body,
		"reply_markup": map[string]any{"inline_keyboard": [][]map[string]string{{
			button("Allow", ChoiceAllow), button("Allow for session", ChoiceAllowSession), button("Deny", ChoiceDeny),
		}}},
	}, &msg)
	if err != nil {
		return Verdict{}, err
	}
	var v *Verdict
	select {
	case got := <-answer:
		v = &got
	case <-ctx.Done():
	}
	// The buttons go, so nobody presses them on a question that is gone.
	settle, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := t.call(settle, "editMessageText", map[string]any{
		"chat_id": t.ChatID, "message_id": msg.MessageID, "text": title + "\n\n" + outcomeText(v, nil),
	}, nil); err != nil {
		t.log().Debug("telegram approvals: could not settle a question", "error", err)
	}
	if v == nil {
		return Verdict{Decision: policy.Decision{Action: policy.ActionDeny, Reason: "approval timed out"}}, nil
	}
	return *v, nil
}

// Run polls for button presses until ctx ends.
func (t *TelegramApprover) Run(ctx context.Context) {
	backoff := time.Second
	logged := false
	for ctx.Err() == nil {
		err := t.poll(ctx)
		if err == nil {
			backoff = time.Second
			if !logged {
				t.log().Info("telegram approvals: listening for answers", "chat", t.ChatID)
				logged = true
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		t.log().Warn("telegram approvals: polling failed, retrying", "in", backoff.String(), "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

type telegramUpdate struct {
	UpdateID      int64 `json:"update_id"`
	CallbackQuery *struct {
		ID   string `json:"id"`
		Data string `json:"data"`
		From struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
		} `json:"from"`
		Message *struct {
			Chat struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
	} `json:"callback_query"`
}

func (t *TelegramApprover) poll(ctx context.Context) error {
	var updates []telegramUpdate
	pollCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := t.call(pollCtx, "getUpdates", map[string]any{
		"offset": t.offset, "timeout": 50, "allowed_updates": []string{"callback_query"},
	}, &updates); err != nil {
		return err
	}
	for _, u := range updates {
		t.offset = max(t.offset, u.UpdateID+1)
		cq := u.CallbackQuery
		if cq == nil || cq.Message == nil {
			continue
		}
		text := "This question is not open any more."
		if cq.Message.Chat.ID == t.ChatID && (len(t.Approvers) == 0 || slices.Contains(t.Approvers, cq.From.ID)) {
			if choice, id, nonce, ok := parseChatPayload(cq.Data); ok {
				who := cq.From.Username
				if who != "" {
					who = "@" + who
				}
				if t.questions.deliver(id, nonce, choice, who, "Telegram") {
					text = "Got it."
				}
			}
		} else {
			text = "You cannot answer this one."
		}
		_ = t.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": cq.ID, "text": text}, nil)
	}
	return nil
}

// unwrapURLError drops the URL from a transport error, so that a token in
// it does not end up in a log.
func unwrapURLError(err error) error {
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok && strings.Contains(err.Error(), "/bot") {
		if inner := u.Unwrap(); inner != nil {
			return inner
		}
	}
	return err
}

// Check asks Telegram whether the token is good.
func (t *TelegramApprover) Check(ctx context.Context) error {
	return t.call(ctx, "getMe", map[string]any{}, nil)
}
