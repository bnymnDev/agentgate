package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// SlackApprover asks in a Slack channel. The question is a message with
// Allow / Allow for session / Deny buttons; the presses arrive over Socket
// Mode, a WebSocket agentgate opens to Slack, so nothing has to reach it from
// outside. Only presses in the configured channel — and, if approvers are
// set, by those users — count, and each carries the question's one-time
// nonce.
type SlackApprover struct {
	BotToken  string
	AppToken  string
	Channel   string
	Approvers []string
	// API defaults to https://slack.com/api.
	API    string
	Redact func([]byte) []byte
	Client *http.Client
	Log    *slog.Logger

	questions chatQuestions
}

func (s *SlackApprover) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return http.DefaultClient
}

func (s *SlackApprover) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

// call invokes a Web API method with a token and decodes the response into
// out.
func (s *SlackApprover) call(ctx context.Context, token, method string, params, out any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	api := s.API
	if api == "" {
		api = "https://slack.com/api"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(api, "/")+"/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.client().Do(req)
	if err != nil {
		return fmt.Errorf("slack %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw := new(bytes.Buffer)
	if _, err := raw.ReadFrom(resp.Body); err != nil {
		return err
	}
	var env struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw.Bytes(), &env); err != nil {
		return fmt.Errorf("slack %s: %s", method, resp.Status)
	}
	if !env.OK {
		return fmt.Errorf("slack %s: %s", method, env.Error)
	}
	if out != nil {
		return json.Unmarshal(raw.Bytes(), out)
	}
	return nil
}

func slackBlocks(title, body string, buttons bool, id, nonce string) []any {
	blocks := []any{
		map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": "*" + slackEscape(title) + "*\n" + slackEscape(body)}},
	}
	if buttons {
		button := func(label string, c Choice, style string) map[string]any {
			b := map[string]any{"type": "button", "action_id": "agentgate_" + string(c),
				"text": map[string]any{"type": "plain_text", "text": label}, "value": chatPayload(c, id, nonce)}
			if style != "" {
				b["style"] = style
			}
			return b
		}
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{
			button("Allow", ChoiceAllow, "primary"), button("Allow for session", ChoiceAllowSession, ""), button("Deny", ChoiceDeny, "danger"),
		}})
	}
	return blocks
}

// slackEscape keeps a tool's arguments from being read as mrkdwn.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// Approve posts the question and waits for a press, or ctx.
func (s *SlackApprover) Approve(ctx context.Context, req ApprovalRequest) (Verdict, error) {
	return firstAnswer(ctx, s, req)
}

// Collect posts the question and passes on every press until ctx ends.
func (s *SlackApprover) Collect(ctx context.Context, req ApprovalRequest, out chan<- Verdict) error {
	id, nonce, answer, done := s.questions.open()
	defer done()
	title, body := chatText(req, s.Redact)
	var posted struct {
		Channel string `json:"channel"`
		TS      string `json:"ts"`
	}
	if err := s.call(ctx, s.BotToken, "chat.postMessage", map[string]any{
		"channel": s.Channel, "text": title, "blocks": slackBlocks(title, body, true, id, nonce),
	}, &posted); err != nil {
		return err
	}
	for wait := true; wait; {
		select {
		case v := <-answer:
			out <- v
		case <-ctx.Done():
			wait = false
		}
	}
	settle, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.call(settle, s.BotToken, "chat.update", map[string]any{
		"channel": posted.Channel, "ts": posted.TS, "text": title,
		"blocks": slackBlocks(title, body+"\n\n"+outcomeText(finalOutcome(ctx), nil), false, "", ""),
	}, nil); err != nil {
		s.log().Debug("slack approvals: could not settle a question", "error", err)
	}
	return nil
}

// Run keeps the Socket Mode connection open until ctx ends, reconnecting
// when Slack asks it to or the connection drops.
func (s *SlackApprover) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		connected, err := s.connect(ctx)
		if ctx.Err() != nil {
			return
		}
		if connected {
			backoff = time.Second
		}
		s.log().Warn("slack approvals: connection dropped, reconnecting", "in", backoff.String(), "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

type slackEnvelope struct {
	EnvelopeID string `json:"envelope_id"`
	Type       string `json:"type"`
	Payload    struct {
		Type string `json:"type"`
		User struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
		Channel struct {
			ID string `json:"id"`
		} `json:"channel"`
		Actions []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"actions"`
	} `json:"payload"`
}

var errSlackDisconnect = errors.New("slack asked for a reconnect")

func (s *SlackApprover) connect(ctx context.Context) (bool, error) {
	var open struct {
		URL string `json:"url"`
	}
	if err := s.call(ctx, s.AppToken, "apps.connections.open", map[string]any{}, &open); err != nil {
		return false, err
	}
	conn, resp, err := websocket.Dial(ctx, open.URL, &websocket.DialOptions{HTTPClient: s.client()})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return false, fmt.Errorf("slack socket mode: %w", err)
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(1 << 20)
	// A connection that died quietly would leave Read waiting for ever; a
	// ping that goes unanswered closes it, and Run dials again.
	alive, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-alive.Done():
				return
			case <-tick.C:
			}
			pingCtx, cancel := context.WithTimeout(alive, 10*time.Second)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				_ = conn.CloseNow()
				return
			}
		}
	}()
	s.log().Info("slack approvals: listening for answers", "channel", s.Channel)
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return true, err
		}
		var env slackEnvelope
		if json.Unmarshal(data, &env) != nil {
			continue
		}
		if env.EnvelopeID != "" {
			ack, _ := json.Marshal(map[string]string{"envelope_id": env.EnvelopeID})
			if err := conn.Write(ctx, websocket.MessageText, ack); err != nil {
				return true, err
			}
		}
		switch env.Type {
		case "disconnect":
			_ = conn.Close(websocket.StatusNormalClosure, "")
			return true, errSlackDisconnect
		case "interactive":
			s.handle(env)
		}
	}
}

func (s *SlackApprover) handle(env slackEnvelope) {
	p := env.Payload
	if p.Type != "block_actions" || p.Channel.ID != s.Channel {
		return
	}
	if len(s.Approvers) > 0 && !slices.Contains(s.Approvers, p.User.ID) {
		s.log().Warn("slack approvals: a press by someone not in approvers was ignored", "user", p.User.ID)
		return
	}
	for _, a := range p.Actions {
		if !strings.HasPrefix(a.ActionID, "agentgate_") {
			continue
		}
		if choice, id, nonce, ok := parseChatPayload(a.Value); ok {
			who := p.User.Username
			if who == "" {
				who = p.User.ID
			}
			s.questions.deliver(id, nonce, choice, who, "Slack")
		}
	}
}

// Check asks Slack whether the bot token is good.
func (s *SlackApprover) Check(ctx context.Context) error {
	return s.call(ctx, s.BotToken, "auth.test", map[string]any{}, nil)
}
