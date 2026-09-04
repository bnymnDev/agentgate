package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// Event is what a webhook receives. It is also what the log line says, so a
// Slack message and a grep of the log tell the same story.
type Event struct {
	Event     string          `json:"event"`
	At        time.Time       `json:"at"`
	SessionID string          `json:"session_id,omitempty"`
	Host      string          `json:"host,omitempty"`
	Upstream  string          `json:"upstream,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Decision  policy.Decision `json:"decision"`
	Args      json.RawMessage `json:"args,omitempty"`
	Shadow    bool            `json:"shadow,omitempty"`
	Message   string          `json:"message"`
}

// notifier fans events out to the configured webhooks, off the request path
// and with a deadline, so a slow chat service can never slow down a tool call.
type notifier struct {
	p      *Proxy
	client *http.Client
}

func newNotifier(p *Proxy) *notifier {
	return &notifier{p: p, client: &http.Client{Timeout: 10 * time.Second}}
}

// emit sends an event to every webhook that subscribed to it.
func (n *notifier) emit(ev Event) {
	cfg := n.p.Config()
	if len(cfg.Notify.Webhooks) == 0 {
		return
	}
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	if ev.Message == "" {
		ev.Message = ev.render()
	}
	// Arguments go out redacted: a webhook is one more place a secret could
	// end up.
	if n.p.store != nil && len(ev.Args) > 0 {
		ev.Args = n.p.redactor().Redact(ev.Args)
	}
	for i := range cfg.Notify.Webhooks {
		hook := &cfg.Notify.Webhooks[i]
		if !hook.Wants(ev.Event) {
			continue
		}
		n.p.wg.Add(1)
		go func(hook *config.Webhook) {
			defer n.p.wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := n.post(ctx, hook, ev); err != nil {
				n.p.log.Warn("webhook delivery failed", "url", hook.URL, "event", ev.Event, "error", err)
			}
		}(hook)
	}
}

func (n *notifier) post(ctx context.Context, hook *config.Webhook, ev Event) error {
	body, contentType, err := encode(hook.Format, ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "agentgate/"+Version)
	if hook.Format == "ntfy" {
		req.Header.Set("Title", "agentgate: "+ev.Event)
		req.Header.Set("Tags", ntfyTag(ev.Event))
		if ev.Event == config.EventHoneypot || ev.Event == config.EventFreeze {
			req.Header.Set("Priority", "urgent")
		}
	}
	for k, v := range hook.Headers {
		req.Header.Set(k, v)
	}
	res, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode >= 300 {
		return fmt.Errorf("%s answered %s", hook.URL, res.Status)
	}
	return nil
}

// encode shapes the body for the service behind the URL.
func encode(format string, ev Event) ([]byte, string, error) {
	switch format {
	case "slack":
		body, err := json.Marshal(map[string]any{"text": ev.Message})
		return body, "application/json", err
	case "discord":
		body, err := json.Marshal(map[string]any{"content": ev.Message})
		return body, "application/json", err
	case "ntfy":
		return []byte(ev.Message), "text/plain; charset=utf-8", nil
	default:
		body, err := json.Marshal(ev)
		return body, "application/json", err
	}
}

// render writes the one-line human version of an event.
func (ev Event) render() string {
	var b strings.Builder
	switch ev.Event {
	case config.EventHoneypot:
		b.WriteString("🪤 honeypot tripped: ")
	case config.EventFreeze:
		b.WriteString("🧊 gateway frozen: ")
	case config.EventDeny:
		b.WriteString("⛔ denied: ")
	case config.EventAsk:
		b.WriteString("🙋 approval needed: ")
	case config.EventShadow:
		b.WriteString("👻 shadow mode would have denied: ")
	case config.EventError:
		b.WriteString("💥 call failed: ")
	default:
		b.WriteString(ev.Event + ": ")
	}
	if ev.Tool != "" {
		b.WriteString(ev.Tool)
	}
	if ev.Decision.Reason != "" {
		b.WriteString(" — " + ev.Decision.Reason)
	}
	if ev.Decision.RuleID != "" {
		b.WriteString(" (rule " + ev.Decision.RuleID + ")")
	}
	if ev.Host != "" {
		b.WriteString(" · host " + ev.Host)
	}
	if ev.SessionID != "" {
		b.WriteString(" · session " + shortID(ev.SessionID))
	}
	if len(ev.Args) > 0 && len(ev.Args) <= 400 {
		b.WriteString("\n" + string(ev.Args))
	}
	return b.String()
}

func ntfyTag(event string) string {
	switch event {
	case config.EventHoneypot:
		return "rotating_light"
	case config.EventFreeze:
		return "ice_cube"
	case config.EventAsk:
		return "raising_hand"
	case config.EventError:
		return "boom"
	default:
		return "no_entry"
	}
}

func shortID(id string) string {
	if len(id) <= 10 {
		return id
	}
	return id[:10]
}

// redactor is the audit store's redactor, or a no-op when auditing is off.
func (p *Proxy) redactor() *audit.Redactor {
	if p.redact != nil {
		return p.redact
	}
	return audit.NewRedactor(nil)
}
