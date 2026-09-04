package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Honeypots are tools that do not exist. They are advertised to the host like
// any other tool, and a call to one is proof that the agent is acting on
// instructions you did not give it — a prompt injection, a hallucinated
// capability, or a model that has decided to be creative. Nothing is ever
// forwarded; the call is denied, recorded and, if you say so, freezes the
// gateway.
type Honeypots struct {
	// Action is what tripping a honeypot does beyond denying the call:
	// "deny" (the default) or "freeze", which also throws the kill switch.
	Action string `yaml:"action"`
	// Tools are the decoys. Each needs a name; a description makes it more
	// convincing, and the whole point is to be convincing.
	Tools []Honeypot `yaml:"tools"`
}

// Honeypot is one decoy tool.
type Honeypot struct {
	// Name is the exact name the host sees. Give it a prefix that matches a
	// real upstream if you want it to blend in ("fs__delete_everything").
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// Notify sends events to the outside world.
type Notify struct {
	Webhooks []Webhook `yaml:"webhooks"`
}

// Webhook is one HTTP endpoint that wants to hear about events.
type Webhook struct {
	URL string `yaml:"url"`
	// Events is the subset to send: deny, ask, honeypot, freeze, error,
	// shadow. Empty means deny, ask, honeypot and freeze.
	Events []string `yaml:"events"`
	// Format shapes the body: "json" (the default, agentgate's own event
	// object), "slack", "discord" or "ntfy". The named ones post a message
	// the service renders as-is, so a webhook URL from any of them works
	// with no glue in between.
	Format  string            `yaml:"format"`
	Headers map[string]string `yaml:"headers"`
}

// Event names a webhook can subscribe to.
const (
	EventDeny     = "deny"
	EventAsk      = "ask"
	EventHoneypot = "honeypot"
	EventFreeze   = "freeze"
	EventError    = "error"
	EventShadow   = "shadow"
)

var knownEvents = map[string]bool{
	EventDeny: true, EventAsk: true, EventHoneypot: true, EventFreeze: true, EventError: true, EventShadow: true,
}

// DefaultWebhookEvents are sent when a webhook does not say which it wants.
var DefaultWebhookEvents = []string{EventDeny, EventAsk, EventHoneypot, EventFreeze}

// Wants reports whether the webhook subscribed to an event.
func (w *Webhook) Wants(event string) bool {
	events := w.Events
	if len(events) == 0 {
		events = DefaultWebhookEvents
	}
	for _, e := range events {
		if e == event {
			return true
		}
	}
	return false
}

func (h *Honeypots) normalize() error {
	var errs []error
	if h.Action == "" {
		h.Action = "deny"
	}
	switch h.Action {
	case "deny", "freeze":
	default:
		errs = append(errs, fmt.Errorf("honeypots.action: unknown action %q, use deny or freeze", h.Action))
	}
	seen := map[string]bool{}
	for i := range h.Tools {
		t := &h.Tools[i]
		where := fmt.Sprintf("honeypots.tools[%d]", i)
		if t.Name == "" {
			errs = append(errs, fmt.Errorf("%s: missing name", where))
			continue
		}
		if seen[t.Name] {
			errs = append(errs, fmt.Errorf("%s: duplicate honeypot %q", where, t.Name))
		}
		seen[t.Name] = true
		if t.Description == "" {
			t.Description = "Administrative operation. Requires elevated privileges."
		}
	}
	return errors.Join(errs...)
}

func (n *Notify) normalize() error {
	var errs []error
	for i := range n.Webhooks {
		w := &n.Webhooks[i]
		where := fmt.Sprintf("notify.webhooks[%d]", i)
		w.URL = ExpandEnv(w.URL)
		u, err := url.Parse(w.URL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			errs = append(errs, fmt.Errorf("%s: url %q is not an absolute http(s) URL", where, w.URL))
		} else if u.Scheme != "http" && u.Scheme != "https" {
			errs = append(errs, fmt.Errorf("%s: url must be http or https, not %s", where, u.Scheme))
		}
		if w.Format == "" {
			w.Format = "json"
		}
		switch strings.ToLower(w.Format) {
		case "json", "slack", "discord", "ntfy":
			w.Format = strings.ToLower(w.Format)
		default:
			errs = append(errs, fmt.Errorf("%s: unknown format %q, use json, slack, discord or ntfy", where, w.Format))
		}
		for j, e := range w.Events {
			if !knownEvents[e] {
				errs = append(errs, fmt.Errorf("%s: events[%d]: unknown event %q", where, j, e))
			}
		}
		for k, v := range w.Headers {
			w.Headers[k] = ExpandEnv(v)
		}
	}
	return errors.Join(errs...)
}
