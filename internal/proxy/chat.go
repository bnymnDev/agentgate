package proxy

import (
	"crypto/subtle"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// Chat approvers — Telegram, Slack — post a question with three buttons and
// read the presses back over a connection agentgate opens itself. They share
// the bookkeeping: each question has an id and a one-time nonce, both in the
// button's payload, and an answer that does not carry the right pair is
// ignored.

type chatQuestion struct {
	nonce  string
	answer chan Verdict
}

type chatQuestions struct {
	mu sync.Mutex
	m  map[string]*chatQuestion
}

// open registers a question and returns its id, nonce and the channel its
// answer arrives on; close forgets it.
func (c *chatQuestions) open() (id, nonce string, answer <-chan Verdict, close func()) {
	id, nonce = randomHex(4), randomHex(8)
	q := &chatQuestion{nonce: nonce, answer: make(chan Verdict, 1)}
	c.mu.Lock()
	if c.m == nil {
		c.m = map[string]*chatQuestion{}
	}
	c.m[id] = q
	c.mu.Unlock()
	return id, nonce, q.answer, func() {
		c.mu.Lock()
		delete(c.m, id)
		c.mu.Unlock()
	}
}

// deliver hands an answer to the question it belongs to. It reports whether
// there was one: an unknown id, a wrong nonce or a question already answered
// is not.
func (c *chatQuestions) deliver(id, nonce string, choice Choice, who, where string) bool {
	c.mu.Lock()
	q, ok := c.m[id]
	c.mu.Unlock()
	if !ok || subtle.ConstantTimeCompare([]byte(nonce), []byte(q.nonce)) != 1 {
		return false
	}
	by := where
	if who != "" {
		by = who + " on " + where
	}
	var v Verdict
	switch choice {
	case ChoiceAllow:
		v = Verdict{Decision: policy.Decision{Action: policy.ActionAllow, Reason: "approved by " + by}}
	case ChoiceAllowSession:
		v = Verdict{Decision: policy.Decision{Action: policy.ActionAllow, Reason: "approved by " + by + " for the rest of the session"}, Session: true}
	case ChoiceDeny:
		v = Verdict{Decision: policy.Decision{Action: policy.ActionDeny, Reason: "rejected by " + by}}
	default:
		return false
	}
	select {
	case q.answer <- v:
		return true
	default:
		return false
	}
}

// chatPayload is what a button carries: "choice id nonce". It fits
// Telegram's 64 bytes.
func chatPayload(choice Choice, id, nonce string) string {
	return string(choice) + " " + id + " " + nonce
}

func parseChatPayload(s string) (Choice, string, string, bool) {
	f := strings.Fields(s)
	if len(f) != 3 {
		return "", "", "", false
	}
	return Choice(f[0]), f[1], f[2], true
}

// chatText is the question, in plain text, the same on every chat.
func chatText(req ApprovalRequest, redact func([]byte) []byte) (title, body string) {
	args := req.Args
	if redact != nil && len(args) > 0 {
		args = redact(args)
	}
	argText := string(args)
	if len(argText) > 600 {
		argText = argText[:600] + "…"
	}
	var b strings.Builder
	b.WriteString(req.Decision.Reason)
	if argText != "" && argText != "null" {
		fmt.Fprintf(&b, "\n\n%s", argText)
	}
	if req.Decision.RuleID != "" {
		fmt.Fprintf(&b, "\n\nrule %s", req.Decision.RuleID)
	}
	if req.Timeout > 0 {
		fmt.Fprintf(&b, " · denied after %s without an answer", req.Timeout.Round(time.Second))
	}
	return "agentgate: allow " + req.Tool + "?", b.String()
}

// outcomeText is what replaces the buttons once the question is settled.
func outcomeText(v *Verdict, err error) string {
	switch {
	case err != nil:
		return "Not answered here: " + err.Error()
	case v == nil:
		return "Answered on another channel, or timed out."
	case v.Action == policy.ActionAllow:
		return "Allowed — " + v.Reason
	default:
		return "Denied — " + v.Reason
	}
}
