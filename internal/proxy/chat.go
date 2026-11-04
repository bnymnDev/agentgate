package proxy

import (
	"context"
	"crypto/subtle"
	"errors"
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
	// seen is who answered already: in a chat, each person counts once.
	seen map[string]bool
}

type chatQuestions struct {
	mu sync.Mutex
	m  map[string]*chatQuestion
}

// open registers a question and returns its id, nonce and the channel its
// answer arrives on; close forgets it.
func (c *chatQuestions) open() (id, nonce string, answer <-chan Verdict, close func()) {
	id, nonce = randomHex(4), randomHex(8)
	q := &chatQuestion{nonce: nonce, answer: make(chan Verdict, 16), seen: map[string]bool{}}
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
// it counted: an unknown id, a wrong nonce or a second answer by the same
// person does not.
func (c *chatQuestions) deliver(id, nonce string, choice Choice, who, where string) bool {
	c.mu.Lock()
	q, ok := c.m[id]
	if ok && subtle.ConstantTimeCompare([]byte(nonce), []byte(q.nonce)) == 1 {
		key := who
		if key == "" {
			key = "anonymous"
		}
		if q.seen[key] {
			ok = false
		}
		q.seen[key] = true
	} else {
		ok = false
	}
	c.mu.Unlock()
	if !ok {
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
	v.Who, v.Channel = who, where
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

// Collector is an approver that can take more than one answer to the same
// question — several people in one chat — which a quorum needs. It posts
// the question, sends every answer to out as it arrives, and settles the
// question when ctx ends; context.Cause(ctx) carries the final outcome.
type Collector interface {
	Collect(ctx context.Context, req ApprovalRequest, out chan<- Verdict) error
}

// settled is the cause a question is closed with: how it ended.
type settled struct{ v Verdict }

func (s settled) Error() string { return "settled" }

// finalOutcome is how a collected question ended, if the asker said.
func finalOutcome(ctx context.Context) *Verdict {
	var s settled
	if errors.As(context.Cause(ctx), &s) {
		return &s.v
	}
	return nil
}

// firstAnswer is Approve for a Collector: the first answer decides.
func firstAnswer(ctx context.Context, c Collector, req ApprovalRequest) (Verdict, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	out := make(chan Verdict, 16)
	done := make(chan error, 1)
	go func() { done <- c.Collect(ctx, req, out) }()
	select {
	case v := <-out:
		cancel(settled{v})
		<-done
		return v, nil
	case err := <-done:
		select {
		case v := <-out:
			return v, nil
		default:
		}
		if err != nil {
			return Verdict{}, err
		}
		return Verdict{Decision: policy.Decision{Action: policy.ActionDeny, Reason: "approval timed out"}}, nil
	}
}
