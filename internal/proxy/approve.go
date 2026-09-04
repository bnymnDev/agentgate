package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// ApprovalRequest describes a call that a rule marked "ask".
type ApprovalRequest struct {
	SessionID string          `json:"session_id"`
	Upstream  string          `json:"upstream"`
	Tool      string          `json:"tool"`
	ToolName  string          `json:"tool_name"`
	Args      json.RawMessage `json:"args,omitempty"`
	Decision  policy.Decision `json:"decision"`
	Timeout   time.Duration   `json:"-"`
}

// Approver turns an "ask" into an allow or a deny. An error means the question
// could not be put to anyone, and the call is denied with that reason.
type Approver interface {
	Approve(ctx context.Context, req ApprovalRequest) (policy.Decision, error)
}

// DenyApprover is the fallback when no one can be asked.
type DenyApprover struct {
	// Reason overrides the default explanation.
	Reason string
}

// Approve always denies.
func (d DenyApprover) Approve(context.Context, ApprovalRequest) (policy.Decision, error) {
	reason := d.Reason
	if reason == "" {
		reason = "approval required, no TTY"
	}
	return policy.Decision{Action: policy.ActionDeny, Reason: reason}, nil
}

// TTYApprover asks on agentgate's own terminal. In stdio mode stdin and stdout
// belong to the MCP conversation, so this only works when agentgate is run with
// --http, or when a separate terminal is wired up.
type TTYApprover struct {
	In  io.Reader
	Out io.Writer

	mu    sync.Mutex
	once  sync.Once
	lines chan string
}

// reader starts the single goroutine that owns the terminal's input. Two
// scanners on one reader would race for bytes, and a scanner abandoned by a
// question that timed out would eat the answer to the next one.
func (t *TTYApprover) reader() <-chan string {
	t.once.Do(func() {
		t.lines = make(chan string, 8)
		go func() {
			scanner := bufio.NewScanner(t.In)
			for scanner.Scan() {
				select {
				case t.lines <- strings.TrimSpace(strings.ToLower(scanner.Text())):
				default:
					// Nobody is asking; whatever was typed is not an answer.
				}
			}
			close(t.lines)
		}()
	})
	return t.lines
}

// Approve prints the call and waits for y or n.
func (t *TTYApprover) Approve(ctx context.Context, req ApprovalRequest) (policy.Decision, error) {
	// One question at a time: two agents asking at once on one terminal would
	// be unanswerable.
	t.mu.Lock()
	defer t.mu.Unlock()

	fmt.Fprintf(t.Out, "\n── agentgate approval ───────────────────────────────\n")
	fmt.Fprintf(t.Out, "  tool     %s\n", req.Tool)
	fmt.Fprintf(t.Out, "  upstream %s\n", req.Upstream)
	fmt.Fprintf(t.Out, "  rule     %s — %s\n", req.Decision.RuleID, req.Decision.Reason)
	fmt.Fprintf(t.Out, "  args     %s\n", indentArgs(req.Args))
	if req.Timeout > 0 {
		fmt.Fprintf(t.Out, "  allow this call? [y/N] (denied after %s) ", req.Timeout)
	} else {
		fmt.Fprintf(t.Out, "  allow this call? [y/N] ")
	}

	lines := t.reader()
	// Anything typed before the question was asked is not an answer to it.
	for drained := false; !drained; {
		select {
		case _, ok := <-lines:
			if !ok {
				drained = true
			}
		default:
			drained = true
		}
	}

	select {
	case <-ctx.Done():
		fmt.Fprintf(t.Out, "\n  no answer, denied\n")
		return policy.Decision{Action: policy.ActionDeny, Reason: "approval timed out"}, nil
	case answer, ok := <-lines:
		if !ok {
			return policy.Decision{Action: policy.ActionDeny, Reason: "approval required, the terminal was closed"}, nil
		}
		if answer == "y" || answer == "yes" {
			fmt.Fprintf(t.Out, "  allowed\n")
			return policy.Decision{Action: policy.ActionAllow, Reason: "approved on the agentgate terminal"}, nil
		}
		fmt.Fprintf(t.Out, "  denied\n")
		return policy.Decision{Action: policy.ActionDeny, Reason: "rejected on the agentgate terminal"}, nil
	}
}

// NewTTYApprover returns an approver bound to the controlling terminal, or nil
// when there is none. In stdio mode /dev/tty is used so that the prompt does
// not land in the MCP stream.
func NewTTYApprover() *TTYApprover {
	if tty, err := os.OpenFile(ttyDevice, os.O_RDWR, 0); err == nil {
		return &TTYApprover{In: tty, Out: tty}
	}
	if isTerminal(os.Stdin) && isTerminal(os.Stderr) {
		return &TTYApprover{In: os.Stdin, Out: os.Stderr}
	}
	return nil
}

// Inbox is the queue of pending approvals the web UI shows. It is also an
// Approver, so "ask" in a run with --ui waits for a click instead of a
// keystroke.
type Inbox struct {
	mu      sync.Mutex
	pending map[string]*pendingApproval
}

type pendingApproval struct {
	ID        string          `json:"id"`
	Request   ApprovalRequest `json:"request"`
	CreatedAt time.Time       `json:"created_at"`
	Expires   time.Time       `json:"expires"`

	answer chan policy.Decision
}

// PendingApproval is the read-only view the UI renders.
type PendingApproval struct {
	ID        string
	Request   ApprovalRequest
	CreatedAt time.Time
	Expires   time.Time
}

// NewInbox returns an empty approval inbox.
func NewInbox() *Inbox {
	return &Inbox{pending: map[string]*pendingApproval{}}
}

// Approve parks the call until someone answers in the UI or ctx expires.
func (i *Inbox) Approve(ctx context.Context, req ApprovalRequest) (policy.Decision, error) {
	entry := &pendingApproval{
		ID:        newApprovalID(),
		Request:   req,
		CreatedAt: time.Now(),
		answer:    make(chan policy.Decision, 1),
	}
	if req.Timeout > 0 {
		entry.Expires = entry.CreatedAt.Add(req.Timeout)
	}
	i.mu.Lock()
	i.pending[entry.ID] = entry
	i.mu.Unlock()

	defer func() {
		i.mu.Lock()
		delete(i.pending, entry.ID)
		i.mu.Unlock()
	}()

	select {
	case d := <-entry.answer:
		return d, nil
	case <-ctx.Done():
		return policy.Decision{Action: policy.ActionDeny, Reason: "approval timed out"}, nil
	}
}

// Pending lists the waiting approvals, oldest first.
func (i *Inbox) Pending() []PendingApproval {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]PendingApproval, 0, len(i.pending))
	for _, e := range i.pending {
		out = append(out, PendingApproval{ID: e.ID, Request: e.Request, CreatedAt: e.CreatedAt, Expires: e.Expires})
	}
	for a := 0; a < len(out); a++ {
		for b := a + 1; b < len(out); b++ {
			if out[b].CreatedAt.Before(out[a].CreatedAt) {
				out[a], out[b] = out[b], out[a]
			}
		}
	}
	return out
}

// Resolve answers a pending approval. It reports false when the id is unknown,
// which happens when the call already timed out.
func (i *Inbox) Resolve(id string, allow bool, who string) bool {
	i.mu.Lock()
	entry, ok := i.pending[id]
	i.mu.Unlock()
	if !ok {
		return false
	}
	d := policy.Decision{Action: policy.ActionDeny, Reason: "rejected in the agentgate web UI"}
	if allow {
		d = policy.Decision{Action: policy.ActionAllow, Reason: "approved in the agentgate web UI"}
	}
	if who != "" {
		d.Reason += " by " + who
	}
	select {
	case entry.answer <- d:
		return true
	default:
		return false
	}
}

// ChainApprover tries each approver in turn and uses the first that can answer.
type ChainApprover []Approver

// Approve asks each approver in order.
func (c ChainApprover) Approve(ctx context.Context, req ApprovalRequest) (policy.Decision, error) {
	var last error
	for _, a := range c {
		if a == nil {
			continue
		}
		d, err := a.Approve(ctx, req)
		if err == nil {
			return d, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("no approver available")
	}
	return policy.Decision{}, last
}

func indentArgs(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "           ", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}
