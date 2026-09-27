package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// NtfyApprover puts a question on your phone. It publishes the pending call
// to an ntfy topic with Allow / Allow for session / Deny buttons; a button
// posts its answer to a second topic, <topic>-answers, which the approver
// reads over a long-lived subscription. Nothing listens on a port, so it
// works from a laptop behind any NAT, and the answer carries a one-time
// nonce, so it cannot be replayed or guessed.
type NtfyApprover struct {
	// Server is the ntfy base URL, "https://ntfy.sh" or your own.
	Server string
	// Topic is where questions are published. On a public server the topic
	// name is the password: make it long and random.
	Topic string
	// Token is an access token for servers with access control.
	Token string
	// Redact scrubs the arguments before they leave the machine.
	Redact func([]byte) []byte
	Client *http.Client
	Log    *slog.Logger

	mu      sync.Mutex
	pending map[string]*ntfyPending
	started time.Time
}

type ntfyPending struct {
	nonce  string
	answer chan Verdict
}

func (n *NtfyApprover) client() *http.Client {
	if n.Client != nil {
		return n.Client
	}
	return http.DefaultClient
}

func (n *NtfyApprover) log() *slog.Logger {
	if n.Log != nil {
		return n.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (n *NtfyApprover) answersTopic() string { return n.Topic + "-answers" }

func (n *NtfyApprover) url(parts ...string) string {
	return strings.TrimRight(n.Server, "/") + "/" + strings.Join(parts, "/")
}

// Approve publishes the question and waits for a button, or ctx.
func (n *NtfyApprover) Approve(ctx context.Context, req ApprovalRequest) (Verdict, error) {
	id, nonce := randomHex(4), randomHex(16)
	entry := &ntfyPending{nonce: nonce, answer: make(chan Verdict, 1)}
	n.mu.Lock()
	if n.pending == nil {
		n.pending = map[string]*ntfyPending{}
	}
	n.pending[id] = entry
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.pending, id)
		n.mu.Unlock()
	}()

	if err := n.publish(ctx, req, id, nonce); err != nil {
		return Verdict{}, fmt.Errorf("ntfy: %w", err)
	}
	select {
	case v := <-entry.answer:
		return v, nil
	case <-ctx.Done():
		return Verdict{Decision: policy.Decision{Action: policy.ActionDeny, Reason: "approval timed out"}}, nil
	}
}

type ntfyAction struct {
	Action  string            `json:"action"`
	Label   string            `json:"label"`
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Body    string            `json:"body"`
	Headers map[string]string `json:"headers,omitempty"`
	Clear   bool              `json:"clear"`
}

func (n *NtfyApprover) publish(ctx context.Context, req ApprovalRequest, id, nonce string) error {
	args := req.Args
	if n.Redact != nil && len(args) > 0 {
		args = n.Redact(args)
	}
	argText := string(args)
	if len(argText) > 600 {
		argText = argText[:600] + "…"
	}
	var msg strings.Builder
	fmt.Fprintf(&msg, "%s\n", req.Decision.Reason)
	if argText != "" && argText != "null" {
		fmt.Fprintf(&msg, "\n%s\n", argText)
	}
	if req.Decision.RuleID != "" {
		fmt.Fprintf(&msg, "\nrule %s", req.Decision.RuleID)
	}
	if req.Timeout > 0 {
		fmt.Fprintf(&msg, " · denied after %s without an answer", req.Timeout.Round(time.Second))
	}
	var headers map[string]string
	if n.Token != "" {
		headers = map[string]string{"Authorization": "Bearer " + n.Token}
	}
	button := func(label string, choice Choice) ntfyAction {
		return ntfyAction{
			Action: "http", Label: label, URL: n.url(n.answersTopic()), Method: "POST",
			Body: string(choice) + " " + id + " " + nonce, Headers: headers, Clear: true,
		}
	}
	body, err := json.Marshal(map[string]any{
		"topic":    n.Topic,
		"title":    "agentgate: allow " + req.Tool + "?",
		"message":  msg.String(),
		"priority": 4,
		"tags":     []string{"agentgate", "ask"},
		"actions": []ntfyAction{
			button("Allow", ChoiceAllow),
			button("Allow for session", ChoiceAllowSession),
			button("Deny", ChoiceDeny),
		},
	})
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(n.Server, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if n.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+n.Token)
	}
	resp, err := n.client().Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("publishing to %s: %s", n.Server, resp.Status)
	}
	return nil
}

// Run keeps the subscription to the answers topic open until ctx ends,
// reconnecting with backoff when the connection drops.
func (n *NtfyApprover) Run(ctx context.Context) {
	n.mu.Lock()
	if n.started.IsZero() {
		n.started = time.Now()
	}
	n.mu.Unlock()
	backoff := time.Second
	for ctx.Err() == nil {
		connected, err := n.subscribe(ctx)
		if ctx.Err() != nil {
			return
		}
		if connected {
			backoff = time.Second
		}
		n.log().Warn("ntfy approvals: subscription dropped, reconnecting", "in", backoff.String(), "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// subscribe reads the answers topic as a JSON stream. It reports whether it
// got as far as a connection, for the backoff.
func (n *NtfyApprover) subscribe(ctx context.Context) (bool, error) {
	// Answers are read from when the approver started, so one given while
	// the connection was down is still picked up after it comes back.
	since := strconv.FormatInt(n.started.Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.url(n.answersTopic(), "json")+"?since="+since, nil)
	if err != nil {
		return false, err
	}
	if n.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}
	// The stream is long-lived; the client's own timeout would cut it.
	client := *n.client()
	client.Timeout = 0
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return false, fmt.Errorf("subscribing to %s: %s", n.answersTopic(), resp.Status)
	}
	n.log().Info("ntfy approvals: listening for answers", "server", n.Server)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		var ev struct {
			Event   string `json:"event"`
			Message string `json:"message"`
		}
		if json.Unmarshal(scanner.Bytes(), &ev) != nil || ev.Event != "message" {
			continue
		}
		n.answer(ev.Message)
	}
	if err := scanner.Err(); err != nil {
		return true, err
	}
	return true, errors.New("stream closed")
}

// answer delivers "choice id nonce" to the approval it belongs to. Anything
// else — an unknown id, a wrong nonce, an old answer — is ignored.
func (n *NtfyApprover) answer(msg string) {
	fields := strings.Fields(msg)
	if len(fields) != 3 {
		return
	}
	choice, id, nonce := Choice(fields[0]), fields[1], fields[2]
	n.mu.Lock()
	entry, ok := n.pending[id]
	n.mu.Unlock()
	if !ok || subtle.ConstantTimeCompare([]byte(nonce), []byte(entry.nonce)) != 1 {
		return
	}
	v := Verdict{Decision: policy.Decision{Action: policy.ActionDeny, Reason: "rejected on the phone"}}
	switch choice {
	case ChoiceAllow:
		v = Verdict{Decision: policy.Decision{Action: policy.ActionAllow, Reason: "approved on the phone"}}
	case ChoiceAllowSession:
		v = Verdict{Decision: policy.Decision{Action: policy.ActionAllow, Reason: "approved on the phone for the rest of the session"}, Session: true}
	case ChoiceDeny:
	default:
		return
	}
	select {
	case entry.answer <- v:
	default:
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return hex.EncodeToString(b)
}

// FanoutApprover puts the question to every channel at once — the web UI,
// the terminal, the phone — and takes the first answer; the other channels
// are withdrawn. A channel that cannot ask at all (an error) is skipped.
type FanoutApprover []Approver

// Approve asks everyone and returns the first answer.
func (f FanoutApprover) Approve(ctx context.Context, req ApprovalRequest) (Verdict, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		v   Verdict
		err error
	}
	answers := make(chan result, len(f))
	asked := 0
	for _, a := range f {
		if a == nil {
			continue
		}
		asked++
		go func(a Approver) {
			v, err := a.Approve(ctx, req)
			answers <- result{v, err}
		}(a)
	}
	var last error
	for range asked {
		r := <-answers
		if r.err == nil {
			return r.v, nil
		}
		last = r.err
	}
	if last == nil {
		last = errors.New("no approver available")
	}
	return Verdict{}, last
}

// pendingIDs lists the questions waiting for an answer, for tests.
func (n *NtfyApprover) pendingIDs() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]string, 0, len(n.pending))
	for id := range n.pending {
		out = append(out, id)
	}
	return out
}
