package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// Session is one downstream connection.
type Session struct {
	ID                  string     `json:"id"`
	StartedAt           time.Time  `json:"started_at"`
	EndedAt             *time.Time `json:"ended_at,omitempty"`
	HostName            string     `json:"host_name,omitempty"`
	HostVersion         string     `json:"host_version,omitempty"`
	DownstreamTransport string     `json:"downstream_transport,omitempty"`

	// Calls and Denied are filled in by the listing queries, not stored.
	Calls  int `json:"calls"`
	Denied int `json:"denied"`
}

// Duration reports how long the session lasted, or how long it has been running.
func (s *Session) Duration() time.Duration {
	if s.EndedAt != nil {
		return s.EndedAt.Sub(s.StartedAt)
	}
	return time.Since(s.StartedAt)
}

// Call is one tools/call request and its outcome.
type Call struct {
	ID         string          `json:"id"`
	SessionID  string          `json:"session_id"`
	TS         time.Time       `json:"ts"`
	Upstream   string          `json:"upstream"`
	Tool       string          `json:"tool"`
	Args       json.RawMessage `json:"args,omitempty"`
	ArgsHash   string          `json:"args_hash,omitempty"`
	Decision   policy.Action   `json:"decision"`
	RuleID     string          `json:"rule_id,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	ResultHash string          `json:"result_hash,omitempty"`
	IsError    bool            `json:"is_error"`
	DurationMS int64           `json:"duration_ms"`
	TokensEst  int             `json:"tokens_est"`
	// ResultTruncated reports that the stored result was capped at the
	// configured size.
	ResultTruncated bool `json:"result_truncated,omitempty"`
	// Error carries a transport level failure (a timeout, a dead upstream).
	Error string `json:"error,omitempty"`
	// Shadow reports that the decision was recorded but not applied: the
	// policy was in shadow mode and the call was forwarded anyway.
	Shadow bool `json:"shadow,omitempty"`
}

// Blocked reports whether the call was actually stopped: a deny that was
// applied, as opposed to one that shadow mode only wrote down.
func (c *Call) Blocked() bool { return c.Decision != policy.ActionAllow && !c.Shadow }

// StartSession records the beginning of a downstream connection. It is
// synchronous: everything else in the session references this row, so it has to
// exist before the first call is written.
func (s *Store) StartSession(ctx context.Context, sess *Session) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, started_at, host_name, host_version, downstream_transport)
		 VALUES (?, ?, ?, ?, ?)`,
		sess.ID, sess.StartedAt.UnixMilli(), sess.HostName, sess.HostVersion, sess.DownstreamTransport)
	return err
}

// EndSession stamps a session as finished. Best effort, like every other write
// on the hot path.
func (s *Store) EndSession(id string, at time.Time) {
	s.enqueue("session_end", func(ctx context.Context) {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE sessions SET ended_at = ? WHERE id = ?`, at.UnixMilli(), id); err != nil {
			s.log.Warn("audit: cannot close session", "session", id, "error", err)
		}
	})
}

// RecordCall queues a call for storage. Arguments and results are redacted and
// hashed on the caller's goroutine so that the record is a snapshot, then the
// insert happens in the background.
func (s *Store) RecordCall(c *Call) {
	if s == nil {
		return
	}
	row := s.prepare(c)
	s.enqueue("call", func(ctx context.Context) {
		if err := s.insertCall(ctx, row); err != nil {
			s.log.Warn("audit: cannot record call", "tool", row.Tool, "error", err)
		}
	})
}

// prepare applies redaction, truncation and hashing. It returns a copy, leaving
// the caller's record untouched.
func (s *Store) prepare(c *Call) *Call {
	out := *c
	if s.redactor.Enabled() {
		out.Args = s.redactor.Redact(out.Args)
		out.Result = s.redactor.Redact(out.Result)
		out.Reason = s.redactor.RedactString(out.Reason)
		out.Error = s.redactor.RedactString(out.Error)
	}
	// Hashes are taken after redaction so that the same call always hashes the
	// same way, whatever the redaction rules were when it ran.
	out.ArgsHash = Hash(out.Args)
	out.ResultHash = Hash(out.Result)
	out.TokensEst = TokensEst(out.Args, out.Result)
	if truncated, cut := Truncate(out.Result, s.maxBytes); cut {
		out.Result = truncated
		out.ResultTruncated = true
	}
	if out.ID == "" {
		out.ID = NewID()
	}
	if out.TS.IsZero() {
		out.TS = time.Now()
	}
	return &out
}

func (s *Store) insertCall(ctx context.Context, c *Call) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO calls (id, session_id, ts, upstream, tool, args_json, args_hash,
		                    decision, rule_id, reason, result_json, result_hash,
		                    is_error, duration_ms, tokens_est, result_truncated, error, shadow)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.SessionID, c.TS.UnixMilli(), c.Upstream, c.Tool, string(c.Args), c.ArgsHash,
		string(c.Decision), c.RuleID, c.Reason, string(c.Result), c.ResultHash,
		boolInt(c.IsError), c.DurationMS, c.TokensEst, boolInt(c.ResultTruncated), c.Error, boolInt(c.Shadow))
	return err
}

// Prune deletes every session that started before cutoff, and its calls.
func (s *Store) Prune(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE started_at < ?`, cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	// Foreign keys are on, but a database created before they were enforced may
	// still hold orphans; clean them up unconditionally.
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM calls WHERE session_id NOT IN (SELECT id FROM sessions)`); err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
