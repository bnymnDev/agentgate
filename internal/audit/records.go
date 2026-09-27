package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	// CatalogHash names the tool catalog the session started with; see
	// Store.Catalog.
	CatalogHash string `json:"catalog_hash,omitempty"`

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
	// Labels are the labels the session earned with this call.
	Labels []string `json:"labels,omitempty"`
	// CatalogHash names the tool catalog in force when the call was made.
	CatalogHash string `json:"catalog_hash,omitempty"`

	// Seq, PrevHash and RowHash are the call's link in the hash chain. They
	// are assigned when the row is written; Seq is zero for rows written
	// before the chain existed.
	Seq      int64  `json:"seq,omitempty"`
	PrevHash string `json:"prev_hash,omitempty"`
	RowHash  string `json:"row_hash,omitempty"`
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
		`INSERT INTO sessions (id, started_at, host_name, host_version, downstream_transport, catalog_hash)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.StartedAt.UnixMilli(), sess.HostName, sess.HostVersion, sess.DownstreamTransport, sess.CatalogHash)
	return err
}

// CatalogEntry is one tool of a catalog snapshot: the definition exactly as
// the upstream server sent it, and the name agentgate exposed it under.
type CatalogEntry struct {
	Upstream string          `json:"upstream"`
	Exposed  string          `json:"exposed"`
	Tool     json.RawMessage `json:"tool"`
}

// SaveCatalog stores a tool catalog under its hash, once, and returns the
// hash. It is asynchronous and best effort like every other write; the hash
// is computed up front so the caller can reference the catalog at once.
func (s *Store) SaveCatalog(raw []byte) string {
	hash := Hash(raw)
	if s == nil || hash == "" {
		return hash
	}
	canonical := string(Canonical(raw))
	s.enqueue("catalog", func(ctx context.Context) {
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO catalogs (hash, json, created_at) VALUES (?, ?, ?)`,
			hash, canonical, time.Now().UnixMilli()); err != nil {
			s.log.Warn("audit: cannot record the tool catalog", "error", err)
		}
	})
	return hash
}

// Catalog returns a stored tool catalog by hash.
func (s *Store) Catalog(ctx context.Context, hash string) (json.RawMessage, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT json FROM catalogs WHERE hash = ?`, hash).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("catalog %q: %w", hash, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
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

// insertCall writes a call as the next link of the hash chain. The link is
// read and written in one immediate transaction, which holds SQLite's write
// lock throughout, so several agentgate processes sharing one database still
// build a single chain.
func (s *Store) insertCall(ctx context.Context, c *Call) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	head, err := chainHead(ctx, tx)
	if err != nil {
		return err
	}
	c.Seq = head.Seq + 1
	c.PrevHash = head.Hash
	c.RowHash = rowHash(c)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO calls (id, session_id, ts, upstream, tool, args_json, args_hash,
		                    decision, rule_id, reason, result_json, result_hash,
		                    is_error, duration_ms, tokens_est, result_truncated, error, shadow,
		                    labels, catalog_hash, seq, prev_hash, row_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.SessionID, c.TS.UnixMilli(), c.Upstream, c.Tool, string(c.Args), c.ArgsHash,
		string(c.Decision), c.RuleID, c.Reason, string(c.Result), c.ResultHash,
		boolInt(c.IsError), c.DurationMS, c.TokensEst, boolInt(c.ResultTruncated), c.Error, boolInt(c.Shadow),
		strings.Join(c.Labels, ","), c.CatalogHash, c.Seq, c.PrevHash, c.RowHash); err != nil {
		return err
	}
	return tx.Commit()
}

// Prune applies the retention period: it deletes the calls made before
// cutoff and then every session that started before cutoff and has no calls
// left. It returns the number of sessions deleted.
//
// Calls leave the hash chain from the front only. A call that is still
// within the retention period keeps every later link, even one that is
// older, and the last deleted link becomes the chain's anchor so that what
// remains still verifies.
func (s *Store) Prune(ctx context.Context, cutoff time.Time) (int64, error) {
	cut := cutoff.UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var last sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT CASE
		  WHEN EXISTS (SELECT 1 FROM calls WHERE seq IS NOT NULL AND ts >= ?)
		    THEN (SELECT MIN(seq) FROM calls WHERE seq IS NOT NULL AND ts >= ?) - 1
		  ELSE (SELECT MAX(seq) FROM calls WHERE seq IS NOT NULL)
		END`, cut, cut).Scan(&last); err != nil {
		return 0, err
	}
	if last.Valid && last.Int64 > 0 {
		var hash string
		err := tx.QueryRowContext(ctx, `SELECT row_hash FROM calls WHERE seq = ?`, last.Int64).Scan(&hash)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// Already gone: the anchor is at or past it.
		case err != nil:
			return 0, err
		default:
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO chain_anchor (id, seq, hash, pruned_at) VALUES (1, ?, ?, ?)
				ON CONFLICT (id) DO UPDATE SET seq = excluded.seq, hash = excluded.hash, pruned_at = excluded.pruned_at
				WHERE excluded.seq > chain_anchor.seq`,
				last.Int64, hash, time.Now().UnixMilli()); err != nil {
				return 0, err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM calls WHERE seq IS NOT NULL AND seq <= ?`, last.Int64); err != nil {
				return 0, err
			}
		}
	}
	// Rows from before the chain existed simply go by age, and so do the
	// orphans a database created before foreign keys were enforced may hold.
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM calls
		WHERE seq IS NULL AND (ts < ? OR session_id NOT IN (SELECT id FROM sessions))`, cut); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
		DELETE FROM sessions
		WHERE COALESCE(ended_at, started_at) < ?
		  AND NOT EXISTS (SELECT 1 FROM calls c WHERE c.session_id = sessions.id)`, cut)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM catalogs
		WHERE created_at < ?
		  AND hash NOT IN (SELECT catalog_hash FROM sessions)
		  AND hash NOT IN (SELECT catalog_hash FROM calls)`, cut); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
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
