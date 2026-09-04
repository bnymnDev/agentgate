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

// ErrNotFound is returned when a session or call id does not resolve.
var ErrNotFound = errors.New("not found")

// SessionFilter narrows a session listing.
type SessionFilter struct {
	// Since keeps sessions started at or after this time. Zero means all.
	Since time.Time
	// Limit caps the number of rows. Zero means 200.
	Limit int
}

// ListSessions returns sessions newest first, with call and denial counts.
func (s *Store) ListSessions(ctx context.Context, f SessionFilter) ([]*Session, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	args := []any{}
	where := ""
	if !f.Since.IsZero() {
		where = "WHERE s.started_at >= ?"
		args = append(args, f.Since.UnixMilli())
	}
	args = append(args, limit)
	q := fmt.Sprintf(`
		SELECT s.id, s.started_at, s.ended_at, s.host_name, s.host_version, s.downstream_transport,
		       (SELECT COUNT(*) FROM calls c WHERE c.session_id = s.id),
		       (SELECT COUNT(*) FROM calls c WHERE c.session_id = s.id AND c.decision = 'deny')
		FROM sessions s %s
		ORDER BY s.started_at DESC, s.id DESC
		LIMIT ?`, where)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanSession(sc scanner) (*Session, error) {
	var (
		sess    Session
		started int64
		ended   sql.NullInt64
	)
	if err := sc.Scan(&sess.ID, &started, &ended, &sess.HostName, &sess.HostVersion,
		&sess.DownstreamTransport, &sess.Calls, &sess.Denied); err != nil {
		return nil, err
	}
	sess.StartedAt = time.UnixMilli(started)
	if ended.Valid {
		t := time.UnixMilli(ended.Int64)
		sess.EndedAt = &t
	}
	return &sess, nil
}

// GetSession resolves a session by full id or by unique prefix, which is what
// makes "agentgate show 01JD" work from a terminal.
func (s *Store) GetSession(ctx context.Context, id string) (*Session, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.id, s.started_at, s.ended_at, s.host_name, s.host_version, s.downstream_transport,
		       (SELECT COUNT(*) FROM calls c WHERE c.session_id = s.id),
		       (SELECT COUNT(*) FROM calls c WHERE c.session_id = s.id AND c.decision = 'deny')
		FROM sessions s
		WHERE s.id = ? OR s.id LIKE ? ESCAPE '\'
		ORDER BY s.started_at DESC
		LIMIT 2`, id, likePrefix(id))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var found []*Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		found = append(found, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("session %q: %w", id, ErrNotFound)
	case 1:
		return found[0], nil
	default:
		if found[0].ID == id {
			return found[0], nil
		}
		return nil, fmt.Errorf("session prefix %q is ambiguous", id)
	}
}

// CallFilter narrows a call listing.
type CallFilter struct {
	SessionID string
	// Decision keeps only calls with this decision. Empty means all.
	Decision policy.Action
	// Tool keeps only calls whose tool name contains this substring.
	Tool string
	// AfterID keeps only calls whose id sorts after this one. Ids are ULIDs,
	// so this is "everything newer than the last thing I saw" — what tail uses.
	AfterID string
	// Since keeps only calls made at or after this time.
	Since time.Time
	// RuleID keeps only calls decided by this rule id.
	RuleID string
	Limit  int
}

// ListCalls returns the calls of a session in the order they were made.
func (s *Store) ListCalls(ctx context.Context, f CallFilter) ([]*Call, error) {
	var (
		conds []string
		args  []any
	)
	if f.SessionID != "" {
		conds = append(conds, "session_id = ?")
		args = append(args, f.SessionID)
	}
	if f.Decision != "" {
		conds = append(conds, "decision = ?")
		args = append(args, string(f.Decision))
	}
	if f.Tool != "" {
		conds = append(conds, `tool LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(f.Tool)+"%")
	}
	if f.AfterID != "" {
		conds = append(conds, "id > ?")
		args = append(args, f.AfterID)
	}
	if !f.Since.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, f.Since.UnixMilli())
	}
	if f.RuleID != "" {
		conds = append(conds, "rule_id = ?")
		args = append(args, f.RuleID)
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 5000
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT id, session_id, ts, upstream, tool, args_json, args_hash, decision, rule_id,
		       reason, result_json, result_hash, is_error, duration_ms, tokens_est,
		       result_truncated, error, shadow
		FROM calls %s ORDER BY ts ASC, id ASC LIMIT ?`, where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Call
	for rows.Next() {
		c, err := scanCall(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCall looks up a single call by id.
func (s *Store) GetCall(ctx context.Context, id string) (*Call, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, session_id, ts, upstream, tool, args_json, args_hash, decision, rule_id,
		       reason, result_json, result_hash, is_error, duration_ms, tokens_est,
		       result_truncated, error, shadow
		FROM calls WHERE id = ?`, id)
	c, err := scanCall(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("call %q: %w", id, ErrNotFound)
	}
	return c, err
}

func scanCall(sc scanner) (*Call, error) {
	var (
		c          Call
		ts         int64
		argsJSON   string
		resultJSON string
		decision   string
		isErr      int
		truncated  int
		shadow     int
	)
	if err := sc.Scan(&c.ID, &c.SessionID, &ts, &c.Upstream, &c.Tool, &argsJSON, &c.ArgsHash,
		&decision, &c.RuleID, &c.Reason, &resultJSON, &c.ResultHash, &isErr,
		&c.DurationMS, &c.TokensEst, &truncated, &c.Error, &shadow); err != nil {
		return nil, err
	}
	c.TS = time.UnixMilli(ts)
	c.Decision = policy.Action(decision)
	c.IsError = isErr != 0
	c.ResultTruncated = truncated != 0
	c.Shadow = shadow != 0
	if argsJSON != "" {
		c.Args = json.RawMessage(argsJSON)
	}
	if resultJSON != "" {
		c.Result = json.RawMessage(resultJSON)
	}
	return &c, nil
}

// Stats is the headline the web UI shows above the session list.
type Stats struct {
	Sessions  int `json:"sessions"`
	Calls     int `json:"calls"`
	Denied    int `json:"denied"`
	Shadowed  int `json:"shadowed"`
	Honeypots int `json:"honeypots"`
	Errors    int `json:"errors"`
	Tokens    int `json:"tokens_est"`
}

// Stats aggregates the database, or the part of it since a time.
func (s *Store) Stats(ctx context.Context, since time.Time) (*Stats, error) {
	var st Stats
	cut := int64(0)
	if !since.IsZero() {
		cut = since.UnixMilli()
	}
	err := s.db.QueryRowContext(ctx, `
		SELECT (SELECT COUNT(*) FROM sessions WHERE started_at >= ?),
		       (SELECT COUNT(*) FROM calls WHERE ts >= ?),
		       (SELECT COUNT(*) FROM calls WHERE ts >= ? AND decision = 'deny' AND shadow = 0),
		       (SELECT COUNT(*) FROM calls WHERE ts >= ? AND shadow = 1),
		       (SELECT COUNT(*) FROM calls WHERE ts >= ? AND rule_id = ?),
		       (SELECT COUNT(*) FROM calls WHERE ts >= ? AND is_error = 1 AND decision = 'allow'),
		       (SELECT COALESCE(SUM(tokens_est), 0) FROM calls WHERE ts >= ?)`,
		cut, cut, cut, cut, cut, policy.RuleHoneypot, cut, cut).
		Scan(&st.Sessions, &st.Calls, &st.Denied, &st.Shadowed, &st.Honeypots, &st.Errors, &st.Tokens)
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// ToolStat is one row of the per-tool breakdown.
type ToolStat struct {
	Tool      string    `json:"tool"`
	Upstream  string    `json:"upstream"`
	Calls     int       `json:"calls"`
	Allowed   int       `json:"allowed"`
	Denied    int       `json:"denied"`
	Asked     int       `json:"asked"`
	Errors    int       `json:"errors"`
	AvgMS     float64   `json:"avg_ms"`
	Tokens    int       `json:"tokens_est"`
	LastRule  string    `json:"last_rule,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// ToolStats breaks the calls since a time down by tool, busiest first.
func (s *Store) ToolStats(ctx context.Context, since time.Time, sessionID string) ([]*ToolStat, error) {
	var (
		conds []string
		args  []any
	)
	if !since.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, since.UnixMilli())
	}
	if sessionID != "" {
		conds = append(conds, "session_id = ?")
		args = append(args, sessionID)
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT tool, MAX(upstream), COUNT(*),
		       SUM(CASE WHEN decision = 'allow' OR shadow = 1 THEN 1 ELSE 0 END),
		       SUM(CASE WHEN decision = 'deny' AND shadow = 0 THEN 1 ELSE 0 END),
		       SUM(CASE WHEN decision = 'ask' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN is_error = 1 AND decision = 'allow' THEN 1 ELSE 0 END),
		       AVG(CASE WHEN decision = 'allow' THEN duration_ms END),
		       COALESCE(SUM(tokens_est), 0),
		       MIN(ts), MAX(ts)
		FROM calls %s
		GROUP BY tool
		ORDER BY COUNT(*) DESC, tool ASC`, where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ToolStat
	for rows.Next() {
		var (
			st          ToolStat
			avg         sql.NullFloat64
			first, last int64
		)
		if err := rows.Scan(&st.Tool, &st.Upstream, &st.Calls, &st.Allowed, &st.Denied, &st.Asked,
			&st.Errors, &avg, &st.Tokens, &first, &last); err != nil {
			return nil, err
		}
		st.AvgMS = avg.Float64
		st.FirstSeen = time.UnixMilli(first)
		st.LastSeen = time.UnixMilli(last)
		out = append(out, &st)
	}
	return out, rows.Err()
}

// RuleStat counts how often a rule decided something.
type RuleStat struct {
	RuleID   string        `json:"rule_id"`
	Decision policy.Action `json:"decision"`
	Calls    int           `json:"calls"`
}

// RuleStats lists the rules that fired since a time, most active first.
func (s *Store) RuleStats(ctx context.Context, since time.Time, sessionID string) ([]*RuleStat, error) {
	conds := []string{"rule_id != ''"}
	var args []any
	if !since.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, since.UnixMilli())
	}
	if sessionID != "" {
		conds = append(conds, "session_id = ?")
		args = append(args, sessionID)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT rule_id, decision, COUNT(*) FROM calls WHERE `+strings.Join(conds, " AND ")+`
		GROUP BY rule_id, decision ORDER BY COUNT(*) DESC, rule_id ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RuleStat
	for rows.Next() {
		var (
			st       RuleStat
			decision string
		)
		if err := rows.Scan(&st.RuleID, &decision, &st.Calls); err != nil {
			return nil, err
		}
		st.Decision = policy.Action(decision)
		out = append(out, &st)
	}
	return out, rows.Err()
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func likePrefix(s string) string { return escapeLike(s) + "%" }
