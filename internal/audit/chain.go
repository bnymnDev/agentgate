package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The audit log is a hash chain. Every call row carries a sequence number,
// the hash of the row before it, and its own hash over both that link and
// every column it stores. Editing a stored row changes its hash; deleting one
// leaves a gap in the sequence; either breaks every link after it. Only the
// end of the chain can be cut off unnoticed, which is why `agentgate verify`
// prints the head: write it down somewhere else, and a later verify with
// --anchor proves nothing up to that point was touched.

// Link identifies one position in the chain.
type Link struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

// String renders a link the way --anchor takes it: "seq:hash".
func (l Link) String() string { return fmt.Sprintf("%d:%s", l.Seq, l.Hash) }

// ParseLink reads a link written as "seq:hash".
func ParseLink(s string) (Link, error) {
	seqStr, hash, ok := strings.Cut(strings.TrimSpace(s), ":")
	var l Link
	if !ok || hash == "" {
		return l, fmt.Errorf("anchor %q: want seq:hash, as verify prints it", s)
	}
	if _, err := fmt.Sscanf(seqStr, "%d", &l.Seq); err != nil || l.Seq <= 0 {
		return l, fmt.Errorf("anchor %q: the sequence number must be a positive integer", s)
	}
	l.Hash = strings.ToLower(hash)
	return l, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// chainHead returns the last link: the newest chained call, or the anchor
// retention left behind, or the zero link for an empty chain.
func chainHead(ctx context.Context, q querier) (Link, error) {
	var l Link
	err := q.QueryRowContext(ctx,
		`SELECT seq, row_hash FROM calls WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1`).Scan(&l.Seq, &l.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		err = q.QueryRowContext(ctx, `SELECT seq, hash FROM chain_anchor WHERE id = 1`).Scan(&l.Seq, &l.Hash)
		if errors.Is(err, sql.ErrNoRows) {
			return Link{}, nil
		}
	}
	return l, err
}

// chainRow is what a row hash covers: every stored column, in a fixed order,
// with the values exactly as stored.
type chainRow struct {
	Seq             int64  `json:"seq"`
	ID              string `json:"id"`
	SessionID       string `json:"session_id"`
	TS              int64  `json:"ts"`
	Upstream        string `json:"upstream"`
	Tool            string `json:"tool"`
	Args            string `json:"args_json"`
	ArgsHash        string `json:"args_hash"`
	Decision        string `json:"decision"`
	RuleID          string `json:"rule_id"`
	Reason          string `json:"reason"`
	Result          string `json:"result_json"`
	ResultHash      string `json:"result_hash"`
	IsError         bool   `json:"is_error"`
	DurationMS      int64  `json:"duration_ms"`
	TokensEst       int    `json:"tokens_est"`
	ResultTruncated bool   `json:"result_truncated"`
	Error           string `json:"error"`
	Shadow          bool   `json:"shadow"`
	Labels          string `json:"labels"`
	CatalogHash     string `json:"catalog_hash"`
}

// rowHash is sha256(prev_hash "\n" row), hex encoded.
func rowHash(c *Call) string {
	row, _ := json.Marshal(chainRow{
		Seq: c.Seq, ID: c.ID, SessionID: c.SessionID, TS: c.TS.UnixMilli(),
		Upstream: c.Upstream, Tool: c.Tool, Args: string(c.Args), ArgsHash: c.ArgsHash,
		Decision: string(c.Decision), RuleID: c.RuleID, Reason: c.Reason,
		Result: string(c.Result), ResultHash: c.ResultHash, IsError: c.IsError,
		DurationMS: c.DurationMS, TokensEst: c.TokensEst, ResultTruncated: c.ResultTruncated,
		Error: c.Error, Shadow: c.Shadow, Labels: strings.Join(c.Labels, ","), CatalogHash: c.CatalogHash,
	})
	h := sha256.New()
	h.Write([]byte(c.PrevHash))
	h.Write([]byte{'\n'})
	h.Write(row)
	return hex.EncodeToString(h.Sum(nil))
}

// ChainProblem is one place where the chain does not hold.
type ChainProblem struct {
	Seq    int64  `json:"seq"`
	CallID string `json:"call_id,omitempty"`
	What   string `json:"what"`
}

// VerifyReport is the outcome of walking the chain.
type VerifyReport struct {
	// Checked is the number of chained calls verified.
	Checked int64 `json:"checked"`
	// Legacy counts calls written before the chain existed. They cannot be
	// verified and are not part of it.
	Legacy int64 `json:"legacy"`
	// Anchor is where retention cut the chain, if it has.
	Anchor *Link `json:"anchor,omitempty"`
	// Head is the newest link.
	Head Link `json:"head"`
	// Problems lists every break found. Empty means the chain holds.
	Problems []ChainProblem `json:"problems,omitempty"`
	// AnchorChecked reports that an anchor given to Verify was found intact.
	AnchorChecked bool `json:"anchor_checked,omitempty"`
}

// OK reports whether the chain verified.
func (r *VerifyReport) OK() bool { return len(r.Problems) == 0 }

// Verify walks the whole chain and reports every break in it. When expect is
// set, it also checks that the chain still passes through that link — which
// catches a chain that was cut short and regrown since the link was noted.
func (s *Store) Verify(ctx context.Context, expect *Link) (*VerifyReport, error) {
	report := &VerifyReport{}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM calls WHERE seq IS NULL`).Scan(&report.Legacy); err != nil {
		return nil, err
	}
	var anchor Link
	err := s.db.QueryRowContext(ctx, `SELECT seq, hash FROM chain_anchor WHERE id = 1`).Scan(&anchor.Seq, &anchor.Hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return nil, err
	default:
		report.Anchor = &anchor
	}
	prev := anchor
	report.Head = anchor
	if expect != nil && report.Anchor != nil && *expect == anchor {
		report.AnchorChecked = true
	}

	rows, err := s.db.QueryContext(ctx, `SELECT `+callColumns+` FROM calls WHERE seq IS NOT NULL ORDER BY seq ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		c, err := scanCall(rows)
		if err != nil {
			return nil, err
		}
		report.Checked++
		if c.Seq != prev.Seq+1 {
			if c.Seq <= prev.Seq {
				report.Problems = append(report.Problems, ChainProblem{Seq: c.Seq, CallID: c.ID,
					What: fmt.Sprintf("sequence number %d does not follow %d", c.Seq, prev.Seq)})
			} else {
				report.Problems = append(report.Problems, ChainProblem{Seq: prev.Seq + 1,
					What: fmt.Sprintf("%d call(s) missing before seq %d: rows were deleted", c.Seq-prev.Seq-1, c.Seq)})
			}
		}
		if c.PrevHash != prev.Hash {
			report.Problems = append(report.Problems, ChainProblem{Seq: c.Seq, CallID: c.ID,
				What: "does not link to the call before it"})
		}
		if got := rowHash(c); got != c.RowHash {
			report.Problems = append(report.Problems, ChainProblem{Seq: c.Seq, CallID: c.ID,
				What: "was changed after it was written: its contents no longer match its hash"})
		}
		if expect != nil && c.Seq == expect.Seq {
			if c.RowHash == expect.Hash {
				report.AnchorChecked = true
			} else {
				report.Problems = append(report.Problems, ChainProblem{Seq: c.Seq, CallID: c.ID,
					What: "is not the call the anchor names: the chain was rewritten from here on"})
			}
		}
		prev = Link{Seq: c.Seq, Hash: c.RowHash}
		report.Head = prev
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if expect != nil && !report.AnchorChecked && !hasProblemAt(report, expect.Seq) {
		switch {
		case report.Anchor != nil && expect.Seq <= report.Anchor.Seq:
			report.Problems = append(report.Problems, ChainProblem{Seq: expect.Seq,
				What: fmt.Sprintf("the anchor is older than the retention cut at seq %d and can no longer be checked", report.Anchor.Seq)})
		default:
			report.Problems = append(report.Problems, ChainProblem{Seq: expect.Seq,
				What: fmt.Sprintf("the chain ends at seq %d and no longer reaches the anchor: calls were removed from its end", report.Head.Seq)})
		}
	}
	return report, nil
}

func hasProblemAt(r *VerifyReport, seq int64) bool {
	for _, p := range r.Problems {
		if p.Seq == seq {
			return true
		}
	}
	return false
}

// Head returns the newest link of the chain without walking it.
func (s *Store) Head(ctx context.Context) (Link, error) {
	return chainHead(ctx, s.db)
}

// PrunedAt reports when retention last cut the chain, if it has.
func (s *Store) PrunedAt(ctx context.Context) (time.Time, bool, error) {
	var ms int64
	err := s.db.QueryRowContext(ctx, `SELECT pruned_at FROM chain_anchor WHERE id = 1`).Scan(&ms)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return time.UnixMilli(ms), true, nil
}
