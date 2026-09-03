package replay

import (
	"github.com/bnymnDev/agentgate/internal/audit"
)

// Status is how a pair of calls relates across two sessions.
type Status string

const (
	// StatusSame means same tool, same arguments, same result.
	StatusSame Status = "same"
	// StatusResult means same tool and arguments, different result.
	StatusResult Status = "result"
	// StatusArgs means same tool, different arguments.
	StatusArgs Status = "args"
	// StatusOnlyA means the call happened only in the first session.
	StatusOnlyA Status = "only-a"
	// StatusOnlyB means the call happened only in the second session.
	StatusOnlyB Status = "only-b"
	// StatusDecision means the call was allowed in one session and not the other.
	StatusDecision Status = "decision"
)

// Row is one line of a session diff.
type Row struct {
	Status Status      `json:"status"`
	A      *audit.Call `json:"a,omitempty"`
	B      *audit.Call `json:"b,omitempty"`
	Tool   string      `json:"tool"`
}

// Diff is the comparison of two recorded sessions.
type Diff struct {
	SessionA string `json:"session_a"`
	SessionB string `json:"session_b"`
	Rows     []Row  `json:"rows"`
}

// Summary counts the rows by status.
func (d *Diff) Summary() map[Status]int {
	out := map[Status]int{}
	for _, r := range d.Rows {
		out[r.Status]++
	}
	return out
}

// Identical reports whether the two sessions did the same things with the same
// arguments and got the same answers.
func (d *Diff) Identical() bool {
	for _, r := range d.Rows {
		if r.Status != StatusSame {
			return false
		}
	}
	return true
}

// Compare aligns two recorded sessions and classifies every call.
//
// The alignment is a longest-common-subsequence over the tool names, which is
// what makes an inserted or removed call show up as one row instead of pushing
// everything after it out of step.
func Compare(sessionA, sessionB string, a, b []*audit.Call) *Diff {
	d := &Diff{SessionA: sessionA, SessionB: sessionB}
	for _, pair := range align(a, b) {
		d.Rows = append(d.Rows, classify(pair.a, pair.b))
	}
	return d
}

type pair struct {
	a, b *audit.Call
}

// align pairs up calls with a classic LCS table over tool names.
func align(a, b []*audit.Call) []pair {
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i].Tool == b[j].Tool {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []pair
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i].Tool == b[j].Tool:
			out = append(out, pair{a[i], b[j]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, pair{a: a[i]})
			i++
		default:
			out = append(out, pair{b: b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, pair{a: a[i]})
	}
	for ; j < m; j++ {
		out = append(out, pair{b: b[j]})
	}
	return out
}

func classify(a, b *audit.Call) Row {
	switch {
	case a == nil:
		return Row{Status: StatusOnlyB, B: b, Tool: b.Tool}
	case b == nil:
		return Row{Status: StatusOnlyA, A: a, Tool: a.Tool}
	}
	row := Row{A: a, B: b, Tool: a.Tool}
	switch {
	case a.Decision != b.Decision:
		row.Status = StatusDecision
	case a.ArgsHash != b.ArgsHash:
		row.Status = StatusArgs
	case a.ResultHash != b.ResultHash:
		row.Status = StatusResult
	default:
		row.Status = StatusSame
	}
	return row
}
