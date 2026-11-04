// Package behavior pins what a tool does, not only what it says. Pinning a
// definition catches a server that changes its description; it cannot catch
// one that keeps its description and changes what it does — a read tool that
// suddenly returns forty times as much, takes a new argument, or starts
// earning the session labels it never did. A profile learned from the audit
// log is what normal looked like, and a call far outside it is an anomaly.
package behavior

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"time"

	"github.com/bnymnDev/agentgate/internal/audit"
)

// Profile is what every tool looked like over a stretch of the audit log.
type Profile struct {
	Version   int                     `json:"version"`
	LearnedAt time.Time               `json:"learned_at"`
	From      time.Time               `json:"from"`
	To        time.Time               `json:"to"`
	Tools     map[string]*ToolProfile `json:"tools"`
}

// ToolProfile is one tool's normal.
type ToolProfile struct {
	Calls       int      `json:"calls"`
	ResultBytes Spread   `json:"result_bytes"`
	DurationMS  Spread   `json:"duration_ms"`
	ErrorRate   float64  `json:"error_rate"`
	ArgKeys     []string `json:"arg_keys,omitempty"`
	Labels      []string `json:"labels,omitempty"`
}

// Spread is a distribution in three numbers.
type Spread struct {
	P50 int64 `json:"p50"`
	P95 int64 `json:"p95"`
	Max int64 `json:"max"`
}

func spread(vs []int64) Spread {
	if len(vs) == 0 {
		return Spread{}
	}
	slices.Sort(vs)
	at := func(q float64) int64 { return vs[min(len(vs)-1, int(q*float64(len(vs))))] }
	return Spread{P50: at(0.5), P95: at(0.95), Max: vs[len(vs)-1]}
}

// Learn builds a profile from recorded calls. Only calls that reached their
// server count; a denied call says nothing about what the tool does.
func Learn(calls []*audit.Call) *Profile {
	p := &Profile{Version: 1, LearnedAt: time.Now().UTC().Truncate(time.Second), Tools: map[string]*ToolProfile{}}
	type acc struct {
		bytes, ms []int64
		errors    int
		keys      map[string]bool
		labels    map[string]bool
	}
	accs := map[string]*acc{}
	for _, c := range calls {
		if c.Decision != "allow" && !c.Shadow {
			continue
		}
		if p.From.IsZero() || c.TS.Before(p.From) {
			p.From = c.TS
		}
		if c.TS.After(p.To) {
			p.To = c.TS
		}
		a := accs[c.Tool]
		if a == nil {
			a = &acc{keys: map[string]bool{}, labels: map[string]bool{}}
			accs[c.Tool] = a
		}
		a.bytes = append(a.bytes, int64(len(c.Result)))
		a.ms = append(a.ms, c.DurationMS)
		if c.IsError || c.Error != "" {
			a.errors++
		}
		for _, k := range ArgKeys(c.Args) {
			a.keys[k] = true
		}
		for _, l := range c.Labels {
			a.labels[l] = true
		}
	}
	for tool, a := range accs {
		tp := &ToolProfile{Calls: len(a.bytes), ResultBytes: spread(a.bytes), DurationMS: spread(a.ms),
			ErrorRate: float64(a.errors) / float64(len(a.bytes))}
		tp.ArgKeys = sortedKeys(a.keys)
		tp.Labels = sortedKeys(a.labels)
		p.Tools[tool] = tp
	}
	return p
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ArgKeys are the top-level argument names of a call.
func ArgKeys(args json.RawMessage) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(args, &m) != nil {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Load reads a profile; a missing file is no profile.
func Load(path string) (*Profile, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

// Save writes a profile.
func (p *Profile) Save(path string) error {
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644) //nolint:gosec // a profile is meant to be reviewed and committed
}

// Thresholds say how far outside normal is an anomaly.
type Thresholds struct {
	// MinCalls is how many calls a tool needs in the profile before its
	// numbers mean anything.
	MinCalls int
	// Factor is how many times the 95th percentile is too much.
	Factor float64
}

// Anomaly is one way a call is outside its tool's normal.
type Anomaly struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// The kinds of anomaly.
const (
	KindNewArgument = "new-argument"
	KindResultSize  = "result-size"
	KindDuration    = "duration"
	KindNewLabel    = "new-label"
)

// Floors below which nothing is too big or too slow: a tool that answers in
// 3 ms and once in 40 ms is not misbehaving.
const (
	minBytes = 4096
	minMS    = 2000
)

// Before checks what is known before the call is made: its arguments.
func (tp *ToolProfile) Before(args json.RawMessage, th Thresholds) []Anomaly {
	if tp == nil || tp.Calls < th.MinCalls {
		return nil
	}
	var out []Anomaly
	for _, k := range ArgKeys(args) {
		if !slices.Contains(tp.ArgKeys, k) {
			out = append(out, Anomaly{KindNewArgument, fmt.Sprintf("argument %q was never passed in %d calls", k, tp.Calls)})
		}
	}
	return out
}

// After checks what the call did.
func (tp *ToolProfile) After(resultBytes, durationMS int64, labels []string, th Thresholds) []Anomaly {
	if tp == nil || tp.Calls < th.MinCalls {
		return nil
	}
	var out []Anomaly
	if limit := int64(th.Factor * float64(max(tp.ResultBytes.P95, 1))); resultBytes > max(limit, minBytes, tp.ResultBytes.Max) {
		out = append(out, Anomaly{KindResultSize, fmt.Sprintf("returned %d bytes; 95%% of %d calls returned at most %d", resultBytes, tp.Calls, tp.ResultBytes.P95)})
	}
	if limit := int64(th.Factor * float64(max(tp.DurationMS.P95, 1))); durationMS > max(limit, minMS) {
		out = append(out, Anomaly{KindDuration, fmt.Sprintf("took %d ms; 95%% of %d calls took at most %d ms", durationMS, tp.Calls, tp.DurationMS.P95)})
	}
	for _, l := range labels {
		if !slices.Contains(tp.Labels, l) {
			out = append(out, Anomaly{KindNewLabel, fmt.Sprintf("earned the label %s, which it never did in %d calls", l, tp.Calls)})
		}
	}
	return out
}
