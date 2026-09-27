package policy

import (
	"sort"
	"time"
)

// Tracker keeps the part of a session the evaluator reads: the counters
// behind budgets and the loop guard, the labels the session has earned, and
// the tools it has called. The proxy keeps one per downstream session; replay
// keeps one while it walks a recorded session, which is how a replayed
// decision sees the same budgets, streaks and labels the live one did.
//
// A Tracker is not safe for concurrent use; the proxy guards it with the
// session's lock. Like Evaluate it reads no clock: the time of each call is
// passed in.
type Tracker struct {
	calls   int
	perTool map[string]int
	// recent holds the times of forwarded calls in the trailing minute.
	recent []time.Time
	// lastSig and streak drive the loop guard: how many times in a row the
	// identical call has just been made.
	lastSig string
	streak  int
	tokens  int
	labels  []string
	called  []string
	seen    map[string]bool
}

// Observe notes that a call with the given signature (tool plus a hash of its
// arguments) is about to be evaluated, and returns the counters as they stood
// before it. Every evaluated call counts towards the loop guard, denied ones
// included: an agent retrying a denied call is exactly the loop to stop.
func (t *Tracker) Observe(tool, sig string, now time.Time) Counts {
	repeats := 0
	if sig == t.lastSig {
		repeats = t.streak
		t.streak++
	} else {
		t.lastSig = sig
		t.streak = 1
	}
	cutoff := now.Add(-time.Minute)
	keep := t.recent[:0]
	for _, at := range t.recent {
		if at.After(cutoff) {
			keep = append(keep, at)
		}
	}
	t.recent = keep
	return Counts{
		Session:    t.calls,
		Tool:       t.perTool[tool],
		LastMinute: len(t.recent),
		Repeats:    repeats,
		Tokens:     t.tokens,
	}
}

// Forwarded records that call reached its upstream: it counts towards the
// budgets and joins session.called under each of its names.
func (t *Tracker) Forwarded(call *Call, tokens int, now time.Time) {
	if t.perTool == nil {
		t.perTool = map[string]int{}
	}
	t.calls++
	t.perTool[call.Tool]++
	t.recent = append(t.recent, now)
	t.tokens += tokens
	if t.seen == nil {
		t.seen = map[string]bool{}
	}
	for _, name := range call.names() {
		if !t.seen[name] {
			t.seen[name] = true
			t.called = append(t.called, name)
		}
	}
}

// Earn adds labels to the session and returns the ones it did not have yet.
func (t *Tracker) Earn(labels ...string) []string {
	var added []string
	for _, l := range labels {
		i := sort.SearchStrings(t.labels, l)
		if i < len(t.labels) && t.labels[i] == l {
			continue
		}
		t.labels = append(t.labels, "")
		copy(t.labels[i+1:], t.labels[i:])
		t.labels[i] = l
		added = append(added, l)
	}
	return added
}

// History returns a copy of the session's labels and called tools, for a Call.
func (t *Tracker) History() History {
	return History{
		Labels: append([]string(nil), t.labels...),
		Called: append([]string(nil), t.called...),
	}
}

// Calls is the number of calls forwarded so far.
func (t *Tracker) Calls() int { return t.calls }
