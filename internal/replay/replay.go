// Package replay re-runs a recorded session: either against the current policy
// only (a dry run, which answers "what would this policy have done yesterday?")
// or against the current upstreams as well.
package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// Forwarder sends a call to the live upstreams and returns the result as JSON,
// so that replay can hash it the same way the audit log did.
type Forwarder interface {
	ForwardJSON(ctx context.Context, tool string, args json.RawMessage) (json.RawMessage, error)
}

// Options control a replay.
type Options struct {
	// Policy is evaluated against every recorded call. Required.
	Policy *policy.Policy
	// OnlyAllowed skips calls that were denied when they were recorded.
	OnlyAllowed bool
	// Forwarder re-sends allowed calls. Nil means a dry run.
	Forwarder Forwarder
	// Host is the client that opened the recorded session, for host.*
	// conditions.
	Host policy.Host
	// Annotations returns what the servers said about their tools in the
	// catalog a call was made under, keyed by exposed tool name, for
	// annotations.* conditions. Nil means nothing is known.
	Annotations func(catalogHash string) map[string]policy.Annotations
}

// Entry is one recorded call, re-evaluated and possibly re-sent.
type Entry struct {
	Call *audit.Call `json:"call"`
	// Was is the decision recorded at the time.
	Was policy.Decision `json:"was"`
	// Now is the decision the current policy reaches.
	Now policy.Decision `json:"now"`
	// Skipped is set when OnlyAllowed filtered the call out.
	Skipped bool `json:"skipped,omitempty"`
	// Sent reports whether the call was actually re-sent upstream.
	Sent bool `json:"sent"`
	// ResultHash is the hash of the fresh result, when the call was re-sent.
	ResultHash string `json:"result_hash,omitempty"`
	// Error is a failure from the fresh call.
	Error string `json:"error,omitempty"`
	// DurationMS is how long the fresh call took.
	DurationMS int64 `json:"duration_ms,omitempty"`
	// Labels are the labels the session earns with this call under the
	// current policy.
	Labels []string `json:"labels,omitempty"`
}

// DecisionChanged reports whether the current policy disagrees with what was
// recorded. This is the line "replay --dry-run" is really about.
func (e *Entry) DecisionChanged() bool { return e.Was.Action != e.Now.Action }

// ResultChanged reports whether a re-sent call produced a different result than
// the recorded one. It is false for calls that were not re-sent, and for calls
// whose recorded result was truncated and cannot be compared.
func (e *Entry) ResultChanged() bool {
	if !e.Sent || e.ResultHash == "" || e.Call.ResultHash == "" || e.Call.ResultTruncated {
		return false
	}
	return e.ResultHash != e.Call.ResultHash
}

// Report is the outcome of a replay.
type Report struct {
	SessionID string   `json:"session_id"`
	Entries   []*Entry `json:"entries"`
	DryRun    bool     `json:"dry_run"`
}

// Changed returns the entries whose decision differs from the recorded one.
func (r *Report) Changed() []*Entry {
	var out []*Entry
	for _, e := range r.Entries {
		if e.DecisionChanged() {
			out = append(out, e)
		}
	}
	return out
}

// Counts summarises a report for the CLI footer.
func (r *Report) Counts() (allowed, denied, changed, failed int) {
	for _, e := range r.Entries {
		switch e.Now.Action {
		case policy.ActionAllow:
			allowed++
		default:
			denied++
		}
		if e.DecisionChanged() {
			changed++
		}
		if e.Error != "" {
			failed++
		}
	}
	return
}

// Run replays the calls in order.
//
// The session is simulated as the walk proceeds, the way the proxy tracks a
// live one: budgets, the rate limit, the loop guard, labels and the list of
// tools called all build up call by call. A policy that adds a budget shows up
// in a dry run exactly where the session would have run out, and one that
// adds a label rule changes the decisions after the call that earns it.
//
// A call counts as having gone through when the current policy allows it, or
// asks and the call went through at the time: the human who approved it then
// is taken to approve it again.
func Run(ctx context.Context, sessionID string, calls []*audit.Call, opts Options) (*Report, error) {
	if opts.Policy == nil {
		return nil, errors.New("replay: no policy to evaluate against")
	}
	report := &Report{SessionID: sessionID, DryRun: opts.Forwarder == nil}
	var track policy.Tracker

	for _, rec := range calls {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		entry := &Entry{
			Call: rec,
			Was:  policy.Decision{Action: rec.Decision, Reason: rec.Reason, RuleID: rec.RuleID},
		}
		if opts.OnlyAllowed && rec.Decision != policy.ActionAllow {
			entry.Skipped = true
			entry.Now = entry.Was
			report.Entries = append(report.Entries, entry)
			continue
		}

		call := &policy.Call{
			Tool:     rec.Tool,
			Upstream: rec.Upstream,
			ToolName: toolName(rec),
			Args:     decodeArgs(rec.Args),
			Counts:   track.Observe(rec.Tool, rec.Tool+"\x00"+rec.ArgsHash, rec.TS),
			At:       rec.TS,
			Host:     opts.Host,
			Session:  track.History(),
		}
		if opts.Annotations != nil {
			call.Annotations = opts.Annotations(rec.CatalogHash)[rec.Tool]
		}
		entry.Now = policy.Evaluate(opts.Policy, call)

		result := rec.Result
		if opts.Forwarder != nil && entry.Now.Action == policy.ActionAllow {
			started := time.Now()
			raw, err := opts.Forwarder.ForwardJSON(ctx, rec.Tool, rec.Args)
			entry.DurationMS = time.Since(started).Milliseconds()
			entry.Sent = true
			if err != nil {
				entry.Error = err.Error()
				result = nil
			} else {
				entry.ResultHash = audit.Hash(raw)
				result = raw
			}
		}

		wentThrough := entry.Now.Action == policy.ActionAllow ||
			(entry.Now.Action == policy.ActionAsk && rec.Decision == policy.ActionAllow)
		if wentThrough {
			var labels []string
			if len(opts.Policy.Labels) > 0 {
				if opts.Policy.LabelsReadResult() {
					call.Result = policy.ResultFromJSON(result)
				}
				labels = policy.LabelsFor(opts.Policy, call)
			}
			track.Forwarded(call, rec.TokensEst, rec.TS)
			entry.Labels = track.Earn(labels...)
		}
		report.Entries = append(report.Entries, entry)
	}
	return report, nil
}

// toolName recovers the upstream-local tool name from a recorded call. The
// audit log stores the exposed name; stripping the upstream prefix is enough
// because that is exactly how the name was built.
func toolName(rec *audit.Call) string {
	if rec.Upstream == "" {
		return rec.Tool
	}
	for _, sep := range []string{"__", ".", "/", ":"} {
		prefix := rec.Upstream + sep
		if len(rec.Tool) > len(prefix) && rec.Tool[:len(prefix)] == prefix {
			return rec.Tool[len(prefix):]
		}
	}
	return rec.Tool
}

// decodeArgs mirrors what the proxy does on the live path, numbers included,
// so a replayed decision is the decision the proxy would have reached.
func decodeArgs(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var args map[string]any
	if err := dec.Decode(&args); err != nil {
		return nil
	}
	return args
}
