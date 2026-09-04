package audit

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// Placeholder replaces anything a redaction pattern matched.
const Placeholder = "[REDACTED]"

// Redactor applies the configured patterns to a JSON document before it is
// written to the audit store.
//
// Patterns are applied in two places, which is what makes a single pattern like
//
//	(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S+
//
// do the obvious thing in both of these documents:
//
//	{"api_key": "sk-live-1234"}          -> {"api_key": "[REDACTED]"}
//	{"command": "curl -H token=abc123"}  -> {"command": "curl -H [REDACTED]"}
//
// For the first, the pattern is tested against a synthetic "key: value" probe
// for every object member; a hit replaces the whole value. For the second, the
// pattern is applied to the string itself and only the match is replaced.
// Object keys are never rewritten, so the result stays readable and stays valid
// JSON — which a plain regex over the serialized document could not promise.
type Redactor struct {
	patterns []*regexp.Regexp
}

// NewRedactor returns a Redactor for the given patterns. A Redactor with no
// patterns passes documents through unchanged.
func NewRedactor(patterns []*regexp.Regexp) *Redactor {
	return &Redactor{patterns: patterns}
}

// Enabled reports whether any pattern is configured.
func (r *Redactor) Enabled() bool { return r != nil && len(r.patterns) > 0 }

// Redact rewrites a JSON document. Input that does not parse as JSON is treated
// as plain text and still redacted.
func (r *Redactor) Redact(raw []byte) []byte {
	if !r.Enabled() || len(bytes.TrimSpace(raw)) == 0 {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return []byte(r.RedactString(string(raw)))
	}
	out, err := json.Marshal(r.redactValue(v))
	if err != nil {
		return raw
	}
	return out
}

// RedactString applies the patterns to a plain string, replacing each match.
func (r *Redactor) RedactString(s string) string {
	if !r.Enabled() || s == "" {
		return s
	}
	for _, re := range r.patterns {
		s = re.ReplaceAllString(s, Placeholder)
	}
	return s
}

func (r *Redactor) redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			if scalar, ok := scalarString(child); ok && r.keyMatches(k, scalar) {
				out[k] = Placeholder
				continue
			}
			out[k] = r.redactValue(child)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = r.redactValue(child)
		}
		return out
	case string:
		return r.RedactString(t)
	default:
		return v
	}
}

// keyMatches tests the patterns against "key: value" and "key=value" probes, so
// that a pattern written for config-file syntax also catches a JSON member.
//
// The match has to start at the beginning of the probe, which is what makes it
// a statement about the key. Without that anchor, {"command": "curl -H
// token=abc"} would lose its whole command, because the pattern matches
// somewhere inside the value. Values are still scrubbed on their own afterwards
// — there the pattern is allowed to match anywhere, and only the match is
// replaced.
func (r *Redactor) keyMatches(key, value string) bool {
	if value == "" {
		return false
	}
	probes := [2]string{key + ": " + value, key + "=" + value}
	for _, re := range r.patterns {
		for _, probe := range probes {
			if loc := re.FindStringIndex(probe); loc != nil && loc[0] == 0 {
				return true
			}
		}
	}
	return false
}

// scalarString renders a JSON scalar for the key probe. Objects and arrays
// return false: they are walked instead.
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	}
	return "", false
}

// Truncate caps a document at max bytes. It reports whether it had to cut, and
// keeps the output valid JSON by wrapping the cut text in an object rather than
// slicing the document in half.
func Truncate(raw []byte, max int) ([]byte, bool) {
	if max <= 0 || len(raw) <= max {
		return raw, false
	}
	head := string(raw[:max])
	if !utf8Safe(head) {
		head = strings.ToValidUTF8(head, "")
	}
	out, err := json.Marshal(map[string]any{
		"_agentgate_truncated": true,
		"_agentgate_bytes":     len(raw),
		"head":                 head,
	})
	if err != nil {
		return raw[:max], true
	}
	return out, true
}

func utf8Safe(s string) bool { return strings.ToValidUTF8(s, "") == s }
