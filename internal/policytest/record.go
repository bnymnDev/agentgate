package policytest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// Recording is a recorded session to turn into a test.
type Recording struct {
	Session *audit.Session
	Calls   []*audit.Call
	// Annotations returns what the servers said about their tools in the
	// catalog a call was made under, keyed by exposed name; nil means
	// nothing is known.
	Annotations func(catalogHash string) map[string]policy.Annotations
}

// notPolicy are the decisions that never came from the policy, so a test of
// the policy cannot reproduce them.
var notPolicy = map[string]string{
	policy.RuleHoneypot:   "a honeypot",
	policy.RuleCanary:     "the canary check",
	policy.RuleQuarantine: "tool pinning",
	policy.RuleFrozen:     "the kill switch",
}

// FromRecordings writes a test file with one test per recorded session:
// every call it made, in order, at the time it was made, expecting the
// decision the policy reached then. Run against a changed policy, it fails
// on exactly the calls the change would decide differently.
func FromRecordings(recs []Recording, now time.Time) (string, error) {
	var b strings.Builder
	var ids []string
	for _, r := range recs {
		ids = append(ids, shortID(r.Session.ID))
	}
	fmt.Fprintf(&b, "# Written by `agentgate test --from %s` on %s.\n", strings.Join(ids, " --from "), now.Format("2006-01-02"))
	b.WriteString("# The decisions the policy reached in a recorded session, call by call, at\n")
	b.WriteString("# the time each was made: a change to the policy that would decide one of\n")
	b.WriteString("# them differently fails the test. Arguments and results are as the audit\n")
	b.WriteString("# log holds them, redacted. Edit what should change, and keep the rest.\n")
	b.WriteString("tests:\n")
	for i, r := range recs {
		if i > 0 {
			b.WriteString("\n")
		}
		if err := writeRecording(&b, r); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func writeRecording(b *strings.Builder, r Recording) error {
	s := r.Session
	checked := 0
	var steps strings.Builder
	for _, c := range r.Calls {
		if why, skip := notPolicy[c.RuleID]; skip {
			fmt.Fprintf(&steps, "      # %s: stopped by %s, which is not a policy decision\n", c.Tool, why)
			continue
		}
		fmt.Fprintf(&steps, "      - tool: %s\n", quote(c.Tool))
		if args := decode(c.Args); len(args) > 0 {
			fmt.Fprintf(&steps, "        args: %s\n", flow(args))
		}
		if r.Annotations != nil {
			if a, ok := r.Annotations(c.CatalogHash)[c.Tool]; ok {
				if hints := annotationFlow(a); hints != "" {
					fmt.Fprintf(&steps, "        annotations: %s\n", hints)
				}
			}
		}
		fmt.Fprintf(&steps, "        at: %s\n", c.TS.UTC().Format(time.RFC3339Nano))

		// The result matters only when the call earned labels: a label rule
		// may have read it, and the labels agentgate attaches itself come
		// from it.
		labels := c.Labels
		if len(labels) > 0 {
			if res := policy.ResultFromJSON(c.Result); res != nil && !c.ResultTruncated {
				fmt.Fprintf(&steps, "        result: {text: %s, is_error: %t}\n", quote(res.Text), res.IsError)
			} else {
				steps.WriteString("        # the recorded result was cut short, so the labels it earned are not expected\n")
				labels = nil
			}
		}

		expect := string(c.Decision)
		if c.RuleID != "" || len(labels) > 0 {
			parts := []string{"action: " + string(c.Decision)}
			if c.RuleID != "" {
				parts = append(parts, "rule: "+quote(c.RuleID))
			}
			if len(labels) > 0 {
				parts = append(parts, "labels: ["+strings.Join(labels, ", ")+"]")
			}
			expect = "{" + strings.Join(parts, ", ") + "}"
		}
		fmt.Fprintf(&steps, "        expect: %s\n", expect)
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("session %s has no call the policy decided", shortID(s.ID))
	}

	name := "session " + shortID(s.ID)
	host := s.HostName
	if s.HostVersion != "" {
		host += " " + s.HostVersion
	}
	if host != "" {
		name += ", " + host
	}
	name += ", " + s.StartedAt.Local().Format("2006-01-02 15:04")
	fmt.Fprintf(b, "  - name: %s\n", quote(name))
	if s.HostName != "" {
		h := s.HostName
		if s.HostVersion != "" {
			h += "/" + s.HostVersion
		}
		fmt.Fprintf(b, "    host: %s\n", quote(h))
	}
	b.WriteString("    steps:\n")
	b.WriteString(steps.String())
	return nil
}

func shortID(id string) string {
	if len(id) > 10 {
		return id[:10]
	}
	return id
}

func decode(raw json.RawMessage) map[string]any {
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

func annotationFlow(a policy.Annotations) string {
	var parts []string
	if a.Title != "" {
		parts = append(parts, "title: "+quote(a.Title))
	}
	for _, h := range []struct {
		name string
		v    *bool
	}{{"read_only", a.ReadOnly}, {"destructive", a.Destructive}, {"idempotent", a.Idempotent}, {"open_world", a.OpenWorld}} {
		if h.v != nil {
			parts = append(parts, fmt.Sprintf("%s: %t", h.name, *h.v))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// flow writes a value as YAML in flow style, every string double-quoted
// with anything invisible spelled out as an escape, so that a test file
// never hides what its calls carry.
func flow(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(x)
	case json.Number:
		return x.String()
	case string:
		return quote(x)
	case []any:
		parts := make([]string, len(x))
		for i, item := range x {
			parts[i] = flow(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = key(k) + ": " + flow(x[k])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return quote(fmt.Sprint(x))
	}
}

var bareKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// key leaves a plain key bare, and quotes anything YAML could read as
// something other than a string.
func key(k string) string {
	switch strings.ToLower(k) {
	case "true", "false", "null", "yes", "no", "on", "off", "y", "n":
		return quote(k)
	}
	if bareKey.MatchString(k) {
		return k
	}
	return quote(k)
}

// quote writes a YAML double-quoted string. Go's escapes are YAML's, and
// strconv.Quote escapes every character that does not print.
func quote(s string) string { return strconv.Quote(s) }
