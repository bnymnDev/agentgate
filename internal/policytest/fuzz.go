package policytest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// Fuzzing turns every test that a call must be stopped — denied, or put in
// front of a human — into many calls that mean the same thing and are
// spelled differently: a shell command run through env or sh -c, a path
// with a detour through .., SQL with a comment where the space was, a URL
// with the host in capitals. A variant the policy lets through is a bypass:
// the rule matched the spelling, not the meaning. Only rewrites that keep
// the meaning are made, so every bypass is real.

// Bypass is one variant that got through.
type Bypass struct {
	Test      string          `json:"test"`
	Line      int             `json:"line,omitempty"`
	Tool      string          `json:"tool"`
	Arg       string          `json:"arg"`
	Technique string          `json:"technique"`
	Original  string          `json:"original"`
	Variant   string          `json:"variant"`
	Expected  policy.Action   `json:"expected"`
	Got       policy.Decision `json:"got"`
}

// FuzzReport is what a fuzz run found.
type FuzzReport struct {
	Tests    int      `json:"tests"`
	Variants int      `json:"variants"`
	Bypasses []Bypass `json:"bypasses"`
}

type variant struct {
	technique, value string
}

var (
	sqlLike   = regexp.MustCompile(`(?i)^\s*(select|insert|update|delete|drop|truncate|alter|create|grant|with|merge|replace)\b`)
	urlLike   = regexp.MustCompile(`^(?i)https?://[^/\s]+`)
	pathLike  = regexp.MustCompile(`^(~|\.{1,2})?/[^\s]*$`)
	shellKeys = map[string]bool{"command": true, "cmd": true, "script": true, "shell": true, "run": true, "commandline": true, "command_line": true}
	sqlWS     = regexp.MustCompile(`\s+`)
)

// variants of a string argument that mean the same to whatever reads it.
func variants(key, v string, allowedDirs []string) []variant {
	var out []variant
	add := func(technique, value string) {
		if value != v {
			out = append(out, variant{technique, value})
		}
	}
	switch {
	case sqlLike.MatchString(v):
		add("lower-case SQL", strings.ToLower(v))
		add("SQL keywords split by a newline", sqlWS.ReplaceAllString(strings.TrimSpace(v), "\n"))
		add("SQL keywords split by a comment", sqlWS.ReplaceAllString(strings.TrimSpace(v), "/**/"))
		add("a comment line before the SQL", "-- report\n"+v)
		add("leading whitespace", "  \n"+v)
		add("a harmless statement first", "SELECT 1; "+v)
	case urlLike.MatchString(v):
		host := urlLike.FindString(v)
		scheme, h, _ := strings.Cut(host, "://")
		add("host in capitals", scheme+"://"+strings.ToUpper(h)+v[len(host):])
		add("a trailing dot on the host", scheme+"://"+h+"."+v[len(host):])
		add("an explicit default port", scheme+"://"+h+map[bool]string{true: ":443", false: ":80"}[strings.EqualFold(scheme, "https")]+v[len(host):])
		add("user info before the host", scheme+"://docs.example.com@"+h+v[len(host):])
	case pathLike.MatchString(v) && !shellKeys[strings.ToLower(key)]:
		dir, file := splitPath(v)
		if file != "" {
			add("a ./ in the path", dir+"./"+file)
			add("a doubled slash", dir+"/"+file)
			if parent := strings.TrimSuffix(dir, "/"); parent != "" && parent != "~" && parent != "." {
				base := parent[strings.LastIndex(parent, "/")+1:]
				add("a detour through ..", dir+"../"+base+"/"+file)
			}
		}
		if strings.HasPrefix(v, "/") {
			add("a leading //", "/"+v)
			// From a directory the policy lets through, back up to the root.
			for _, d := range allowedDirs {
				if strings.HasPrefix(v, d) {
					continue
				}
				up := strings.Repeat("../", strings.Count(strings.Trim(d, "/"), "/")+1)
				add("an allowed directory, then .. back out", d+up+strings.TrimPrefix(v, "/"))
			}
		}
	case shellKeys[strings.ToLower(key)] || strings.ContainsAny(v, "|;&$`"):
		fields := strings.Fields(v)
		if len(fields) == 0 {
			break
		}
		cmd, rest := fields[0], strings.Join(fields[1:], " ")
		join := func(c string) string { return strings.TrimSpace(c + " " + rest) }
		add("doubled spaces", strings.Join(fields, "  "))
		add("a tab for a space", strings.Join(fields, "\t"))
		add("run through env", "env "+v)
		add("run through command", "command "+v)
		add("run through sh -c", "sh -c '"+strings.ReplaceAll(v, "'", `'\''`)+"'")
		add("run through bash -c", `bash -c "`+strings.ReplaceAll(v, `"`, `\"`)+`"`)
		add("after another command", "true && "+v)
		add("on a second line", "echo ok\n"+v)
		add("the command quoted", join(`"`+cmd+`"`))
		add("the command escaped", join(`\`+cmd))
		if len(cmd) > 1 && !strings.ContainsAny(cmd, `/'"\`) {
			add("an empty quote inside the command", join(cmd[:1]+"''"+cmd[1:]))
			add("the command by its full path", join("/usr/bin/"+cmd))
		}
		for _, f := range fields[1:] {
			// -rf is -r -f, and -fr.
			if len(f) == 3 && f[0] == '-' && f[1] != '-' {
				add("short flags split", strings.Replace(v, f, "-"+f[1:2]+" -"+f[2:3], 1))
				add("short flags swapped", strings.Replace(v, f, "-"+f[2:3]+f[1:2], 1))
			}
		}
	}
	return out
}

func splitPath(p string) (dir, file string) {
	i := strings.LastIndex(p, "/")
	if i < 0 || i == len(p)-1 {
		return p, ""
	}
	return p[:i+1], p[i+1:]
}

// Fuzz runs the variants of every test that expects a call to be stopped.
func Fuzz(f *File, opts Options) FuzzReport {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	var rep FuzzReport
	allowed := allowedDirs(f)
	for _, c := range f.Tests {
		if opts.Match != nil && !opts.Match.MatchString(c.Name) {
			continue
		}
		steps := c.Steps
		if len(steps) == 0 {
			if c.Call == nil || c.Expect == nil {
				continue
			}
			steps = append(append([]Step(nil), c.Before...), *c.Call)
			steps[len(steps)-1].Expect = c.Expect
		}
		fuzzed := false
		for i, s := range steps {
			if s.Expect == nil || (s.Expect.Action != policy.ActionDeny && s.Expect.Action != policy.ActionAsk) {
				continue
			}
			// A decision the session made — the loop guard, a budget, the kill
			// switch — does not depend on how the call is spelled, and a test
			// that fails already has nothing to fuzz.
			orig, err := decideStep(c, steps, i, opts)
			if err != nil || orig.Action != s.Expect.Action || sessionRule[orig.RuleID] {
				continue
			}
			fuzzed = true
			keys := make([]string, 0, len(s.Args))
			for k := range s.Args {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				str, ok := s.Args[k].(string)
				if !ok {
					continue
				}
				for _, v := range variants(k, str, allowed) {
					rep.Variants++
					mutated := make([]Step, len(steps))
					copy(mutated, steps)
					args := make(map[string]any, len(s.Args))
					for ak, av := range s.Args {
						args[ak] = av
					}
					args[k] = v.value
					mutated[i].Args = args
					got, err := decideStep(c, mutated, i, opts)
					if err != nil || rank(got.Action) >= rank(s.Expect.Action) {
						continue
					}
					rep.Bypasses = append(rep.Bypasses, Bypass{Test: c.Name, Line: c.Line, Tool: s.Tool, Arg: k,
						Technique: v.technique, Original: str, Variant: v.value, Expected: s.Expect.Action, Got: got})
				}
			}
		}
		if fuzzed {
			rep.Tests++
		}
	}
	return rep
}

var sessionRule = map[string]bool{policy.RuleLoopGuard: true, policy.RuleBudget: true, policy.RuleFrozen: true}

func rank(a policy.Action) int {
	switch a {
	case policy.ActionDeny:
		return 2
	case policy.ActionAsk:
		return 1
	}
	return 0
}

// decideStep plays a test's steps and returns the decision step target got.
func decideStep(c Case, steps []Step, target int, opts Options) (policy.Decision, error) {
	at := opts.Now
	if c.At != "" {
		t, err := ParseWhen(c.At, opts.Now)
		if err != nil {
			return policy.Decision{}, err
		}
		at = t
	}
	var host policy.Host
	host.Name, host.Version, _ = strings.Cut(c.Host, "/")
	var track policy.Tracker
	track.Earn(c.Labels...)
	var last policy.Decision
	for i, s := range steps[:target+1] {
		when := at
		if s.At != "" {
			t, err := ParseWhen(s.At, opts.Now)
			if err != nil {
				return policy.Decision{}, err
			}
			when = t
		}
		for range max(s.Repeat, 1) {
			d, _, err := play(opts.Config, &track, s, when, host, opts.ResultLabels)
			if err != nil {
				return policy.Decision{}, fmt.Errorf("step %d: %w", i+1, err)
			}
			last = d
		}
	}
	return last, nil
}

// Markdown renders the bypasses for a pull request or an issue.
func (r FuzzReport) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d variants of %d tests that must stop a call; %d got through.\n", r.Variants, r.Tests, len(r.Bypasses))
	for _, x := range r.Bypasses {
		v, _ := json.Marshal(x.Variant)
		fmt.Fprintf(&b, "\n- **%s** (`%s`, %s): %s gets **%s** instead of %s: `%s`", x.Test, x.Tool, x.Arg, x.Technique, x.Got.Action, x.Expected, v)
	}
	if len(r.Bypasses) > 0 {
		b.WriteString("\n")
	}
	return b.String()
}

// allowedDirs are the directories of the absolute paths the tests expect to
// be let through: a path that starts in one and climbs out with .. tests a
// rule that looks at the start of a path.
func allowedDirs(f *File) []string {
	seen := map[string]bool{}
	var out []string
	note := func(s Step, e *Expect) {
		if e == nil || e.Action != policy.ActionAllow {
			return
		}
		for _, v := range s.Args {
			str, ok := v.(string)
			if !ok || !strings.HasPrefix(str, "/") || strings.ContainsAny(str, " \n") {
				continue
			}
			dir, _ := splitPath(str)
			if dir != "/" && !seen[dir] {
				seen[dir] = true
				out = append(out, dir)
			}
		}
	}
	for _, c := range f.Tests {
		if c.Call != nil {
			note(*c.Call, c.Expect)
		}
		for _, s := range c.Steps {
			note(s, s.Expect)
		}
	}
	sort.Strings(out)
	return out
}
