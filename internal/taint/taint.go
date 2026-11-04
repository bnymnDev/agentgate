// Package taint finds the values in a text that look like secrets, so that a
// session that read them can be stopped from sending them anywhere.
//
// A canary catches a planted credential. Taint catches the real ones: when a
// tool result is private — it came from reading a .env file, a vault, a
// database of customers — the values in it that look like secrets are
// remembered for the session, and a later call that carries one of them out,
// plain or encoded, is noticed. Nothing here knows what a secret is; it
// knows what secrets look like: the value of a KEY=VALUE line whose key says
// so, and long strings with the randomness of a token.
package taint

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

// MinLength is the shortest value worth remembering by default. Shorter ones
// match too much ordinary text.
const MinLength = 12

var (
	// assignment is KEY=VALUE, KEY: VALUE and "key": "value".
	assignment = regexp.MustCompile(`(?m)["']?([A-Za-z_][A-Za-z0-9_.-]{1,63})["']?\s*[:=]\s*["']?([^\s"',;#]+)`)
	secretKey  = regexp.MustCompile(`(?i)(pass(word|wd|phrase)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth|session|cookie|dsn|database_url|conn(ection)?[_-]?string|signing|salt|bearer)`)
	// tokenish is a run of the characters tokens are made of.
	tokenish = regexp.MustCompile(`[A-Za-z0-9+/_\-.~]{12,}={0,2}`)
	// urlUserinfo is the password in scheme://user:password@host.
	urlUserinfo = regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]{6,})@`)
)

// Extract returns the values in text that look like secrets, longest first,
// each at least minLength characters long.
func Extract(text string, minLength int) []string {
	if minLength <= 0 {
		minLength = MinLength
	}
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.Trim(v, `"'`+"`")
		if len(v) < minLength || seen[v] || boring(v) {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, m := range assignment.FindAllStringSubmatch(text, -1) {
		if secretKey.MatchString(m[1]) && len(m[2]) >= 6 {
			// A key that says secret is enough; the value need not look
			// random ("password = correct horse battery staple" does not).
			add(m[2])
		}
	}
	for _, m := range urlUserinfo.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	for _, t := range tokenish.FindAllString(text, -1) {
		if looksRandom(t) {
			add(t)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// looksRandom is the shape of a key or a token: long, mixed, and with the
// entropy of random characters rather than of words or paths.
func looksRandom(s string) bool {
	if len(s) < 16 || strings.Count(s, "/") > 2 || strings.Count(s, ".") > 2 {
		return false
	}
	var lower, upper, digit int
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			lower++
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= '0' && r <= '9':
			digit++
		}
	}
	classes := 0
	for _, n := range []int{lower, upper, digit} {
		if n > 0 {
			classes++
		}
	}
	if classes < 2 || digit == 0 {
		return false
	}
	return entropy(s) >= 3.6
}

// boring are values that look like secrets and are not: placeholders,
// version strings, and the redaction marker.
func boring(v string) bool {
	l := strings.ToLower(v)
	for _, p := range []string{"redacted", "changeme", "example", "placeholder", "xxxxxxxx", "your_", "<", "${"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	h := 0.0
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}
