package pinning

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Finding is one suspicious thing in a tool definition.
type Finding struct {
	// Kind is invisible, instruction, credentials or shadowing.
	Kind string `json:"kind"`
	// Where is the part of the definition it was found in: description,
	// title, or a path into a schema ("inputSchema.properties.note.description").
	Where string `json:"where"`
	// Detail says what was found, in words.
	Detail string `json:"detail"`
	// Excerpt is the text in question. For hidden characters it is what they
	// spell out, which is usually the whole point of hiding them.
	Excerpt string `json:"excerpt,omitempty"`
}

// Key identifies a finding for acceptance: the same kind of thing in the
// same place.
func (f Finding) Key() string { return f.Kind + ":" + f.Where + ":" + f.Detail }

// OtherTool is a tool of another upstream, for the shadowing check.
type OtherTool struct {
	Upstream string
	Name     string
}

// Finding kinds.
const (
	KindInvisible   = "invisible"
	KindInstruction = "instruction"
	KindCredentials = "credentials"
	KindShadowing   = "shadowing"
)

// Scan looks through a definition for the marks of a poisoned tool: text the
// user cannot see, instructions addressed to the model rather than a
// description of the tool, pointers at credentials, and talk about other
// servers' tools.
func Scan(d Definition, others []OtherTool) []Finding {
	var out []Finding
	texts := []textAt{{"name", d.Name}, {"title", d.Title}, {"description", d.Description}}
	texts = append(texts, schemaTexts("inputSchema", d.InputSchema)...)
	texts = append(texts, schemaTexts("outputSchema", d.OutputSchema)...)
	texts = append(texts, schemaTexts("annotations", d.Annotations)...)
	shadow := newShadowMatcher(others)
	for _, t := range texts {
		out = append(out, scanText(t, shadow, true)...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return dedupeFindings(out)
}

type textAt struct {
	where string
	text  string
}

// schemaTexts collects every string in a JSON document — keys included,
// since a property name can hide characters as well as a description can.
func schemaTexts(root string, raw json.RawMessage) []textAt {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	var out []textAt
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch t := v.(type) {
		case string:
			out = append(out, textAt{path, t})
		case []any:
			for i, e := range t {
				walk(fmt.Sprintf("%s[%d]", path, i), e)
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if hasInvisible(k) {
					out = append(out, textAt{path + " (a key)", k})
				}
				walk(path+"."+k, t[k])
			}
		}
	}
	walk(root, v)
	return out
}

// instructionPatterns are phrases addressed to the model rather than a
// description of a tool. The ones marked forResults are precise enough to
// look for in what a tool returns too, where ordinary text (an article about
// system prompts, a confirmation that a mail was sent to someone) would trip
// the others.
var instructionPatterns = []struct {
	re         *regexp.Regexp
	detail     string
	forResults bool
}{
	{regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|other|system)\s+(instructions|directions|rules|prompts?|guidelines)`),
		"tells the model to ignore its instructions", true},
	{regexp.MustCompile(`(?i)\b(do\s+not|don't|never)\s+(tell|inform|mention|reveal|show|notify|alert|disclose)\b[^.]{0,80}\buser\b`),
		"tells the model to keep something from the user", true},
	{regexp.MustCompile(`(?i)\bwithout\s+(telling|informing|asking|notifying|alerting|showing)\s+(the\s+)?user\b`),
		"tells the model to act behind the user's back", true},
	{regexp.MustCompile(`(?i)<\s*/?\s*(important|system|instructions?|secret|hidden|admin|critical)\s*>`),
		"wraps text in an <important>-style tag, the usual wrapper for injected instructions", true},
	{regexp.MustCompile(`(?i)\b(system\s+prompt|developer\s+message|your\s+(instructions|guidelines|rules)\s+(are|say))\b`),
		"talks to the model about its own instructions", false},
	{regexp.MustCompile(`(?i)\b(you\s+are\s+now|from\s+now\s+on,?\s+you|act\s+as\s+(an?\s+)?(admin|root|developer|system))\b`),
		"tries to change who the model thinks it is", false},
	{regexp.MustCompile(`(?i)\b(send|forward|post|upload|exfiltrate|leak|transmit|e-?mail|copy)\b[^.\n]{0,80}\b(to|at)\s+(https?://\S+|[\w.+-]+@[\w-]+\.[\w.-]+)`),
		"tells the model to send something to a specific address", false},
}

var credentialPattern = regexp.MustCompile(`(?i)((~|\$home|%userprofile%)[/\\]\.(ssh|aws|gnupg|kube|docker|config[/\\]gh|netrc|cursor|claude)\b|\bid_(rsa|ed25519|ecdsa|dsa)\b|(^|[\s"'/\\(])\.env\b|\bmcp\.json\b|claude_desktop_config\.json|\.git-credentials|\bprivate[\s_-]?key\b)`)

// shadowMatcher finds other servers' tool names in a text, with one regex
// for all of them.
type shadowMatcher struct {
	re     *regexp.Regexp
	owners map[string]OtherTool
}

func newShadowMatcher(others []OtherTool) *shadowMatcher {
	m := &shadowMatcher{owners: map[string]OtherTool{}}
	var names []string
	for _, o := range others {
		key := strings.ToLower(o.Name)
		if !distinctive(o.Name) || m.owners[key].Name != "" {
			continue
		}
		m.owners[key] = o
		names = append(names, regexp.QuoteMeta(o.Name))
	}
	if len(names) == 0 {
		return m
	}
	// Longer names first, so that send_email_draft wins over send_email.
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	m.re = regexp.MustCompile(`(?i)(?:^|[^\w])(` + strings.Join(names, "|") + `)(?:$|[^\w])`)
	return m
}

func (m *shadowMatcher) find(text, where string) []Finding {
	if m.re == nil {
		return nil
	}
	var out []Finding
	for _, loc := range m.re.FindAllStringSubmatchIndex(text, -1) {
		o := m.owners[strings.ToLower(text[loc[2]:loc[3]])]
		out = append(out, Finding{Kind: KindShadowing, Where: where,
			Detail:  fmt.Sprintf("talks about %s's tool %s; a tool has no business steering how another server's tools are used", o.Upstream, o.Name),
			Excerpt: excerpt(text, loc[2:4])})
	}
	return out
}

// maxResultScan caps how much of a tool result is scanned.
const maxResultScan = 512 << 10

// ScanResult looks through what a tool returned for text aimed at the model
// rather than the user: hidden characters and instructions. Pointers at
// credentials are left out here; a result that mentions .env files is
// usually just a result about .env files.
func ScanResult(text string) []Finding {
	if len(text) > maxResultScan {
		cut := maxResultScan
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = text[:cut]
	}
	return dedupeFindings(scanText(textAt{where: "result", text: text}, &shadowMatcher{}, false))
}

// StripInvisible removes every character that renders as nothing or
// reorders what is rendered, and reports how many it removed.
func StripInvisible(s string) (string, int) {
	n := 0
	out := strings.Map(func(r rune) rune {
		if (r >= 0xE0000 && r <= 0xE007F) || isZeroWidth(r) || isBidi(r) {
			n++
			return -1
		}
		return r
	}, s)
	return out, n
}

// scanText checks one text. definition is true for a tool definition and
// false for a tool result, which is held to what only an attack looks like:
// results are full of ordinary zero-width joiners, soft hyphens and terminal
// colours.
func scanText(t textAt, shadow *shadowMatcher, definition bool) []Finding {
	if t.text == "" {
		return nil
	}
	var out []Finding
	if f, ok := invisibleFinding(t, definition); ok {
		out = append(out, f)
	}
	visible := visibleText(t.text)
	for _, p := range instructionPatterns {
		if !definition && !p.forResults {
			continue
		}
		if loc := p.re.FindStringIndex(visible); loc != nil {
			out = append(out, Finding{Kind: KindInstruction, Where: t.where, Detail: p.detail, Excerpt: excerpt(visible, loc)})
		}
	}
	// A tool's own name is allowed to say what it is.
	if definition && t.where != "name" {
		if loc := credentialPattern.FindStringIndex(visible); loc != nil {
			out = append(out, Finding{Kind: KindCredentials, Where: t.where,
				Detail: "points the model at credentials or an agent's configuration", Excerpt: excerpt(visible, loc)})
		}
		out = append(out, shadow.find(visible, t.where)...)
	}
	return out
}

// distinctive keeps the shadowing check to names that would not turn up in
// ordinary prose: "add" or "search" would, "send_email" would not.
func distinctive(name string) bool {
	return strings.ContainsAny(name, "_-.") || len(name) >= 12
}

// invisibleFinding reports characters that render as nothing, or reorder
// what is rendered, and decodes Unicode tag characters back into the ASCII
// they smuggle. strict also counts zero-width and control characters, which
// have no business in a tool definition but turn up in ordinary results.
func invisibleFinding(t textAt, strict bool) (Finding, bool) {
	var (
		tags      strings.Builder
		flag      strings.Builder
		zeroWidth int
		bidi      int
		control   int
		prev      rune
		inFlag    bool
	)
	// Subdivision flags (England, Scotland, Wales) are a black flag followed
	// by a few tag letters and a cancel tag: the one honest use of tag
	// characters. A "flag" that goes on for longer is hiding something.
	endFlag := func(honest bool) {
		if !honest {
			tags.WriteString(flag.String())
		}
		flag.Reset()
		inFlag = false
	}
	for i, r := range t.text {
		isTag := r >= 0xE0000 && r <= 0xE007F
		if inFlag && !isTag {
			endFlag(false)
		}
		switch {
		case isTag:
			if prev == 0x1F3F4 && !inFlag {
				inFlag = true
			}
			switch {
			case inFlag && r == 0xE007F:
				endFlag(flag.Len() <= 6)
			case r >= 0xE0020 && r <= 0xE007E && inFlag:
				flag.WriteRune(r - 0xE0000)
			case r >= 0xE0020 && r <= 0xE007E:
				tags.WriteRune(r - 0xE0000)
			}
		case isBidi(r):
			if strict || r == 0x202D || r == 0x202E {
				bidi++
			}
		case !strict:
		case isZeroWidth(r) && (r != 0xFEFF || i != 0):
			zeroWidth++
		case r < 0x20 && r != '\n' && r != '\t' && r != '\r', r == 0x7F, r >= 0x80 && r < 0xA0:
			control++
		}
		prev = r
	}
	if inFlag {
		endFlag(false)
	}
	var parts []string
	f := Finding{Kind: KindInvisible, Where: t.where}
	if tags.Len() > 0 {
		parts = append(parts, "text hidden in Unicode tag characters, which show as nothing but the model reads")
		f.Excerpt = tags.String()
	}
	if zeroWidth > 0 {
		parts = append(parts, fmt.Sprintf("%d zero-width character(s)", zeroWidth))
	}
	if bidi > 0 {
		parts = append(parts, fmt.Sprintf("%d bidirectional control character(s), which make text read differently than it runs", bidi))
	}
	if control > 0 {
		parts = append(parts, fmt.Sprintf("%d control character(s), which can hide text in a terminal", control))
	}
	if len(parts) == 0 {
		return f, false
	}
	f.Detail = strings.Join(parts, "; ")
	return f, true
}

func hasInvisible(s string) bool {
	_, ok := invisibleFinding(textAt{text: s}, true)
	return ok
}

// isZeroWidth covers the characters that take no space and join nothing.
// The zero-width joiner and non-joiner are left out: they hold emoji
// sequences and several scripts together.
func isZeroWidth(r rune) bool {
	switch {
	case r == 0x200B, r >= 0x2060 && r <= 0x2064, r == 0xFEFF,
		r == 0x180E, r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0:
		return true
	}
	return false
}

// isBidi covers the embedding, override and isolate controls — the ones that
// change the order text is shown in ("Trojan Source").
func isBidi(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// visibleText is what a pattern should look at: hidden characters are taken
// out, so they cannot be used to split a phrase, and hidden tag text is
// spelled out, so what it says is checked too.
func visibleText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 0xE0020 && r <= 0xE007E:
			b.WriteRune(r - 0xE0000)
		case r >= 0xE0000 && r <= 0xE007F, isZeroWidth(r), isBidi(r):
		case !unicode.IsPrint(r) && !unicode.IsSpace(r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func excerpt(s string, loc []int) string {
	const pad = 30
	start, end := loc[0]-pad, loc[1]+pad
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	for start > 0 && !utf8.RuneStart(s[start]) {
		start--
	}
	for end < len(s) && !utf8.RuneStart(s[end]) {
		end++
	}
	out := strings.Join(strings.Fields(s[start:end]), " ")
	if start > 0 {
		out = "…" + out
	}
	if end < len(s) {
		out += "…"
	}
	return out
}

func dedupeFindings(in []Finding) []Finding {
	out := in[:0]
	seen := map[string]bool{}
	for _, f := range in {
		if seen[f.Key()] {
			continue
		}
		seen[f.Key()] = true
		out = append(out, f)
	}
	return out
}

// Reveal renders what a text hides: tag characters are spelled out in
// ⟦hidden: …⟧, and every other invisible or reordering character is shown as
// its code point. What is left is exactly what the model reads.
func Reveal(s string) string {
	var (
		b    strings.Builder
		tags strings.Builder
	)
	flush := func() {
		if tags.Len() > 0 {
			b.WriteString("⟦hidden: " + tags.String() + "⟧")
			tags.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			if r >= 0xE0020 && r <= 0xE007E {
				tags.WriteRune(r - 0xE0000)
			}
			continue
		case isZeroWidth(r), isBidi(r):
			flush()
			fmt.Fprintf(&b, "⟦U+%04X⟧", r)
		case r < 0x20 && r != '\n' && r != '\t', r == 0x7F, r >= 0x80 && r < 0xA0:
			flush()
			fmt.Fprintf(&b, "⟦%#02x⟧", r)
		default:
			flush()
			b.WriteRune(r)
		}
	}
	flush()
	return b.String()
}
