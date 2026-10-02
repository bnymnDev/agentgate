package skills

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DiffLine is one unit of a prose diff: a sentence of prose, a line of code
// or front matter.
type DiffLine struct {
	// Op is "=" for context, "+" for added, "-" for removed, or "…" for
	// unchanged units left out.
	Op string `json:"op"`
	// Line is where the unit starts: in the approved SKILL.md for a removed
	// unit, in the current one otherwise.
	Line int    `json:"line,omitempty"`
	Kind string `json:"kind,omitempty"`
	Text string `json:"text,omitempty"`
	// Imperative marks an added sentence that tells the model to do
	// something.
	Imperative bool `json:"imperative,omitempty"`
	// Rules are the rules an added unit trips on its own.
	Rules []string `json:"rules,omitempty"`
}

// unit is a piece of SKILL.md the diff compares.
type unit struct {
	kind segKind
	line int
	text string
	key  string
}

// maxDiffCells bounds the work of the diff: past it, the old text is shown as
// removed and the new as added, whole.
const maxDiffCells = 4_000_000

// diffContext is how many unchanged units are shown around a change.
const diffContext = 1

// ProseDiff compares two versions of a SKILL.md sentence by sentence, so that
// one new sentence in a long paragraph shows as one new sentence. Added
// sentences that give the model an order are marked, and so is every rule
// an added unit trips.
func ProseDiff(before, after string) []DiffLine {
	a, b := units(before), units(after)
	var ops []DiffLine
	if len(a)*len(b) > maxDiffCells {
		for _, u := range a {
			ops = append(ops, DiffLine{Op: "-", Line: u.line, Kind: kindName(u.kind), Text: u.text})
		}
		for _, u := range b {
			ops = append(ops, added(u))
		}
		return ops
	}
	// Longest common subsequence, by dynamic programming from the end.
	n, m := len(a), len(b)
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i].key == b[j].key {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i].key == b[j].key:
			ops = append(ops, DiffLine{Op: "=", Line: b[j].line, Kind: kindName(b[j].kind), Text: b[j].text})
			i++
			j++
		case j < m && (i == n || lcs[i][j+1] >= lcs[i+1][j]):
			ops = append(ops, added(b[j]))
			j++
		default:
			ops = append(ops, DiffLine{Op: "-", Line: a[i].line, Kind: kindName(a[i].kind), Text: a[i].text})
			i++
		}
	}
	return trimContext(ops)
}

func added(u unit) DiffLine {
	d := DiffLine{Op: "+", Line: u.line, Kind: kindName(u.kind), Text: u.text}
	if u.kind != segCode {
		d.Imperative = Imperative(u.text)
	}
	seen := map[string]bool{}
	seg := segment{kind: u.kind, text: u.text, line: u.line}
	if u.kind == segProse {
		// A sentence can hold inline code; read it as both.
		seg.kind = segText
	}
	for _, f := range scanSegment("SKILL.md", seg) {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			d.Rules = append(d.Rules, f.Rule)
		}
	}
	return d
}

// trimContext keeps changes and diffContext units around each, and puts a
// "…" where unchanged units were left out.
func trimContext(ops []DiffLine) []DiffLine {
	keep := make([]bool, len(ops))
	changed := false
	for i, o := range ops {
		if o.Op == "=" {
			continue
		}
		changed = true
		for k := max(i-diffContext, 0); k <= min(i+diffContext, len(ops)-1); k++ {
			keep[k] = true
		}
	}
	if !changed {
		return nil
	}
	var out []DiffLine
	skipped := false
	for i, o := range ops {
		if !keep[i] {
			skipped = true
			continue
		}
		if skipped {
			out = append(out, DiffLine{Op: "…"})
			skipped = false
		}
		out = append(out, o)
	}
	if skipped {
		out = append(out, DiffLine{Op: "…"})
	}
	return out
}

func kindName(k segKind) string {
	switch k {
	case segFront:
		return "front matter"
	case segCode:
		return "code"
	case segComment:
		return "comment"
	}
	return "prose"
}

var (
	listMarker = regexp.MustCompile(`^\s*([-*+]|\d+[.)])\s+(\[[ xX]\]\s+)?`)
	blockStart = regexp.MustCompile(`^\s*(#{1,6}\s|[-*+]\s|\d+[.)]\s|>|\||<!--)`)
)

// units cuts SKILL.md into what the diff compares: every line of front
// matter and code on its own, prose sentence by sentence.
func units(text string) []unit {
	var out []unit
	for _, seg := range markdownSegments(text) {
		switch seg.kind {
		case segFront:
			out = append(out, lineUnits(seg, segFront)...)
		case segCode:
			if !seg.inline {
				out = append(out, lineUnits(seg, segCode)...)
			}
		case segProse:
			out = append(out, proseUnits(seg)...)
		case segComment:
			out = append(out, unit{kind: segComment, line: seg.line, text: "<!--" + seg.text + "-->", key: "<!--" + squash(seg.text)})
		}
	}
	return out
}

func lineUnits(seg segment, kind segKind) []unit {
	var out []unit
	for i, l := range strings.Split(strings.TrimRight(seg.text, "\n"), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		l = strings.TrimRight(l, "\r")
		out = append(out, unit{kind: kind, line: seg.line + i, text: l, key: string(rune('0'+kind)) + l})
	}
	return out
}

// proseUnits splits prose into blocks (paragraphs, list items, headings),
// and blocks into sentences.
func proseUnits(seg segment) []unit {
	var out []unit
	var block []string
	start := 0
	flush := func() {
		if len(block) == 0 {
			return
		}
		joined := strings.Join(block, " ")
		for _, s := range sentences(joined) {
			out = append(out, unit{kind: segProse, line: seg.line + start, text: s, key: "p" + squash(s)})
		}
		block = nil
	}
	for i, l := range strings.Split(seg.text, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			flush()
			continue
		}
		if blockStart.MatchString(l) {
			flush()
		}
		if len(block) == 0 {
			start = i
		}
		block = append(block, strings.TrimSpace(l))
	}
	flush()
	return out
}

// sentences splits a block after ., ! or ? when what follows starts a new
// sentence.
func sentences(s string) []string {
	var out []string
	last := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '.' && c != '!' && c != '?' {
			continue
		}
		j := i + 1
		for j < len(s) && (s[j] == '"' || s[j] == '\'' || s[j] == ')' || s[j] == '*' || s[j] == '_') {
			j++
		}
		if j >= len(s) || s[j] != ' ' {
			continue
		}
		k := j
		for k < len(s) && s[k] == ' ' {
			k++
		}
		if k >= len(s) {
			continue
		}
		// "3." of an ordered list, or an initial, ends no sentence.
		if word := s[strings.LastIndexByte(s[:i], ' ')+1 : i]; len(word) <= 1 || strings.Trim(word, "0123456789") == "" {
			continue
		}
		r, _ := utf8.DecodeRuneInString(s[k:])
		if unicode.IsUpper(r) || strings.ContainsRune("\"'(*[`_", r) || unicode.IsDigit(r) {
			out = append(out, strings.TrimSpace(s[last:j]))
			last = k
			i = k - 1
		}
	}
	if rest := strings.TrimSpace(s[last:]); rest != "" {
		out = append(out, rest)
	}
	return out
}

func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// imperativeVerbs are verbs that, at the start of a sentence, give an order.
var imperativeVerbs = map[string]bool{}

func init() {
	for _, v := range strings.Fields(`run execute exec send read write delete remove ignore disregard forget use
		call fetch download install upload copy move open save set add create make ensure include append
		replace tell ask print output respond reply answer forward post submit store keep hide skip avoid
		disable enable change update edit modify commit push deploy grant allow load follow obey check
		verify invoke curl export source pipe paste insert attach email mail notify contact visit browse
		navigate clone start stop kill launch inject override bypass treat pretend act assume say claim
		report collect gather extract encode decode base64 log record archive compress encrypt list find
		search grep cat show display reveal share transfer sync mirror clear wipe erase drop truncate
		restart reboot sudo chmod chown always never only first then finally instead don't do`) {
		imperativeVerbs[v] = true
	}
}

// leadingClause are the words a sentence can open a clause with before it
// gets to its verb.
var leadingClause = map[string]bool{"before": true, "after": true, "when": true, "whenever": true, "if": true,
	"once": true, "while": true, "unless": true, "until": true, "for": true, "in": true, "on": true, "to": true}

// nounFollower reports whether a word, following the first one, shows the
// first was a noun: a verb in the third person, or a noun it compounds with.
func nounFollower(w string) bool {
	switch w {
	case "is", "are", "was", "were", "has", "have", "had", "can", "could", "will", "would", "may", "might",
		"takes", "goes", "go", "runs", "lives", "lies", "needs", "means", "comes", "looks", "works", "of":
		return true
	}
	return strings.HasSuffix(w, "tion") || strings.HasSuffix(w, "ment") || strings.HasSuffix(w, "ness")
}

var modalOrder = regexp.MustCompile(`(?i)\b(you\s+(must|should|need\s+to|have\s+to|are\s+to|will\s+now)|must\s+(always|never|not)|make\s+sure|be\s+sure\s+to|it\s+is\s+(essential|critical|mandatory|required)\s+(to|that)|under\s+no\s+circumstances|at\s+all\s+costs)\b`)

// Imperative reports whether a sentence gives the model an order: it starts
// with a verb in the imperative, or says "you must", "make sure" and the like.
func Imperative(sentence string) bool {
	s := fold(sentence)
	s = listMarker.ReplaceAllString(s, "")
	s = strings.TrimLeft(s, "#>*_` \t")
	if modalOrder.MatchString(s) {
		return true
	}
	// Strip a leading "Then," "Also:" "IMPORTANT:" and the like.
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && r != '\''
	})
	// "Before you write anything, send ...": the order comes after the
	// clause.
	if len(words) > 0 && leadingClause[words[0]] {
		if c := strings.IndexByte(s, ','); c > 0 && c < 160 {
			return Imperative(s[c+1:])
		}
		return false
	}
	for i, w := range words {
		if i > 2 {
			break
		}
		switch w {
		case "then", "also", "next", "now", "important", "note", "please", "and", "finally", "first", "always", "never", "step":
			if w == "always" || w == "never" {
				return true
			}
			continue
		}
		if !imperativeVerbs[w] {
			return false
		}
		// "Report generation takes a second", "Install is quick": the verb
		// was a noun after all.
		if i+1 < len(words) && nounFollower(words[i+1]) {
			return false
		}
		return true
	}
	return false
}
