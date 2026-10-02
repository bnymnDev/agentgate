package skills

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/bnymnDev/agentgate/internal/pinning"
)

// Severity says how much a finding should worry a reviewer.
type Severity string

// Severities, from the most to the least worrying.
const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
)

// Rank orders severities: high is 3, low is 1, anything else 0.
func (s Severity) Rank() int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

// ParseSeverity reads a severity, or "none".
func ParseSeverity(s string) (Severity, error) {
	switch v := Severity(strings.ToLower(s)); v {
	case High, Medium, Low:
		return v, nil
	case "none", "off":
		return "", nil
	}
	return "", fmt.Errorf("want high, medium, low or none, got %q", s)
}

// Finding is one thing a rule found in a skill.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	// File is relative to the skill directory.
	File string `json:"file"`
	Line int    `json:"line,omitempty"`
	// Detail says what was found, in words.
	Detail string `json:"detail"`
	// Excerpt is the text in question; for hidden characters, what they
	// spell out.
	Excerpt string `json:"excerpt,omitempty"`
}

// Key identifies a finding for acceptance. It leaves the line out, so a
// finding a human accepted stays accepted when a line is added above it.
func (f Finding) Key() string {
	sum := sha256.Sum256([]byte(f.Excerpt + "\x00" + f.Detail))
	return f.Rule + ":" + f.File + ":" + hex.EncodeToString(sum[:6])
}

// Where is file:line.
func (f Finding) Where() string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return f.File
}

// scope says which segments a text rule reads.
type scope int

const (
	inProse scope = 1 << iota
	inCode
	inComment
	anywhere = inProse | inCode
)

// Rule is one deterministic check.
type Rule struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	// Title is what a finding says.
	Title string `json:"title"`
	// Why explains what the rule is for, and what it is not.
	Why string `json:"why"`

	scope scope
	// raw rules read the text as it is; the others read what the model
	// reads, with hidden characters taken out and look-alike forms folded.
	raw bool
	// loadTime rules read only what Claude Code runs as the skill loads.
	loadTime bool
	pat      pattern
	// find is used instead of re for checks a regexp cannot express. It
	// returns byte ranges with an optional excerpt and detail.
	find func(text string) []hit
	// skill checks the skill as a whole.
	skill func(s *Skill) []Finding
}

type hit struct {
	start, end int
	excerpt    string
	detail     string
}

// Rules lists every rule, in the order the documentation shows them.
func Rules() []Rule { return append([]Rule(nil), rules...) }

// Scan runs every rule over a skill.
func Scan(s *Skill) []Finding {
	var out []Finding
	for i := range s.Files {
		f := &s.Files[i]
		for _, seg := range segments(f) {
			out = append(out, scanSegment(f.Path, seg)...)
		}
	}
	for _, r := range rules {
		if r.skill != nil {
			for _, fd := range r.skill(s) {
				fd.Rule, fd.Severity = r.ID, r.Severity
				if fd.Detail == "" {
					fd.Detail = r.Title
				}
				out = append(out, fd)
			}
		}
	}
	return dedupe(out)
}

func scanSegment(file string, seg segment) []Finding {
	var out []Finding
	var folded, lowerFolded string
	for _, r := range rules {
		if r.skill != nil || !r.applies(seg) {
			continue
		}
		text := seg.text
		if !r.raw {
			if folded == "" {
				folded = fold(seg.text)
			}
			text = folded
		}
		var hits []hit
		if r.find != nil {
			hits = r.find(text)
		} else {
			lower := lowerFolded
			if r.raw {
				lower = lowerASCII(text)
			}
			if lower == "" {
				lowerFolded = lowerASCII(text)
				lower = lowerFolded
			}
			for _, loc := range r.pat.findAll(text, lower) {
				hits = append(hits, hit{start: loc[0], end: loc[1]})
			}
		}
		for _, h := range hits {
			fd := Finding{Rule: r.ID, Severity: r.Severity, File: file,
				Line: seg.line + strings.Count(text[:h.start], "\n"), Detail: r.Title, Excerpt: h.excerpt}
			if h.detail != "" {
				fd.Detail = h.detail
			}
			if fd.Excerpt == "" {
				fd.Excerpt = excerpt(text, h.start, h.end)
			}
			out = append(out, fd)
		}
	}
	return out
}

func (r Rule) applies(seg segment) bool {
	if r.loadTime {
		return seg.loadTime
	}
	switch seg.kind {
	case segComment:
		return r.scope&(inComment|inProse) != 0
	case segCode:
		return r.scope&inCode != 0
	case segText:
		return r.scope&anywhere != 0
	default:
		return r.scope&inProse != 0
	}
}

// fold is what a pattern reads: hidden characters out, hidden tag text
// spelled out, and compatibility forms (fullwidth letters, ligatures) folded
// to the letters they look like. Line breaks are kept, so lines still count.
func fold(s string) string {
	return norm.NFKC.String(pinning.VisibleText(s))
}

func dedupe(in []Finding) []Finding {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
	out := in[:0]
	seen := map[string]bool{}
	for _, f := range in {
		// One finding per rule and line: a line read as prose and again as
		// inline code is still one line.
		k := fmt.Sprintf("%s:%s:%d", f.Rule, f.File, f.Line)
		if f.Line == 0 {
			k += ":" + f.Detail + f.Excerpt
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

// excerpt is the match with some context, on one line.
func excerpt(s string, start, end int) string {
	const pad, most = 30, 160
	if end-start > most {
		end = start + most
		for end > start && !utf8.RuneStart(s[end]) {
			end--
		}
	}
	from, to := max(start-pad, 0), min(end+pad, len(s))
	for from > 0 && !utf8.RuneStart(s[from]) {
		from--
	}
	for to < len(s) && !utf8.RuneStart(s[to]) {
		to++
	}
	// Stay on the lines of the match.
	if i := strings.LastIndexByte(s[from:start], '\n'); i >= 0 {
		from += i + 1
	}
	if i := strings.IndexByte(s[end:to], '\n'); i >= 0 && end+i > start {
		to = end + i
	}
	out := strings.Join(strings.Fields(s[from:to]), " ")
	if from > 0 && s[from-1] != '\n' {
		out = "…" + out
	}
	if to < len(s) && s[to] != '\n' {
		out += "…"
	}
	return out
}

// ---------------------------------------------------------------------------
// Hidden text

func isTag(r rune) bool { return r >= 0xE0000 && r <= 0xE007F }

func isBidi(r rune) bool { return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) }

// isZeroWidth: characters that take no space and join nothing. The
// zero-width joiner and non-joiner are left out; emoji sequences and several
// scripts depend on them.
func isZeroWidth(r rune) bool {
	switch r {
	case 0x200B, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E, 0x00AD, 0x034F,
		0x115F, 0x1160, 0x3164, 0xFFA0:
		return true
	}
	return false
}

// runeHits reports each line with characters for which pick is true, once,
// spelled out by pinning.Reveal. what is the rule's title.
func runeHits(text string, pick func(text string, i int, r rune) bool, what string) []hit {
	var out []hit
	lastLine := -1
	count := 0
	for i, r := range text {
		if !pick(text, i, r) {
			continue
		}
		line := strings.Count(text[:i], "\n")
		if line == lastLine {
			count++
			out[len(out)-1].detail = fmt.Sprintf("%s: %d on this line", what, count)
			continue
		}
		lastLine, count = line, 1
		ls := strings.LastIndexByte(text[:i], '\n') + 1
		le := strings.IndexByte(text[i:], '\n')
		if le < 0 {
			le = len(text)
		} else {
			le += i
		}
		ex := Reveal(text[ls:le])
		if utf8.RuneCountInString(ex) > 160 {
			ex = string([]rune(ex)[:159]) + "…"
		}
		out = append(out, hit{start: i, end: i + utf8.RuneLen(r), excerpt: ex,
			detail: what + ": 1 on this line"})
	}
	return out
}

// Reveal spells out what a text hides, as pinning.Reveal does — tag text in
// «hidden: …», invisible and reordering characters by code point — and
// variation selectors too.
func Reveal(s string) string {
	s = pinning.Reveal(s)
	if !strings.ContainsFunc(s, isSelector) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if isSelector(r) {
			fmt.Fprintf(&b, "«U+%04X»", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isSelector(r rune) bool { return r >= 0xFE00 && r <= 0xFE0F || r >= 0xE0100 && r <= 0xE01EF }

// tagHits decodes runs of Unicode tag characters back into the ASCII they
// smuggle. A subdivision flag (England, Scotland, Wales: a black flag, a
// few tag letters and a cancel tag) is the one honest use and is let be.
func tagHits(text string) []hit {
	var out []hit
	runes := []rune(text)
	offs := make([]int, 0, len(runes))
	for i := range text {
		offs = append(offs, i)
	}
	for i := 0; i < len(runes); i++ {
		if !isTag(runes[i]) {
			continue
		}
		j := i
		var b strings.Builder
		for j < len(runes) && isTag(runes[j]) {
			if runes[j] >= 0xE0020 && runes[j] <= 0xE007E {
				b.WriteRune(runes[j] - 0xE0000)
			}
			j++
		}
		flag := i > 0 && runes[i-1] == 0x1F3F4 && runes[j-1] == 0xE007F && j-i <= 8
		if !flag {
			end := len(text)
			if j < len(offs) {
				end = offs[j]
			}
			out = append(out, hit{start: offs[i], end: end, excerpt: b.String()})
		}
		i = j - 1
	}
	return out
}

// ---------------------------------------------------------------------------
// Look-alikes

var urlHost = regexp.MustCompile(`(?i)\b(?:https?|ftp|wss?)://([^\s/?#"'<>()\[\]` + "`" + `]+)`)

func confusableURLs(text string) []hit {
	var out []hit
	for _, m := range urlMatches(urlHost, text) {
		host := text[m[2]:m[3]]
		if at := strings.LastIndexByte(host, '@'); at >= 0 {
			host = host[at+1:]
		}
		ascii := true
		for _, r := range host {
			if r > unicode.MaxASCII {
				ascii = false
				break
			}
		}
		lower := strings.ToLower(host)
		if ascii && !strings.HasPrefix(lower, "xn--") && !strings.Contains(lower, ".xn--") {
			continue
		}
		out = append(out, hit{start: m[0], end: m[1], excerpt: Reveal(text[m[0]:m[1]]) + "  (host " + spellRunes(host) + ")"})
	}
	return out
}

// spellRunes writes every character outside ASCII as its code point, so a
// look-alike shows itself.
func spellRunes(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > unicode.MaxASCII {
			fmt.Fprintf(&b, "«U+%04X»", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func mixedScript(text string) []hit {
	var out []hit
	start := -1
	check := func(end int) {
		word := text[start:end]
		var latin, other bool
		for _, r := range word {
			switch {
			case unicode.Is(unicode.Latin, r):
				latin = true
			case unicode.Is(unicode.Cyrillic, r), unicode.Is(unicode.Greek, r), unicode.Is(unicode.Armenian, r):
				other = true
			}
		}
		if latin && other {
			out = append(out, hit{start: start, end: end, excerpt: spellRunes(word),
				detail: "a word that mixes Latin letters with Cyrillic, Greek or Armenian look-alikes"})
		}
	}
	for i, r := range text {
		if unicode.IsLetter(r) || unicode.IsMark(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			check(i)
			start = -1
		}
	}
	if start >= 0 {
		check(len(text))
	}
	return out
}

// urlMatches runs a URL pattern, with submatches, on the lines that have a
// "://" in them.
func urlMatches(re *regexp.Regexp, text string) [][]int {
	var out [][]int
	for _, w := range windows(text, []string{"://"}) {
		for _, m := range re.FindAllStringSubmatchIndex(text[w[0]:w[1]], -1) {
			for i := range m {
				if m[i] >= 0 {
					m[i] += w[0]
				}
			}
			out = append(out, m)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Encoded payloads

// padding finds 40 or more blank lines in a row, and 400 or more spaces or
// tabs in a row.
func padding(text string) []hit {
	var out []hit
	blank, runStart := 0, 0
	for pos := 0; pos < len(text); {
		line, next := lineAt(text, pos)
		if strings.TrimSpace(line) == "" && next > pos+len(line) {
			if blank == 0 {
				runStart = pos
			}
			blank++
		} else {
			if blank >= 40 {
				out = append(out, hit{start: runStart, end: pos,
					excerpt: fmt.Sprintf("%d blank lines, then: %s", blank, excerpt(text, pos, pos+len(line)))})
			}
			blank = 0
		}
		spaces := 0
		for i := 0; i < len(line); i++ {
			if line[i] == ' ' || line[i] == '\t' {
				spaces++
				continue
			}
			if spaces >= 400 {
				out = append(out, hit{start: pos + i - spaces, end: pos + i, excerpt: fmt.Sprintf("%d spaces in a row", spaces)})
			}
			spaces = 0
		}
		pos = next
	}
	if blank >= 40 {
		out = append(out, hit{start: runStart, end: len(text), excerpt: fmt.Sprintf("%d blank lines", blank)})
	}
	return out
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// hexBlobs finds 200 or more hex digits in a row, and strings of escaped
// bytes.
func hexBlobs(text string) []hit {
	var out []hit
	for i := 0; i < len(text); {
		if !isHex(text[i]) || i > 0 && isWordByte(text[i-1]) {
			i++
			continue
		}
		j := i
		for j < len(text) && isHex(text[j]) {
			j++
		}
		if j-i >= 200 && (j == len(text) || !isWordByte(text[j])) {
			out = append(out, hit{start: i, end: j})
		}
		i = j + 1
	}
	for _, loc := range escapedBytes.findAll(text, lowerASCII(text)) {
		out = append(out, hit{start: loc[0], end: loc[1]})
	}
	return out
}

func isBase64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_'
}

// base64Runs finds runs of base64 characters at least 120 long; a run in the
// URL-safe alphabet has to be 160.
func base64Runs(text string) [][]int {
	var out [][]int
	for i := 0; i < len(text); {
		if !isBase64(text[i]) {
			i++
			continue
		}
		j := i
		std, safe := true, true
		for j < len(text) && isBase64(text[j]) {
			switch text[j] {
			case '+', '/':
				safe = false
			case '-', '_':
				std = false
			}
			j++
		}
		k := j
		for k < len(text) && k-j < 2 && text[k] == '=' {
			k++
		}
		if std && j-i >= 120 || safe && j-i >= 160 {
			out = append(out, []int{i, k})
		}
		i = k + 1
	}
	return out
}

func base64Blobs(text string) []hit {
	var out []hit
	for _, loc := range base64Runs(text) {
		s := text[loc[0]:loc[1]]
		before := text[max(loc[0]-40, 0):loc[0]]
		if strings.Contains(before, "data:image/") || strings.Contains(before, "data:font/") {
			continue
		}
		if !strings.ContainsAny(s, "0123456789") || strings.ToLower(s) == s || strings.ToUpper(s) == s {
			continue
		}
		h := hit{start: loc[0], end: loc[1], excerpt: s[:40] + "…"}
		if dec := decodeBase64(s); dec != "" {
			h.excerpt += "  decodes to: " + dec
		}
		out = append(out, h)
	}
	return out
}

// decodeBase64 returns what a blob decodes to, when that is mostly
// readable text.
func decodeBase64(s string) string {
	s = strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(s)
		if err != nil {
			continue
		}
		if !utf8.Valid(b) {
			return ""
		}
		text := string(b)
		printable := 0
		for _, r := range text {
			if unicode.IsPrint(r) || unicode.IsSpace(r) {
				printable++
			}
		}
		if printable*10 < utf8.RuneCountInString(text)*9 {
			return ""
		}
		text = strings.Join(strings.Fields(text), " ")
		if utf8.RuneCountInString(text) > 100 {
			text = string([]rune(text)[:99]) + "…"
		}
		return Reveal(text)
	}
	return ""
}

// ---------------------------------------------------------------------------
// Prose aimed at the model

var (
	conditionalOpen = pat(`(?i)\b(if|when|whenever|once|should)\s+(the\s+|a\s+)?(user|someone|anyone|they|human|person|developer)\s+(ever\s+)?(asks?|mentions?|says?|requests?|types?|brings?\s+up|talks?\s+about|is\s+asking|wants?|writes?)\b`,
		"user", "someone", "anyone", "they", "human", "person", "developer")
	covert = regexp.MustCompile(`(?i)\b(secretly|silently|quietly|covertly|discreetly|instead|pretend|lie|ignore|without\s+(telling|asking|mentioning|informing|showing)|(do\s+not|don't|never)\s+(tell|mention|reveal|show|say|inform)|also\s+(send|upload|post|run|execute|include|copy|attach|forward)|first\s+(send|upload|post|run|execute|read|copy|fetch))\b`)
)

// conditionals finds instructions that only apply when the user brings
// something up, and then do something other than what was asked: the shape
// of a trigger that waits for its moment.
func conditionals(text string) []hit {
	var out []hit
	for _, loc := range conditionalOpen.findAll(text, lowerASCII(text)) {
		end := loc[1]
		for end < len(text) && end-loc[1] < 300 {
			c := text[end]
			if c == '.' || c == '!' || c == '?' || (c == '\n' && end+1 < len(text) && text[end+1] == '\n') {
				break
			}
			end++
		}
		if covert.MatchString(text[loc[0]:end]) {
			out = append(out, hit{start: loc[0], end: end})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Files

func fileRules(check func(f File) (string, bool)) func(s *Skill) []Finding {
	return func(s *Skill) []Finding {
		var out []Finding
		for _, f := range s.Files {
			if detail, ok := check(f); ok {
				out = append(out, Finding{File: f.Path, Detail: detail})
			}
		}
		return out
	}
}

func symlinks(s *Skill) []Finding {
	var out []Finding
	for _, f := range s.Files {
		if f.Kind != KindSymlink {
			continue
		}
		target := f.Target
		resolved := path.Join(path.Dir(f.Path), target)
		escapes := path.IsAbs(target) || strings.HasPrefix(target, "~") || len(target) > 1 && target[1] == ':' ||
			resolved == ".." || strings.HasPrefix(resolved, "../")
		detail := "a symlink inside the skill, to " + target + "; it is pinned by where it points, not by what is there"
		if escapes {
			detail = "a symlink that points outside the skill, to " + target + "; what it points at is not pinned, and can change at any time"
		}
		out = append(out, Finding{File: f.Path, Detail: detail, Excerpt: Reveal(f.Path + " -> " + target)})
	}
	return out
}

// executableKind tells compiled code apart by its first bytes or extension.
func executableKind(f File) (string, bool) {
	if !f.Binary {
		return "", false
	}
	h := f.head
	ext := strings.ToLower(path.Ext(f.Path))
	switch {
	case len(h) >= 4 && string(h[:4]) == "\x7fELF":
		return "an ELF executable", true
	case len(h) >= 2 && string(h[:2]) == "MZ":
		return "a Windows executable", true
	case len(h) >= 4 && (string(h[:4]) == "\xfe\xed\xfa\xce" || string(h[:4]) == "\xfe\xed\xfa\xcf" ||
		string(h[:4]) == "\xce\xfa\xed\xfe" || string(h[:4]) == "\xcf\xfa\xed\xfe"):
		return "a Mach-O executable", true
	case len(h) >= 4 && string(h[:4]) == "\xca\xfe\xba\xbe":
		if ext == ".class" {
			return "compiled Java bytecode", true
		}
		return "a Mach-O universal executable", true
	case len(h) >= 4 && string(h[:4]) == "\x00asm":
		return "a WebAssembly module", true
	case ext == ".pyc" || ext == ".pyo":
		return "compiled Python bytecode, which the source next to it need not match", true
	case ext == ".so" || ext == ".dylib" || ext == ".dll" || ext == ".exe" || ext == ".node":
		return "a native library or program", true
	}
	return "", false
}

// opaqueKind is a binary file nobody can review by reading it: an archive,
// or something unrecognised. Images, PDFs and fonts are let be.
func opaqueKind(f File) (string, bool) {
	if !f.Binary {
		return "", false
	}
	if _, ok := executableKind(f); ok {
		return "", false
	}
	h := string(f.head)
	has := func(p string) bool { return strings.HasPrefix(h, p) }
	switch {
	case has("PK\x03\x04"):
		return "a ZIP archive (also .docx, .xlsx, .jar): what is inside is not scanned", true
	case has("\x1f\x8b"), has("7z\xbc\xaf\x27\x1c"), has("Rar!"), has("\xfd7zXZ"), has("BZh"),
		len(h) > 262 && h[257:262] == "ustar":
		return "a compressed archive: what is inside is not scanned", true
	case has("\x89PNG"), has("\xff\xd8\xff"), has("GIF8"), has("RIFF"), has("BM"), has("\x00\x00\x01\x00"),
		has("%PDF"), has("wOFF"), has("wOF2"), has("OTTO"), has("\x00\x01\x00\x00"), has("ttcf"),
		len(h) > 12 && h[4:8] == "ftyp":
		return "", false
	}
	return "a binary file of no kind agentgate recognises: you cannot review it by reading it", true
}

// ---------------------------------------------------------------------------
// Front matter

var specName = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func frontMatter(s *Skill) []Finding {
	if s.FrontErr != "" {
		return []Finding{{File: ManifestName, Line: 1, Detail: s.FrontErr}}
	}
	var out []Finding
	name, _ := s.Front["name"].(string)
	desc, _ := s.Front["description"].(string)
	dir := path.Base(s.Key)
	switch {
	case strings.TrimSpace(name) == "":
		out = append(out, Finding{File: ManifestName, Detail: "the front matter has no name"})
	case len(name) > 64 || !specName.MatchString(name):
		out = append(out, Finding{File: ManifestName, Detail: "the name is not 1-64 lowercase letters, digits and single hyphens", Excerpt: Reveal(name)})
	case name != dir:
		out = append(out, Finding{File: ManifestName, Detail: fmt.Sprintf("the name %q is not the directory's, %q: the skill calls itself something it is not installed as", Reveal(name), dir)})
	}
	if strings.TrimSpace(desc) == "" {
		out = append(out, Finding{File: ManifestName, Detail: "the front matter has no description"})
	}
	return out
}

func longDescription(s *Skill) []Finding {
	if n := utf8.RuneCountInString(s.Description); n > 1024 {
		return []Finding{{File: ManifestName, Detail: fmt.Sprintf("the description is %d characters long; the Agent Skills specification allows 1024, and every one of them is in the model's context in every session", n)}}
	}
	return nil
}

var broadTrigger = regexp.MustCompile(`(?i)\b(always|every|all|any)\s+(time|task|request|question|prompt|message|conversation|turn|session|code|file|project|situation|case|change)s?\b|\b(use|invoke|load|apply|activate|run)\s+(this\s+skill\s+)?(for\s+|on\s+)?(everything|anything|always|first)\b|\bwhenever\s+possible\b|\bregardless\s+of\b|\bbefore\s+(any|every|all)\b|\bin\s+all\s+cases\b|\b(must|should)\s+always\s+be\s+(used|loaded|invoked|active)\b`)

// autoTrigger reports a description that claims every conversation for the
// skill. A skill the model cannot invoke on its own, or one limited to some
// paths, is let be.
func autoTrigger(s *Skill) []Finding {
	if b, _ := s.Front["disable-model-invocation"].(bool); b {
		return nil
	}
	if s.Front["paths"] != nil {
		return nil
	}
	var out []Finding
	for _, field := range []string{"description", "when_to_use"} {
		text := fold(s.frontString(field))
		if loc := broadTrigger.FindStringIndex(text); loc != nil {
			out = append(out, Finding{File: ManifestName, Detail: "the " + field + " asks for the skill to be used far beyond what it does", Excerpt: excerpt(text, loc[0], loc[1])})
		}
	}
	return out
}

func hooks(s *Skill) []Finding {
	if s.Front["hooks"] == nil {
		return nil
	}
	return []Finding{{File: ManifestName, Detail: "the front matter registers hooks: commands that run on the agent's events while the skill is active, without the model deciding to"}}
}
