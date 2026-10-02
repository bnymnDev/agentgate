package skills

import (
	"path"
	"regexp"
	"strings"
)

// segKind is what a stretch of a file is, as far as the agent is concerned.
type segKind int

const (
	// segProse is Markdown prose: instructions the model reads.
	segProse segKind = iota
	// segFront is the YAML front matter of a Markdown file.
	segFront
	// segComment is an HTML comment in Markdown: the model reads it, a
	// rendered page does not show it.
	segComment
	// segCode is a fenced code block, an inline code span or a script.
	segCode
	// segText is any other text file, read as both prose and code.
	segText
)

// segment is a stretch of one file. start is its byte offset in the file's
// scanned text and line the line it starts on.
type segment struct {
	kind segKind
	// lang is a code block's info string, or a script's language.
	lang string
	// loadTime marks a block Claude Code runs as shell when it loads the
	// skill (```!).
	loadTime bool
	// inline marks an inline code span, which is also part of the prose
	// around it.
	inline bool
	text   string
	line   int
}

// scriptLangs maps a file extension to the language it is run with.
var scriptLangs = map[string]string{
	".sh": "sh", ".bash": "bash", ".zsh": "zsh", ".fish": "fish", ".ksh": "sh",
	".ps1": "powershell", ".psm1": "powershell", ".bat": "bat", ".cmd": "bat",
	".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
	".ts": "typescript", ".rb": "ruby", ".pl": "perl", ".php": "php", ".lua": "lua",
	".go": "go", ".rs": "rust", ".swift": "swift", ".java": "java", ".kt": "kotlin",
	".applescript": "applescript", ".scpt": "applescript", ".vbs": "vbscript",
}

// shellLangs are the code block languages that are a shell.
var shellLangs = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "fish": true, "shell": true, "console": true,
	"shell-session": true, "shellsession": true, "powershell": true, "pwsh": true, "ps1": true,
	"bat": true, "cmd": true, "batch": true, "terminal": true, "ksh": true,
}

func isMarkdown(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".md", ".markdown", ".mdx", ".mdc":
		return true
	}
	return false
}

// scriptLang is the language a file is run with: by extension, or else by
// its #! line.
func scriptLang(p, text string) string {
	if l, ok := scriptLangs[strings.ToLower(path.Ext(p))]; ok {
		return l
	}
	if strings.HasPrefix(text, "#!") {
		line, _ := lineAt(text, 0)
		fields := strings.Fields(strings.TrimPrefix(line, "#!"))
		if len(fields) == 0 {
			return "sh"
		}
		interp := path.Base(fields[0])
		if interp == "env" && len(fields) > 1 {
			interp = fields[len(fields)-1]
		}
		return strings.TrimRight(interp, "0123456789.")
	}
	return ""
}

// segments cuts a file into what is prose and what is code.
func segments(f *File) []segment {
	if f.text == "" {
		return nil
	}
	if isMarkdown(f.Path) {
		return markdownSegments(f.text)
	}
	if lang := scriptLang(f.Path, f.text); lang != "" {
		return []segment{{kind: segCode, lang: lang, text: f.text, line: 1}}
	}
	return []segment{{kind: segText, text: f.text, line: 1}}
}

var (
	fenceOpen   = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})\\s*(.*)$")
	inlineCode  = regexp.MustCompile("`+")
	htmlComment = regexp.MustCompile(`(?s)<!--(.*?)-->`)
)

// markdownSegments splits Markdown into front matter, prose, fenced code
// blocks, inline code spans and HTML comments. Comments are blanked out of
// the prose around them — spaces for every character, so offsets and lines
// stay where they were — and inline code is code and prose at once.
func markdownSegments(text string) []segment {
	var out []segment
	pos := 0
	if front, body, ok := splitFront(text); ok {
		out = append(out, segment{kind: segFront, text: front, line: 2})
		pos = body
	}
	proseStart := pos
	flushProse := func(end int) {
		if end <= proseStart {
			return
		}
		out = append(out, proseSegments(text[proseStart:end], lineOf(text, proseStart))...)
	}
	for pos < len(text) {
		line, next := lineAt(text, pos)
		m := fenceOpen.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil || (m[1][0] == '`' && strings.Contains(m[2], "`")) {
			pos = next
			continue
		}
		flushProse(pos)
		fence := m[1]
		info := strings.TrimSpace(m[2])
		lang := strings.ToLower(info)
		if i := strings.IndexAny(lang, " \t{"); i >= 0 {
			lang = lang[:i]
		}
		bodyStart := next
		end, after := len(text), len(text)
		for p := next; p < len(text); {
			l, n := lineAt(text, p)
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, fence[:1]) && strings.Trim(t, fence[:1]) == "" && len(t) >= len(fence) {
				end, after = p, n
				break
			}
			p = n
		}
		seg := segment{kind: segCode, lang: lang, text: text[bodyStart:end], line: lineOf(text, bodyStart)}
		if strings.HasPrefix(info, "!") {
			seg.loadTime = true
			seg.lang = "sh"
		}
		out = append(out, seg)
		pos = after
		proseStart = pos
	}
	flushProse(len(text))
	return out
}

// proseSegments takes a stretch of Markdown prose apart into the prose
// itself, its comments and its inline code.
func proseSegments(text string, line int) []segment {
	var out []segment
	blanked := []byte(text)
	for _, loc := range htmlComment.FindAllStringSubmatchIndex(text, -1) {
		out = append(out, segment{kind: segComment, text: text[loc[2]:loc[3]], line: line + strings.Count(text[:loc[2]], "\n")})
		for i := loc[0]; i < loc[1]; i++ {
			if blanked[i] != '\n' {
				blanked[i] = ' '
			}
		}
	}
	prose := string(blanked)
	out = append([]segment{{kind: segProse, text: prose, line: line}}, out...)
	// Inline code: a run of backticks, closed by a run of the same length.
	ticks := inlineCode.FindAllStringIndex(prose, -1)
	for i := 0; i < len(ticks); i++ {
		n := ticks[i][1] - ticks[i][0]
		for j := i + 1; j < len(ticks); j++ {
			if ticks[j][1]-ticks[j][0] != n {
				continue
			}
			body := prose[ticks[i][1]:ticks[j][0]]
			if !strings.Contains(body, "\n\n") {
				out = append(out, segment{kind: segCode, text: body, inline: true,
					line:     line + strings.Count(prose[:ticks[i][1]], "\n"),
					loadTime: ticks[i][0] > 0 && prose[ticks[i][0]-1] == '!'})
			}
			i = j
			break
		}
	}
	return out
}

// lineOf is the 1-based line an offset is on.
func lineOf(text string, off int) int {
	if off > len(text) {
		off = len(text)
	}
	return 1 + strings.Count(text[:off], "\n")
}
