package policy

import (
	"path"
	"regexp"
	"strings"
)

// A rule's regex sees a value as it was written. A shell and a database do
// not: to a shell "rm", r''m and \rm are all rm, and to a database a comment
// is a space. shell_regex and sql_regex match against what they see, so a
// rule about rm cannot be stepped around by spelling rm differently.

func (m *Matcher) text(v any) string {
	s := stringify(v)
	if m.view != nil {
		return m.view(s)
	}
	return s
}

var (
	ifs        = regexp.MustCompile(`\$\{?IFS\}?`)
	blanks     = regexp.MustCompile(`[ \t]+`)
	sqlComment = regexp.MustCompile(`/\*[\s\S]*?(\*/|$)|--[^\n]*`)
	sqlSpace   = regexp.MustCompile(`\s+`)
)

// ShellView is a command as a POSIX shell reads its words: quotes join
// rather than separate (an empty pair of quotes inside rm, or "rm", is
// still rm), a backslash before a character is the character, $IFS is a
// space, and runs of blanks are one.
// It is a view for matching, not a shell parser: it errs towards finding a
// command in a string that only mentions it.
func ShellView(s string) string {
	s = ifs.ReplaceAllString(s, " ")
	var b strings.Builder
	b.Grow(len(s))
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			escaped = false
			if r != '\n' {
				b.WriteRune(r)
			}
		case r == '\\':
			escaped = true
		case r == '\'' || r == '"':
		default:
			b.WriteRune(r)
		}
	}
	return blanks.ReplaceAllString(b.String(), " ")
}

// SQLView is a statement as a database tokenizes it: comments are spaces
// and every run of whitespace is one space.
func SQLView(s string) string {
	s = sqlComment.ReplaceAllString(s, " ")
	return strings.TrimSpace(sqlSpace.ReplaceAllString(s, " "))
}

// PathView is a path as a file system resolves it: backslashes are
// separators, and . and .. are taken out. A relative path stays relative.
func PathView(p string) string {
	if p == "" {
		return ""
	}
	return path.Clean(strings.ReplaceAll(p, "\\", "/"))
}

// underPath reports whether p is dir or inside it, once both are resolved.
func underPath(p, dir string) bool {
	pv, dv := PathView(p), PathView(dir)
	if dv == "/" {
		return strings.HasPrefix(pv, "/")
	}
	return pv == dv || strings.HasPrefix(pv, dv+"/")
}
