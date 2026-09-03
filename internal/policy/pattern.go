package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// pattern is a compiled "tool:" expression. Three spellings are supported:
//
//	fs__write_file                    exact name
//	fs.*                              glob, * and ? are wildcards
//	shopware.*_search|shopware.*_get  alternation of globs, split on |
//	/^fs__(read|write)_file$/         regular expression, delimited by slashes
//
// Globs are anchored: the whole tool name has to match.
type pattern struct {
	src string
	re  *regexp.Regexp
}

func compilePattern(src string) (*pattern, error) {
	if src == "" {
		return nil, nil
	}
	if len(src) >= 2 && strings.HasPrefix(src, "/") && strings.HasSuffix(src, "/") {
		body := src[1 : len(src)-1]
		re, err := regexp.Compile(body)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", body, err)
		}
		return &pattern{src: src, re: re}, nil
	}
	alts := strings.Split(src, "|")
	parts := make([]string, 0, len(alts))
	for _, alt := range alts {
		alt = strings.TrimSpace(alt)
		if alt == "" {
			continue
		}
		parts = append(parts, globToRegex(alt))
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty tool pattern %q", src)
	}
	re, err := regexp.Compile("^(?:" + strings.Join(parts, "|") + ")$")
	if err != nil {
		return nil, fmt.Errorf("invalid tool pattern %q: %w", src, err)
	}
	return &pattern{src: src, re: re}, nil
}

// globToRegex converts a glob to an unanchored regex fragment. Every character
// except * and ? is taken literally, so a dot in "fs.read" only matches a dot.
func globToRegex(glob string) string {
	var b strings.Builder
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return b.String()
}

func (p *pattern) matchAny(names []string) bool {
	for _, n := range names {
		if p.re.MatchString(n) {
			return true
		}
	}
	return false
}

func (p *pattern) String() string { return p.src }
