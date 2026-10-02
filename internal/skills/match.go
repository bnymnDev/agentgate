package skills

import (
	"regexp"
	"sort"
	"strings"
)

// pattern is a regular expression with the keywords one of which every match
// contains. Go's regexp engine is linear but not fast on long alternations,
// so a pattern runs only on the lines where a keyword occurs — found by a
// plain substring search — and on the line before and the lines after them,
// for a match that wraps. Keywords are lowercase ASCII and are looked up in a lowercased
// copy of the text.
type pattern struct {
	re   *regexp.Regexp
	keys []string
}

// wrapLines is how many lines after a keyword's own a match may run on to.
const wrapLines = 2

func pat(re string, keys ...string) pattern {
	return pattern{re: regexp.MustCompile(re), keys: keys}
}

// lowerASCII lowercases ASCII letters only, so every byte offset of the
// result is the same as in s.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// findAll returns every match in text; lower is lowerASCII(text).
func (p pattern) findAll(text, lower string) [][]int {
	if len(p.keys) == 0 {
		return p.re.FindAllStringIndex(text, -1)
	}
	var out [][]int
	seen := map[int]bool{}
	for _, w := range windows(lower, p.keys) {
		for _, loc := range p.re.FindAllStringIndex(text[w[0]:w[1]], -1) {
			start := loc[0] + w[0]
			if !seen[start] {
				seen[start] = true
				out = append(out, []int{start, loc[1] + w[0]})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// find returns the first match, or nil.
func (p pattern) find(text, lower string) []int {
	if all := p.findAll(text, lower); len(all) > 0 {
		return all[0]
	}
	return nil
}

// windows are the stretches of text a pattern needs to read: each line a
// keyword is on, through wrapLines lines after it, merged where they meet.
func windows(lower string, keys []string) [][2]int {
	var spans [][2]int
	for _, k := range keys {
		for off := 0; ; {
			i := strings.Index(lower[off:], k)
			if i < 0 {
				break
			}
			at := off + i
			// From the line before the keyword's — a match may start on it
			// when prose is wrapped — through wrapLines lines after.
			start := strings.LastIndexByte(lower[:at], '\n') + 1
			if start > 0 {
				start = strings.LastIndexByte(lower[:start-1], '\n') + 1
			}
			end := at
			for n := 0; n <= wrapLines && end < len(lower); n++ {
				j := strings.IndexByte(lower[end:], '\n')
				if j < 0 {
					end = len(lower)
					break
				}
				end += j + 1
			}
			spans = append(spans, [2]int{start, end})
			off = max(at+len(k), end-1)
			if off >= len(lower) {
				break
			}
		}
	}
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	out := spans[:1]
	for _, s := range spans[1:] {
		last := &out[len(out)-1]
		if s[0] <= last[1] {
			last[1] = max(last[1], s[1])
			continue
		}
		out = append(out, s)
	}
	return out
}
