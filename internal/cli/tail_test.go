package cli

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/policy"
)

var ansi = regexp.MustCompile("\033\\[[0-9;]*m")

func TestTailLinesFitTheTerminal(t *testing.T) {
	for _, colour := range []bool{false, true} {
		var buf bytes.Buffer
		w := &lineWriter{out: &buf, colour: colour, width: 100, toolWidth: 20}
		at := time.Date(2026, 9, 27, 18, 0, 0, 0, time.Local)
		w.write(&audit.Call{TS: at, Tool: "fs__read_file", Decision: policy.ActionAllow, Reason: "default allow", DurationMS: 2})
		w.write(&audit.Call{TS: at, Tool: "mail__send_message", Decision: policy.ActionDeny, RuleID: "lethal-trifecta/injected-egress",
			Reason: "this session read a tool result with hidden text or instructions aimed at the model; nothing leaves it now"})
		w.write(&audit.Call{TS: at, Tool: "web__fetch", Decision: policy.ActionAllow, Labels: []string{"injection-suspected", "untrusted-input"}, DurationMS: 1})

		lines := strings.Split(strings.TrimRight(ansi.ReplaceAllString(buf.String(), ""), "\n"), "\n")
		require.Len(t, lines, 3)
		for _, l := range lines {
			require.LessOrEqual(t, utf8.RuneCountInString(l), 100, l)
			// The columns line up whatever the tool, coloured or not.
			require.Equal(t, strings.Index(lines[0], "ms  "), strings.Index(l, "ms  "), "colour %v:\n%s", colour, strings.Join(lines, "\n"))
		}
		require.Contains(t, lines[1], "DENY")
		require.True(t, strings.HasSuffix(lines[1], "…"), lines[1])
		require.True(t, strings.HasSuffix(lines[2], "+injection-suspected +untrusted-input"), lines[2])
	}
}

func TestTruncateKeepsCharactersWhole(t *testing.T) {
	require.Equal(t, "ab…", truncate("ab—cdef", 3))
	require.Equal(t, "a—b", truncate("a—b", 3))
	require.True(t, utf8.ValidString(truncate(strings.Repeat("—", 50), 10)))
	require.Equal(t, "a b", truncate("a\nb", 10))
}
