// Package report renders one session as a single HTML file: what the agent
// did, what was stopped and why, and where the calls sit in the audit
// chain. The file has no scripts and loads nothing, so it can be mailed,
// attached to a ticket or archived and still open in ten years.
package report

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/policy"
)

//go:embed report.html.tmpl
var files embed.FS

var page = template.Must(template.New("report.html.tmpl").Funcs(template.FuncMap{
	"pretty":   pretty,
	"offset":   offset,
	"ms":       func(n int64) string { return (time.Duration(n) * time.Millisecond).String() },
	"local":    func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05 MST") },
	"decision": decisionClass,
	"join":     strings.Join,
}).ParseFS(files, "report.html.tmpl"))

// Input is what a report is made from.
type Input struct {
	Session *audit.Session
	Calls   []*audit.Call
	// Chain is the verification of the whole log, if it was run.
	Chain *audit.VerifyReport
	// Version is agentgate's, for the footer.
	Version string
	// Now is when the report was made.
	Now time.Time
}

type toolRow struct {
	Name    string
	Calls   int
	Denied  int
	Errors  int
	TotalMS int64
}

type mark struct {
	X     float64
	Class string
	Title string
}

type view struct {
	Input
	Allowed, Denied, Asked, Shadow, Errors, Tokens int
	Labels                                         []string
	Stopped                                        []*audit.Call
	Tools                                          []toolRow
	Marks                                          []mark
	Duration                                       time.Duration
	FirstSeq, LastSeq                              int64
	ChainOK                                        bool
	ChainProblems                                  []audit.ChainProblem
}

// Write renders the report.
func Write(w io.Writer, in Input) error {
	v := view{Input: in}
	if in.Now.IsZero() {
		v.Now = time.Now()
	}
	end := in.Session.StartedAt
	if in.Session.EndedAt != nil {
		end = *in.Session.EndedAt
	}
	labels := map[string]bool{}
	tools := map[string]*toolRow{}
	for _, c := range in.Calls {
		switch {
		case c.Shadow:
			v.Shadow++
		case c.Decision == policy.ActionDeny:
			v.Denied++
			v.Stopped = append(v.Stopped, c)
		default:
			v.Allowed++
		}
		if strings.Contains(c.Reason, "approved by") || strings.Contains(c.Reason, "rejected by") {
			v.Asked++
		}
		if c.IsError || c.Error != "" {
			v.Errors++
		}
		v.Tokens += c.TokensEst
		for _, l := range c.Labels {
			labels[l] = true
		}
		row := tools[c.Tool]
		if row == nil {
			row = &toolRow{Name: c.Tool}
			tools[c.Tool] = row
		}
		row.Calls++
		row.TotalMS += c.DurationMS
		if c.Decision == policy.ActionDeny && !c.Shadow {
			row.Denied++
		}
		if c.IsError || c.Error != "" {
			row.Errors++
		}
		if done := c.TS.Add(time.Duration(c.DurationMS) * time.Millisecond); done.After(end) {
			end = done
		}
		if c.Seq > 0 {
			if v.FirstSeq == 0 || c.Seq < v.FirstSeq {
				v.FirstSeq = c.Seq
			}
			v.LastSeq = max(v.LastSeq, c.Seq)
		}
	}
	v.Duration = end.Sub(in.Session.StartedAt)
	for l := range labels {
		v.Labels = append(v.Labels, l)
	}
	sort.Strings(v.Labels)
	for _, r := range tools {
		v.Tools = append(v.Tools, *r)
	}
	sort.Slice(v.Tools, func(i, j int) bool {
		if v.Tools[i].Calls != v.Tools[j].Calls {
			return v.Tools[i].Calls > v.Tools[j].Calls
		}
		return v.Tools[i].Name < v.Tools[j].Name
	})
	span := v.Duration.Seconds()
	for _, c := range in.Calls {
		x := 0.0
		if span > 0 {
			x = c.TS.Sub(in.Session.StartedAt).Seconds() / span * 1000
		}
		v.Marks = append(v.Marks, mark{X: min(max(x, 0), 1000), Class: decisionClass(c), Title: offset(in.Session.StartedAt, c.TS) + " " + c.Tool + " " + string(c.Decision)})
	}
	if in.Chain != nil {
		v.ChainOK = true
		for _, p := range in.Chain.Problems {
			if p.Seq >= v.FirstSeq && p.Seq <= v.LastSeq {
				v.ChainOK = false
				v.ChainProblems = append(v.ChainProblems, p)
			}
		}
	}
	var buf bytes.Buffer
	if err := page.Execute(&buf, v); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func decisionClass(c *audit.Call) string {
	switch {
	case c.Shadow:
		return "shadow"
	case c.Decision == policy.ActionDeny:
		return "deny"
	case c.IsError || c.Error != "":
		return "error"
	default:
		return "allow"
	}
}

// pretty indents JSON for reading; anything else is shown as it is.
func pretty(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return string(raw)
	}
	return out.String()
}

func offset(start, at time.Time) string {
	d := at.Sub(start)
	if d < 0 {
		d = 0
	}
	return fmt.Sprintf("+%02d:%02d:%02d", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
}
