package skills

import (
	"fmt"
	"net/url"
	"strings"
)

// Markdown renders the reports for a pull request comment or a CI job
// summary: a table of every skill, and for each one that needs a human, what
// changed and what its instructions now say. Everything taken from a skill is
// revealed (hidden characters spelled out) and escaped, so a skill cannot
// break out of the code block or the table it is shown in.
func Markdown(reports []Report, lockfile string) string {
	var b strings.Builder
	pending := 0
	for _, r := range reports {
		if !r.Clean() {
			pending++
		}
	}
	switch {
	case len(reports) == 0:
		b.WriteString("### agentgate skills: no skills found\n")
		return b.String()
	case pending == 0:
		fmt.Fprintf(&b, "### agentgate skills: all %d skill(s) match %s\n\n", len(reports), mdCode(lockfile))
	default:
		fmt.Fprintf(&b, "### agentgate skills: %d of %d skill(s) need approval\n\n", pending, len(reports))
	}
	b.WriteString("| Skill | Status | Label | New capabilities | Unapproved findings |\n|---|---|---|---|---|\n")
	for _, r := range reports {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", mdCode(r.Key), r.Status, orDash(strings.Join(r.Label, ", ")),
			orDash(bold(r.Gained)), orDash(severityCounts(r.Unaccepted)))
	}
	for _, r := range reports {
		if r.Clean() {
			continue
		}
		fmt.Fprintf(&b, "\n<details open><summary><b>%s</b> — %s</summary>\n\n", mdText(r.Key), r.Status)
		writeDetails(&b, r)
		b.WriteString("\n</details>\n")
	}
	if pending > 0 {
		fmt.Fprintf(&b, "\nReview the changes, then approve them with %s, or each skill with %s, and commit %s.\n",
			mdCode("agentgate skills approve --all"), mdCode("agentgate skills approve <skill>"), mdCode(lockfile))
	}
	return b.String()
}

func writeDetails(b *strings.Builder, r Report) {
	switch r.Status {
	case StatusRemoved:
		b.WriteString("The skill is in the lockfile but no longer on disk.\n")
		return
	case StatusRescanned:
		b.WriteString("No file changed, but this agentgate finds capabilities or findings the lockfile does not record.\n\n")
	case StatusNew:
		b.WriteString("Not in the lockfile yet.\n\n")
	}
	if len(r.Gained) > 0 {
		b.WriteString("**New capabilities**\n\n")
		for _, c := range r.Gained {
			fmt.Fprintf(b, "- **%s** — %s%s\n", c, CapabilityTitle(c), evidenceFor(r, c))
		}
		b.WriteString("\n")
	}
	if len(r.Lost) > 0 {
		fmt.Fprintf(b, "**No longer:** %s\n\n", strings.Join(r.Lost, ", "))
	}
	if len(r.NewHosts) > 0 {
		hosts := make([]string, len(r.NewHosts))
		for i, h := range r.NewHosts {
			hosts[i] = mdCode(h)
		}
		fmt.Fprintf(b, "**New hosts:** %s\n\n", strings.Join(hosts, ", "))
	}
	if len(r.Files) > 0 && r.Status != StatusNew {
		parts := make([]string, len(r.Files))
		for i, f := range r.Files {
			parts[i] = f.Change + " " + mdCode(f.Path)
		}
		fmt.Fprintf(b, "**Files:** %s\n\n", strings.Join(parts, ", "))
	}
	if len(r.Unaccepted) > 0 {
		b.WriteString("**Findings not yet approved**\n\n")
		for _, f := range r.Unaccepted {
			fmt.Fprintf(b, "- %s %s %s %s — %s\n", severityMark(f.Severity), f.Severity, mdCode(f.Rule), mdCode(f.Where()), mdText(f.Detail))
			if f.Excerpt != "" {
				fmt.Fprintf(b, "  %s\n", mdCode((f.Excerpt)))
			}
		}
		b.WriteString("\n")
	}
	if r.Skill == nil {
		return
	}
	before := ""
	if r.Entry != nil {
		before = r.Entry.Instructions
	}
	if d := ProseDiff(before, r.Skill.Manifest()); len(d) > 0 {
		b.WriteString("**What SKILL.md now says**\n\n")
		b.WriteString(MarkdownDiff(d))
	}
}

func evidenceFor(r Report, capability string) string {
	for _, e := range r.Labelled.Evidence {
		if e.Capability == capability {
			return ": " + mdCode(e.Where()) + " " + mdCode((e.Excerpt))
		}
	}
	return ""
}

// MarkdownDiff renders a prose diff as a diff code block. Added sentences
// that give an order are marked [imperative], and every rule an added unit
// trips is named after it.
func MarkdownDiff(d []DiffLine) string {
	var lines []string
	for _, l := range d {
		if l.Op == "…" {
			lines = append(lines, "  …")
			continue
		}
		op := " "
		if l.Op != "=" {
			op = l.Op
		}
		var tags []string
		if l.Imperative {
			tags = append(tags, "imperative")
		}
		tags = append(tags, l.Rules...)
		text := Reveal(l.Text)
		if len(tags) > 0 {
			text = "[" + strings.Join(tags, ", ") + "] " + text
		}
		lines = append(lines, fmt.Sprintf("%s %4d  %s", op, l.Line, text))
	}
	body := strings.Join(lines, "\n")
	fence := fenceFor(body, '`')
	return fence + "diff\n" + body + "\n" + fence + "\n"
}

// Badge is a shields.io badge of a skill's label, as Markdown, for the
// skill's README. Building the link sends nothing anywhere; showing the image
// asks shields.io to draw it.
func Badge(l Label) string {
	msg := "no capabilities"
	if len(l.Capabilities) > 0 {
		msg = strings.Join(l.Capabilities, " · ")
	}
	colour := "brightgreen"
	switch {
	case l.Has("external-include") || l.Has("secrets") || l.Has("auto-trigger"):
		colour = "orange"
	case len(l.Capabilities) > 0:
		colour = "yellow"
	}
	return fmt.Sprintf("![skill: %s](https://img.shields.io/badge/%s-%s-%s)", msg, shieldsEscape("skill"), shieldsEscape(msg), colour)
}

func shieldsEscape(s string) string {
	s = strings.NewReplacer("-", "--", "_", "__").Replace(s)
	return strings.ReplaceAll(url.PathEscape(s), "%20", "_")
}

// LabelMarkdown renders a skill's label: its badge, and a table of what it
// can do with where each capability was seen.
func LabelMarkdown(key string, l Label) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#### %s\n\n%s\n\n", mdText(key), Badge(l))
	if len(l.Capabilities) == 0 {
		b.WriteString("No capabilities: the skill is instructions only.\n")
		return b.String()
	}
	b.WriteString("| Capability | | Seen at |\n|---|---|---|\n")
	for _, c := range l.Capabilities {
		var where []string
		for _, e := range l.Evidence {
			if e.Capability == c && len(where) < 3 {
				where = append(where, mdCode(e.Where())+" "+mdCode((e.Excerpt)))
			}
		}
		fmt.Fprintf(&b, "| **%s** | %s | %s |\n", c, CapabilityTitle(c), strings.Join(where, "<br>"))
	}
	if len(l.Hosts) > 0 {
		hosts := make([]string, len(l.Hosts))
		for i, h := range l.Hosts {
			hosts[i] = mdCode(h)
		}
		fmt.Fprintf(&b, "\nHosts: %s\n", strings.Join(hosts, ", "))
	}
	return b.String()
}

// mdCode is an inline code span that holds s, revealed, whatever backticks
// it has. Line breaks become spaces, and a pipe is escaped so a table cell stays one cell.
func mdCode(s string) string {
	s = strings.Join(strings.Fields(Reveal(s)), " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	fence := strings.Repeat("`", longestRun(s, '`')+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return fence + s + fence
}

// mdText escapes s for Markdown prose and table cells.
func mdText(s string) string {
	s = strings.Join(strings.Fields(Reveal(s)), " ")
	return strings.NewReplacer("\\", "\\\\", "|", `\|`, "<", "&lt;", ">", "&gt;", "`", "\\`", "*", "\\*",
		"_", "\\_", "[", "\\[", "]", "\\]", "@", "&#64;").Replace(s)
}

// fenceFor is a code fence longer than any run of c in s, and at least
// three long, so the block cannot be closed from inside.
func fenceFor(s string, c byte) string {
	return strings.Repeat(string(c), max(3, longestRun(s, c)+1))
}

func longestRun(s string, c byte) int {
	longest, run := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	return longest
}

func bold(list []string) string {
	out := make([]string, len(list))
	for i, v := range list {
		out[i] = "**" + v + "**"
	}
	return strings.Join(out, ", ")
}

func severityCounts(fs []Finding) string {
	counts := map[Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range []Severity{High, Medium, Low} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return strings.Join(parts, ", ")
}

func severityMark(s Severity) string {
	switch s {
	case High:
		return "🔴"
	case Medium:
		return "🟠"
	}
	return "⚪"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
