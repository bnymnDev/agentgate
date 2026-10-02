package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/skills"
)

func newSkillsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "skills",
		Short: "Pin Agent Skills in a lockfile, label what they can do, and review every change",
		Long: `Agent Skills — a SKILL.md and the scripts next to it — are instructions a
coding agent loads and follows. agentgate treats them like any other
dependency: skills.lock pins every file of every skill by a Merkle root,
records a label of what each skill can do, and keeps the findings a human
approved. A skill that changes, gains a capability or picks up a new finding
is drift until someone looks at it:

	agentgate skills lock              pin the skills that are not pinned yet
	agentgate skills verify            exit 1 on any change nobody approved
	agentgate skills diff              what changed, sentence by sentence
	agentgate skills approve <skill>   accept a skill as it is now
	agentgate skills label             what each skill can do, and where it says so
	agentgate skills scan ./some-skill vet a skill before you install it

Skills are looked for where agents look for them: .claude/skills,
.agents/skills and .codex/skills in the project, ~/.claude/skills,
~/.agents/skills, ~/.codex/skills and Claude Code plugins with --user, and
anywhere else with --path. Nothing here needs agentgate.yaml or the network.`,
	}
	cmd.AddCommand(
		newSkillsLockCmd(),
		newSkillsVerifyCmd(),
		newSkillsDiffCmd(),
		newSkillsApproveCmd(),
		newSkillsLabelCmd(),
		newSkillsScanCmd(),
	)
	return cmd
}

// skillFlags are the flags every skills command that reads the lockfile
// takes.
type skillFlags struct {
	dir      string
	lockfile string
	paths    []string
	user     bool
	colour   string
}

func (f *skillFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.dir, "dir", ".", "the project directory: skills are looked for, and keyed, relative to it")
	cmd.Flags().StringVar(&f.lockfile, "lockfile", "", "the lockfile (default <dir>/skills.lock)")
	cmd.Flags().StringArrayVar(&f.paths, "path", nil, "also look in this directory, relative to --dir; a glob, a skills directory or one skill (repeatable; remembered in the lockfile)")
	cmd.Flags().BoolVar(&f.user, "user", false, "also look in ~/.claude/skills, ~/.agents/skills, ~/.codex/skills and Claude Code plugins (remembered in the lockfile)")
	cmd.Flags().StringVar(&f.colour, "color", "auto", "colour the output: auto, always or never")
}

// session is a lockfile and the skills on disk, compared.
type session struct {
	lock    *skills.Lockfile
	reports []skills.Report
	w       *lineWriter
}

func (f *skillFlags) open(cmd *cobra.Command) (*session, error) {
	useColour, err := colourFlag(f.colour)
	if err != nil {
		return nil, err
	}
	path := f.lockfile
	if path == "" {
		path = filepath.Join(f.dir, skills.DefaultLockfile)
	}
	lock, err := skills.LoadLockfile(path)
	if err != nil {
		return nil, err
	}
	// Look where the lockfile was made, and wherever else this run asks.
	paths := append(append([]string{}, lock.Paths...), f.paths...)
	lock.Paths = dedupeStrings(paths)
	lock.User = lock.User || f.user
	found, err := skills.Discover(skills.Options{Dir: f.dir, Paths: lock.Paths, User: lock.User})
	if err != nil {
		return nil, err
	}
	return &session{lock: lock, reports: lock.Check(found), w: &lineWriter{out: cmd.OutOrStdout(), colour: useColour}}, nil
}

// pick returns the reports a list of names on the command line means.
func (s *session) pick(names []string) ([]skills.Report, error) {
	if len(names) == 0 {
		return s.reports, nil
	}
	var out []skills.Report
	for _, n := range names {
		found := false
		for _, r := range s.reports {
			if r.Match(n) {
				out = append(out, r)
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("no skill called %q; agentgate skills label lists them", n)
		}
	}
	return out, nil
}

func dedupeStrings(list []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range list {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func approver(by string) string {
	if by != "" {
		return by
	}
	for _, k := range []string{"USER", "USERNAME", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func newSkillsLockCmd() *cobra.Command {
	var (
		f      skillFlags
		by     string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Pin every skill that is not in skills.lock yet",
		Long: `Pin every skill that is not in the lockfile yet: its files by a Merkle root,
its label, and the findings it has now, which you are accepting by pinning
it. Read what lock prints. A skill that is already pinned and has changed
is left alone: review it with agentgate skills diff and accept it with
agentgate skills approve.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := f.open(cmd)
			if err != nil {
				return err
			}
			var pinned []skills.Report
			for _, r := range s.reports {
				if r.Status == skills.StatusNew {
					s.lock.Approve(r, approver(by), time.Now())
					pinned = append(pinned, r)
				}
			}
			if len(pinned) > 0 || !s.lock.Exists() || len(f.paths) > 0 || f.user {
				if err := s.lock.Save(); err != nil {
					return err
				}
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), pinned)
			}
			for _, r := range pinned {
				fmt.Fprintf(s.w.out, "pinned %s  %s\n", skills.Reveal(r.Key), s.w.dim(labelText(r.Label)))
				printFindings(s.w, r.Findings, "  ")
			}
			if len(pinned) > 0 {
				fmt.Fprintln(s.w.out)
			}
			printSkillTable(s.w, s.lock, s.reports)
			return nil
		},
	}
	f.register(cmd)
	cmd.Flags().StringVar(&by, "by", "", "who is approving, for the lockfile (default $USER)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the skills pinned as JSON")
	return cmd
}

func newSkillsVerifyCmd() *cobra.Command {
	var (
		f        skillFlags
		asJSON   bool
		markdown bool
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Exit 1 if any skill changed, gained a capability or appeared since it was approved",
		Long: `Compare every skill with the lockfile and exit 1 unless all of them are
exactly what was approved: a changed file, a new or removed skill, a new
capability or a new finding all fail. This is the CI gate.

--markdown writes the report for a pull request comment or the job summary,
with the prose diff of every changed SKILL.md.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := f.open(cmd)
			if err != nil {
				return err
			}
			switch {
			case asJSON:
				if err := writeJSON(cmd.OutOrStdout(), s.reports); err != nil {
					return err
				}
			case markdown:
				fmt.Fprint(cmd.OutOrStdout(), skills.Markdown(s.reports, displayPath(s.lock.Path())))
			default:
				printVerify(s)
			}
			for _, r := range s.reports {
				if !r.Clean() {
					return errExitDenied
				}
			}
			return nil
		},
	}
	f.register(cmd)
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the reports as JSON")
	cmd.Flags().BoolVar(&markdown, "markdown", false, "print the report as Markdown, for a pull request or a job summary")
	return cmd
}

func newSkillsDiffCmd() *cobra.Command {
	var (
		f        skillFlags
		markdown bool
	)
	cmd := &cobra.Command{
		Use:   "diff [skill...]",
		Short: "Show what changed in a skill since it was approved, sentence by sentence",
		Long: `Show, for every skill that is not as it was approved (or for the skills
named), which files changed, which capabilities and hosts are new, the
findings nobody approved, and a diff of SKILL.md by sentence: one new
sentence in a long paragraph shows as one new sentence. An added sentence
that gives the model an order is marked imperative, and every rule an added
sentence trips is named next to it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := f.open(cmd)
			if err != nil {
				return err
			}
			picked, err := s.pick(args)
			if err != nil {
				return err
			}
			var shown []skills.Report
			for _, r := range picked {
				if !r.Clean() {
					shown = append(shown, r)
				}
			}
			if markdown {
				fmt.Fprint(cmd.OutOrStdout(), skills.Markdown(shown, displayPath(s.lock.Path())))
				return nil
			}
			if len(shown) == 0 {
				fmt.Fprintln(s.w.out, "no changes: every skill is as it was approved")
				return nil
			}
			for i, r := range shown {
				if i > 0 {
					fmt.Fprintln(s.w.out)
				}
				printDetails(s.w, r)
			}
			return nil
		},
	}
	f.register(cmd)
	cmd.Flags().BoolVar(&markdown, "markdown", false, "print the diff as Markdown")
	return cmd
}

func newSkillsApproveCmd() *cobra.Command {
	var (
		f   skillFlags
		all bool
		by  string
	)
	cmd := &cobra.Command{
		Use:   "approve [skill...]",
		Short: "Accept skills as they are now: files, label and findings",
		Long: `Record skills in the lockfile as they are now — their files, their label and
every finding they have — after you have read agentgate skills diff. A
skill is named by its directory (.claude/skills/pdf), its last element (pdf)
or its name. --all approves every skill that needs it; a removed skill is
dropped from the lockfile.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if all == (len(args) > 0) {
				return errors.New("name the skills to approve, or pass --all")
			}
			s, err := f.open(cmd)
			if err != nil {
				return err
			}
			picked, err := s.pick(args)
			if err != nil {
				return err
			}
			n := 0
			for _, r := range picked {
				if r.Clean() {
					if !all {
						fmt.Fprintf(s.w.out, "%s is already approved as it is\n", skills.Reveal(r.Key))
					}
					continue
				}
				s.lock.Approve(r, approver(by), time.Now())
				n++
				switch r.Status {
				case skills.StatusRemoved:
					fmt.Fprintf(s.w.out, "dropped %s %s\n", skills.Reveal(r.Key), s.w.dim("(removed from disk)"))
				default:
					note := labelText(r.Label)
					if k := len(r.Findings); k > 0 {
						note += fmt.Sprintf("; %d finding(s) accepted", k)
					}
					fmt.Fprintf(s.w.out, "approved %s %s  %s\n", skills.Reveal(r.Key), s.w.dim("(was "+string(r.Status)+")"), s.w.dim(note))
				}
			}
			if n == 0 {
				return nil
			}
			if err := s.lock.Save(); err != nil {
				return err
			}
			fmt.Fprintf(s.w.out, "\n%s\n", s.w.dim("wrote "+displayPath(s.lock.Path())+"; commit it with the change"))
			return nil
		},
	}
	f.register(cmd)
	cmd.Flags().BoolVar(&all, "all", false, "approve every skill that is not as it was approved")
	cmd.Flags().StringVar(&by, "by", "", "who is approving, for the lockfile (default $USER)")
	return cmd
}

func newSkillsLabelCmd() *cobra.Command {
	var (
		f        skillFlags
		asJSON   bool
		markdown bool
	)
	cmd := &cobra.Command{
		Use:   "label [skill...]",
		Short: "Show what each skill can do, and where it says so",
		Long: `Derive each skill's label — shell, scripts, network, urls, secrets, file
writes outside the project, package installs, content fetched from elsewhere,
hooks, pre-approved tools — and show where in the skill each capability was
seen. --markdown writes a shields.io badge and a table for the skill's README.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := f.open(cmd)
			if err != nil {
				return err
			}
			picked, err := s.pick(args)
			if err != nil {
				return err
			}
			var present []skills.Report
			for _, r := range picked {
				if r.Skill != nil {
					present = append(present, r)
				}
			}
			switch {
			case asJSON:
				type labelled struct {
					Key   string       `json:"key"`
					Name  string       `json:"name"`
					Label skills.Label `json:"label"`
				}
				out := make([]labelled, len(present))
				for i, r := range present {
					out[i] = labelled{r.Key, r.Name, r.Labelled}
				}
				return writeJSON(cmd.OutOrStdout(), out)
			case markdown:
				for i, r := range present {
					if i > 0 {
						fmt.Fprintln(cmd.OutOrStdout())
					}
					fmt.Fprint(cmd.OutOrStdout(), skills.LabelMarkdown(r.Key, r.Labelled))
				}
				return nil
			}
			if len(present) == 0 {
				fmt.Fprintln(s.w.out, "no skills found")
				return nil
			}
			for i, r := range present {
				if i > 0 {
					fmt.Fprintln(s.w.out)
				}
				printLabel(s.w, r.Key, r.Labelled)
				printFindings(s.w, r.Findings, "  ")
			}
			return nil
		},
	}
	f.register(cmd)
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the labels as JSON")
	cmd.Flags().BoolVar(&markdown, "markdown", false, "print a badge and a table per skill, as Markdown")
	return cmd
}

func newSkillsScanCmd() *cobra.Command {
	var (
		failOn string
		asJSON bool
		colour string
	)
	cmd := &cobra.Command{
		Use:   "scan <skill-dir>...",
		Short: "Vet skills before you install them: label and findings, no lockfile",
		Long: `Read skill directories — one skill, or a directory of them — and show
their label and everything the rules find. Nothing is written. Exit 1 when a
finding is at least as severe as --fail-on.

	agentgate skills scan ./downloaded/pdf-tools
	agentgate skills scan ~/src/team-skills/skills --fail-on medium`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			useColour, err := colourFlag(colour)
			if err != nil {
				return err
			}
			threshold, err := skills.ParseSeverity(failOn)
			if err != nil {
				return fmt.Errorf("--fail-on: %w", err)
			}
			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			found, err := skills.Discover(skills.Options{Dir: wd, Paths: args, PathsOnly: true})
			if err != nil {
				return err
			}
			if len(found) == 0 {
				return fmt.Errorf("no skill found in %s: a skill is a directory with a %s", strings.Join(args, ", "), skills.ManifestName)
			}
			type scanned struct {
				Key      string           `json:"key"`
				Name     string           `json:"name"`
				Root     string           `json:"root"`
				Label    skills.Label     `json:"label"`
				Findings []skills.Finding `json:"findings"`
			}
			var out []scanned
			fail := false
			for _, s := range found {
				fs := skills.Scan(s)
				for _, f := range fs {
					if threshold != "" && f.Severity.Rank() >= threshold.Rank() {
						fail = true
					}
				}
				out = append(out, scanned{s.Key, s.Name, s.Root, skills.Derive(s), fs})
			}
			if asJSON {
				if err := writeJSON(cmd.OutOrStdout(), out); err != nil {
					return err
				}
			} else {
				w := &lineWriter{out: cmd.OutOrStdout(), colour: useColour}
				for i, s := range out {
					if i > 0 {
						fmt.Fprintln(w.out)
					}
					printLabel(w, s.Key, s.Label)
					if len(s.Findings) == 0 {
						fmt.Fprintf(w.out, "  %s\n", w.paint(colourGreen, "no findings"))
					}
					printFindings(w, s.Findings, "  ")
				}
			}
			if fail {
				return errExitDenied
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 on a finding this severe or worse: high, medium, low or none")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the results as JSON")
	cmd.Flags().StringVar(&colour, "color", "auto", "colour the output: auto, always or never")
	return cmd
}

// displayPath shows a path relative to the working directory when it is
// below it.
func displayPath(p string) string {
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if rel, err := filepath.Rel(wd, abs); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return p
}

func labelText(label []string) string {
	if len(label) == 0 {
		return "no capabilities"
	}
	return strings.Join(label, ", ")
}

func (w *lineWriter) status(s skills.Status) string {
	switch s {
	case skills.StatusLocked:
		return w.paint(colourGreen, string(s))
	case skills.StatusRemoved:
		return w.paint(colourPurple, string(s))
	}
	return w.paint(colourYellow, string(s))
}

func (w *lineWriter) severity(s skills.Severity) string {
	text := fmt.Sprintf("%-6s", s)
	switch s {
	case skills.High:
		return w.paint(colourRed, text)
	case skills.Medium:
		return w.paint(colourYellow, text)
	}
	return w.dim(text)
}

func printSkillTable(w *lineWriter, lock *skills.Lockfile, reports []skills.Report) {
	fmt.Fprintf(w.out, "lockfile  %s\n\n", displayPath(lock.Path()))
	if len(reports) == 0 {
		fmt.Fprintln(w.out, "no skills found; agentgate looks in .claude/skills, .agents/skills and .codex/skills (more with --path and --user)")
		return
	}
	// Plain text: colour codes would throw the columns out.
	t := newTable(w.out, "SKILL", "STATUS", "LABEL", "FINDINGS")
	for _, r := range reports {
		findings := "-"
		if n := len(r.Unaccepted); n > 0 {
			findings = fmt.Sprintf("%d new", n)
		} else if n := len(r.Findings); n > 0 {
			findings = fmt.Sprintf("%d accepted", n)
		}
		label := labelText(r.Label)
		if len(r.Gained) > 0 && r.Status != skills.StatusNew {
			label += " (+" + strings.Join(r.Gained, ", +") + ")"
		}
		t.row(truncate(skills.Reveal(r.Key), 48), r.Status, truncate(label, 60), findings)
	}
	t.flush()
}

func printVerify(s *session) {
	w := s.w
	printSkillTable(w, s.lock, s.reports)
	var pending []skills.Report
	for _, r := range s.reports {
		if !r.Clean() {
			pending = append(pending, r)
		}
	}
	if len(pending) == 0 {
		if len(s.reports) > 0 {
			fmt.Fprintf(w.out, "\n%s\n", w.paint(colourGreen, fmt.Sprintf("all %d skill(s) are as they were approved", len(s.reports))))
		}
		return
	}
	for _, r := range pending {
		fmt.Fprintf(w.out, "\n%s  %s\n", skills.Reveal(r.Key), w.status(r.Status))
		printSummary(w, r)
	}
	fmt.Fprintf(w.out, "\n%s\n", w.dim("Read what changed with agentgate skills diff, then accept it with agentgate skills approve <skill> (or --all)."))
}

// printSummary is what verify says about a skill: the facts, without the
// prose diff.
func printSummary(w *lineWriter, r skills.Report) {
	switch r.Status {
	case skills.StatusRemoved:
		fmt.Fprintln(w.out, "  in the lockfile, no longer on disk")
		return
	case skills.StatusNew:
		fmt.Fprintf(w.out, "  not in the lockfile; label: %s\n", labelText(r.Label))
	case skills.StatusRescanned:
		fmt.Fprintln(w.out, "  no file changed, but this agentgate sees more in it than the lockfile records")
	}
	if r.Status != skills.StatusNew {
		for _, f := range r.Files {
			fmt.Fprintf(w.out, "  %-8s  %s\n", f.Change, skills.Reveal(f.Path))
		}
	}
	for _, c := range r.Gained {
		fmt.Fprintf(w.out, "  %s %s — %s\n", w.paint(colourRed, "+ capability"), c, skills.CapabilityTitle(c))
	}
	for _, c := range r.Lost {
		fmt.Fprintf(w.out, "  %s %s\n", w.dim("- capability"), c)
	}
	for _, h := range r.NewHosts {
		fmt.Fprintf(w.out, "  %s %s\n", w.paint(colourYellow, "+ host"), skills.Reveal(h))
	}
	printFindings(w, r.Unaccepted, "  ")
}

func printDetails(w *lineWriter, r skills.Report) {
	fmt.Fprintf(w.out, "%s  %s\n", skills.Reveal(r.Key), w.status(r.Status))
	printSummary(w, r)
	if r.Skill == nil {
		return
	}
	before := ""
	if r.Entry != nil {
		before = r.Entry.Instructions
	}
	d := skills.ProseDiff(before, r.Skill.Manifest())
	if len(d) == 0 {
		return
	}
	fmt.Fprintf(w.out, "\n  %s\n", w.dim("SKILL.md, sentence by sentence:"))
	for _, l := range d {
		if l.Op == "…" {
			fmt.Fprintf(w.out, "  %s\n", w.dim("  …"))
			continue
		}
		text := w.revealed(skills.Reveal(l.Text))
		prefix := fmt.Sprintf("%s %4d  ", l.Op, l.Line)
		if l.Op == "=" {
			prefix = fmt.Sprintf("  %4d  ", l.Line)
		}
		var tags []string
		if l.Imperative {
			tags = append(tags, "imperative")
		}
		tags = append(tags, l.Rules...)
		tag := ""
		if len(tags) > 0 {
			tag = "  " + w.paint(colourRed, "["+strings.Join(tags, ", ")+"]")
		}
		switch l.Op {
		case "+":
			if l.Imperative || len(l.Rules) > 0 {
				text = w.paint(colourYellow, text)
			} else {
				text = w.paint(colourGreen, text)
			}
			fmt.Fprintf(w.out, "  %s%s%s\n", w.paint(colourGreen, prefix), text, tag)
		case "-":
			fmt.Fprintf(w.out, "  %s%s\n", w.paint(colourRed, prefix), w.dim(text))
		default:
			fmt.Fprintf(w.out, "  %s%s\n", w.dim(prefix), w.dim(text))
		}
	}
}

func printLabel(w *lineWriter, key string, l skills.Label) {
	fmt.Fprintf(w.out, "%s  %s\n", skills.Reveal(key), w.dim(labelText(l.Capabilities)))
	for _, c := range l.Capabilities {
		shown := 0
		for _, e := range l.Evidence {
			if e.Capability != c {
				continue
			}
			if shown == 0 {
				fmt.Fprintf(w.out, "  %-18s %s\n", w.paint(colourCyan, fmt.Sprintf("%-18s", c)), skills.CapabilityTitle(c))
			}
			if shown < 3 {
				fmt.Fprintf(w.out, "  %-18s %s %s\n", "", w.dim(e.Where()), w.revealed(truncate(skills.Reveal(e.Excerpt), 80)))
			}
			shown++
		}
		if shown > 3 {
			fmt.Fprintf(w.out, "  %-18s %s\n", "", w.dim(fmt.Sprintf("and %d more", shown-3)))
		}
	}
	if len(l.Hosts) > 0 {
		fmt.Fprintf(w.out, "  %-18s %s\n", "hosts", skills.Reveal(strings.Join(l.Hosts, ", ")))
	}
}

func printFindings(w *lineWriter, fs []skills.Finding, indent string) {
	for _, f := range fs {
		fmt.Fprintf(w.out, "%s%s %s  %s: %s\n", indent, w.severity(f.Severity), f.Rule, f.Where(), skills.Reveal(f.Detail))
		if f.Excerpt != "" {
			fmt.Fprintf(w.out, "%s       %s\n", indent, w.revealed(fmt.Sprintf("%q", skills.Reveal(truncate(f.Excerpt, 160)))))
		}
	}
}
