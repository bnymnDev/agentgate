package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/bnymnDev/agentgate/internal/audit"
	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policytest"
)

func newTestCmd(g *globals) *cobra.Command {
	var (
		run       string
		asJSON    bool
		missingOK bool
		colour    string
		from      []string
	)
	cmd := &cobra.Command{
		Use:   "test [file...]",
		Short: "Run the policy tests: calls, and the decisions they have to get",
		Long: `Run policy tests against the config, and exit 1 if any fails.

A test is a call, the session it is made in, and the decision it has to get.
Without file arguments, the tests are read from the file next to the config
with .test before the extension: agentgate.test.yaml for agentgate.yaml.

	tests:
	  - name: rm -rf / is denied
	    call: { tool: shell.exec, args: { command: "rm -rf /" } }
	    expect: deny

	  - name: merging waits for a human
	    call: { tool: github.merge_pull_request, args: { pull_number: 7 } }
	    expect: { action: ask, rule: github/merge }

	  - name: nothing leaves after a poisoned page
	    labels: [injection-suspected]
	    call: { tool: mail.send, args: { to: someone@example.com } }
	    expect: deny

	  - name: deploys only after green tests
	    before:
	      - tool: shell.test
	        result: { is_error: false }
	    call: { tool: shell.deploy }
	    expect: allow

Each test runs in a session of its own, through the same evaluator, session
tracker and label rules as the proxy. The calls in before are what the session
did first: denied ones do nothing, the rest earn their labels and count
towards budgets and the loop guard (repeat: 50 makes one 50 times). A test
without at runs at the current time.

A test can also be a whole session, call by call, each call with what it has
to get:

	  - name: a session
	    steps:
	      - { tool: web.fetch, args: { url: "https://example.com" }, expect: allow }
	      - { tool: mail.send, expect: ask }

--from writes such a test from a recorded session, expecting every decision
the policy reached in it, so the decisions of a good day become the
regression suite:

	agentgate test --from 01JD7Z > good-day.test.yaml
	agentgate test agentgate.test.yaml good-day.test.yaml`,
		RunE: func(cmd *cobra.Command, files []string) error {
			useColour, err := colourFlag(colour)
			if err != nil {
				return err
			}
			cfg, err := g.load()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(from) > 0 {
				if len(files) > 0 {
					return errors.New("--from writes a test to stdout; it runs none, so it takes no test files")
				}
				return writeRecordedTests(cmd, g, cfg, from)
			}
			if len(files) == 0 {
				def := policytest.DefaultPath(cfg.Path)
				if _, err := os.Stat(def); errors.Is(err, os.ErrNotExist) {
					if missingOK {
						fmt.Fprintf(out, "no tests: %s does not exist\n", def)
						return nil
					}
					return fmt.Errorf("no tests: %s does not exist; write it, or name the test files (agentgate test --help has an example)", def)
				}
				files = []string{def}
			}
			var match *regexp.Regexp
			if run != "" {
				if match, err = regexp.Compile(run); err != nil {
					return fmt.Errorf("--run: %w", err)
				}
			}
			opts := policytest.Options{Config: cfg, ResultLabels: resultLabels(cfg), Match: match}

			type fileReport struct {
				File  string               `json:"file"`
				Tests []policytest.Outcome `json:"tests"`
			}
			var reports []fileReport
			passed, failed := 0, 0
			for _, path := range files {
				f, err := policytest.Load(path)
				if err != nil {
					return err
				}
				outcomes := policytest.Run(f, opts)
				reports = append(reports, fileReport{File: path, Tests: outcomes})
				for _, o := range outcomes {
					if o.Passed {
						passed++
					} else {
						failed++
					}
				}
			}
			if match != nil && passed+failed == 0 {
				return fmt.Errorf("no test name matches --run %q", run)
			}

			if asJSON {
				if err := writeJSON(out, reports); err != nil {
					return err
				}
			} else {
				w := &lineWriter{out: out, colour: useColour}
				for i, r := range reports {
					if i > 0 {
						fmt.Fprintln(out)
					}
					printTests(w, r.File, r.Tests)
				}
				fmt.Fprintln(out)
				summary := fmt.Sprintf("%d passed, %d failed", passed, failed)
				if failed > 0 {
					summary = w.paint(colourRed, summary)
				} else {
					summary = w.paint(colourGreen, summary)
				}
				fmt.Fprintln(out, summary)
			}
			if failed > 0 {
				return errExitDenied
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&run, "run", "", "only the tests whose names match this regular expression")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the outcomes as JSON")
	cmd.Flags().BoolVar(&missingOK, "missing-ok", false, "succeed when no file is named and the default test file does not exist")
	cmd.Flags().StringVar(&colour, "color", "auto", "colour the output: auto, always or never")
	cmd.Flags().StringArrayVar(&from, "from", nil, "write a test from a recorded session (id or prefix) to stdout, instead of running tests (repeatable)")
	return cmd
}

// writeRecordedTests writes a test per recorded session to stdout.
func writeRecordedTests(cmd *cobra.Command, g *globals, cfg *config.Config, ids []string) error {
	ctx := cmd.Context()
	store, err := g.openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeStore(store)
	annotations := catalogAnnotations(ctx, store)
	var recs []policytest.Recording
	for _, id := range ids {
		sess, err := store.GetSession(ctx, id)
		if err != nil {
			return err
		}
		calls, err := store.ListCalls(ctx, audit.CallFilter{SessionID: sess.ID, Limit: 1_000_000})
		if err != nil {
			return err
		}
		recs = append(recs, policytest.Recording{Session: sess, Calls: calls, Annotations: annotations})
	}
	text, err := policytest.FromRecordings(recs, time.Now())
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(cmd.OutOrStdout(), text)
	return err
}

func printTests(w *lineWriter, file string, outcomes []policytest.Outcome) {
	// Relative to where the command runs, when it is below it: shorter, and
	// what an editor or a CI log turns into a link.
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, file); err == nil && !strings.HasPrefix(rel, "..") {
			file = rel
		}
	}
	fmt.Fprintln(w.out, file)
	width := 0
	for _, o := range outcomes {
		width = max(width, min(utf8.RuneCountInString(o.Name), 60))
	}
	for _, o := range outcomes {
		name := truncate(o.Name, 60)
		name += strings.Repeat(" ", width-utf8.RuneCountInString(name))
		if o.Passed {
			if o.Checked > 1 {
				fmt.Fprintf(w.out, "  %s  %s  %s\n", w.paint(colourGreen, "PASS"), name, w.dim(fmt.Sprintf("%d calls", o.Checked)))
				continue
			}
			rule := o.Got.RuleID
			if rule == "" {
				rule = "default"
			}
			fmt.Fprintf(w.out, "  %s  %s  %-5s  %s\n", w.paint(colourGreen, "PASS"), name, o.Got.Action, w.dim(rule))
			continue
		}
		first, rest := "", []string(nil)
		if len(o.Problems) > 0 {
			first, rest = o.Problems[0], o.Problems[1:]
		}
		fmt.Fprintf(w.out, "  %s  %s  %s\n", w.paint(colourRed, "FAIL"), name, first)
		for _, p := range rest {
			fmt.Fprintf(w.out, "  %s  %s  %s\n", "    ", strings.Repeat(" ", width), p)
		}
		if o.Line > 0 {
			fmt.Fprintf(w.out, "  %s  %s\n", "    ", w.dim(fmt.Sprintf("%s:%d", file, o.Line)))
		}
	}
}
