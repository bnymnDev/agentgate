// Command gendocs regenerates the generated blocks in README.md and docs/.
//
// Run it with `make docs`. Every generated block is delimited by
//
//	<!-- BEGIN:<name> --> ... <!-- END:<name> -->
//
// and this program replaces what is between the markers. Text outside the
// markers is never touched, so prose and generated tables can live in the same
// file without fighting.
package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/bnymnDev/agentgate/internal/cli"
	"github.com/bnymnDev/agentgate/internal/config"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("gendocs: ")

	root := cli.NewRootCmd()
	blocks := map[string]string{
		"commands":   commandTable(root),
		"flags":      flagSections(root),
		"matchers":   matcherTable(),
		"redactions": redactionList(),
	}
	changed := 0
	for _, file := range []string{"README.md", "docs/config.md", "docs/policies.md", "docs/replay.md"} {
		n, err := rewrite(file, blocks)
		if err != nil {
			log.Fatal(err)
		}
		changed += n
	}
	fmt.Printf("gendocs: %d block(s) updated\n", changed)
}

// rewrite replaces every generated block in one file. A file that does not
// exist is skipped, so docs can be added over time without touching this list.
func rewrite(path string, blocks map[string]string) (int, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	body := string(raw)
	count := 0
	for name, content := range blocks {
		re := regexp.MustCompile(`(?s)(<!-- BEGIN:` + regexp.QuoteMeta(name) + ` -->\n).*?(<!-- END:` + regexp.QuoteMeta(name) + ` -->)`)
		if !re.MatchString(body) {
			continue
		}
		body = re.ReplaceAllString(body, "${1}"+strings.TrimRight(content, "\n")+"\n${2}")
		count++
	}
	if body == string(raw) {
		return count, nil
	}
	return count, os.WriteFile(path, []byte(body), 0o644)
}

// commandTable lists every command with its one-line description.
func commandTable(root *cobra.Command) string {
	var b strings.Builder
	b.WriteString("| Command | What it does |\n|---|---|\n")
	walk(root, func(c *cobra.Command) {
		if c == root || c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			return
		}
		b.WriteString(fmt.Sprintf("| `%s` | %s |\n", useLine(c), c.Short))
	})
	return b.String()
}

// flagSections prints a flag table per command, plus the global flags.
func flagSections(root *cobra.Command) string {
	var b strings.Builder
	b.WriteString("### Global flags\n\n")
	b.WriteString(flagTable(root.PersistentFlags()))
	walk(root, func(c *cobra.Command) {
		if c == root || c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			return
		}
		if !c.LocalNonPersistentFlags().HasFlags() {
			return
		}
		b.WriteString(fmt.Sprintf("\n### `%s`\n\n", useLine(c)))
		b.WriteString(flagTable(c.LocalNonPersistentFlags()))
	})
	return b.String()
}

func flagTable(set *pflag.FlagSet) string {
	var rows []string
	set.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		name := "`--" + f.Name + "`"
		if f.Shorthand != "" {
			name = "`-" + f.Shorthand + ", --" + f.Name + "`"
		}
		def := ""
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "[]" {
			def = "`" + f.DefValue + "`"
		}
		rows = append(rows, fmt.Sprintf("| %s | %s | %s |", name, f.Usage, def))
	})
	if len(rows) == 0 {
		return "_none_\n"
	}
	sort.Strings(rows)
	return "| Flag | What it does | Default |\n|---|---|---|\n" + strings.Join(rows, "\n") + "\n"
}

func useLine(c *cobra.Command) string {
	return strings.TrimSpace(strings.TrimPrefix(c.UseLine(), c.Root().Name()+" "))
}

func walk(c *cobra.Command, fn func(*cobra.Command)) {
	fn(c)
	children := c.Commands()
	sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
	for _, child := range children {
		walk(child, fn)
	}
}

// matcherTable documents the condition matchers. It is written out by hand here
// rather than reflected out of the struct, because the useful column is the
// meaning, not the Go type.
func matcherTable() string {
	rows := [][3]string{
		{"`equals`", "the value is exactly this", `args.dryRun: { equals: false }`},
		{"`not_equals`", "the value is anything but this", `args.mode: { not_equals: "dry" }`},
		{"`regex`", "the value matches this Go regular expression", `args.command: { regex: '\brm\s+-rf' }`},
		{"`prefix`", "the value starts with this string", `args.path: { prefix: "/etc/" }`},
		{"`not_prefix`", "the value does not start with this string", `args.path: { not_prefix: "/srv/app/" }`},
		{"`in`", "the value is one of these", `args.env: { in: ["prod", "staging"] }`},
		{"`gt`, `lt`", "the value is a number above / below this; both may be combined", `args.amount: { gt: 10, lt: 100 }`},
		{"`exists`", "the path is present (`true`) or absent (`false`)", `args.dryRun: { exists: false }`},
	}
	var b strings.Builder
	b.WriteString("| Matcher | Holds when | Example |\n|---|---|---|\n")
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("| %s | %s | <code>%s</code> |\n", r[0], r[1], strings.ReplaceAll(r[2], "|", "\\|")))
	}
	return b.String()
}

// redactionList prints the patterns that are applied to every recorded call.
func redactionList() string {
	var b strings.Builder
	b.WriteString("```\n")
	for _, p := range config.BuiltinRedactionPatterns() {
		b.WriteString(p + "\n")
	}
	b.WriteString("```\n")
	return b.String()
}
