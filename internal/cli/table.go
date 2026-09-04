package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// table is a very small aligned-column writer. The CLI prints a handful of
// tables and none of them justify a dependency.
type table struct {
	w    *tabwriter.Writer
	cols int
}

func newTable(out io.Writer, headers ...string) *table {
	t := &table{w: tabwriter.NewWriter(out, 0, 0, 2, ' ', 0), cols: len(headers)}
	fmt.Fprintln(t.w, strings.Join(headers, "\t"))
	rule := make([]string, len(headers))
	for i, h := range headers {
		rule[i] = strings.Repeat("─", len(h))
	}
	fmt.Fprintln(t.w, strings.Join(rule, "\t"))
	return t
}

func (t *table) row(cells ...any) {
	parts := make([]string, len(cells))
	for i, c := range cells {
		parts[i] = fmt.Sprint(c)
	}
	fmt.Fprintln(t.w, strings.Join(parts, "\t"))
}

func (t *table) flush() { t.w.Flush() }

// truncate shortens a string for a table cell, keeping it on one line.
func truncate(s string, n int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\t", " ")
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// shortID is the first 10 characters of a ULID, which is plenty to identify a
// session by eye and still unique in practice within one database.
func shortID(id string) string {
	if len(id) <= 10 {
		return id
	}
	return id[:10]
}
