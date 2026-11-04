// Package corpus is a public, labelled set of poisoned and ordinary MCP
// tool definitions and tool results, and the measurement of how well
// agentgate's scanners tell them apart. The numbers are not a claim; they
// are what `go test ./corpus` measures on every commit, misses and false
// alarms included, so a change to a scanner shows what it gains and costs.
package corpus

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bnymnDev/agentgate/internal/pinning"
)

//go:embed definitions.yaml
var definitionsYAML []byte

//go:embed results.yaml
var resultsYAML []byte

// Definition is one labelled definition.
type Definition struct {
	ID        string              `yaml:"id"`
	Attack    bool                `yaml:"attack"`
	Technique string              `yaml:"technique"`
	Others    []pinning.OtherTool `yaml:"others"`
	Def       map[string]any      `yaml:"def"`
}

// Result is one labelled tool result.
type Result struct {
	ID        string `yaml:"id"`
	Attack    bool   `yaml:"attack"`
	Technique string `yaml:"technique"`
	Text      string `yaml:"text"`
}

// Definitions loads the definition corpus.
func Definitions() ([]Definition, error) {
	var out []Definition
	if err := yaml.Unmarshal(definitionsYAML, &out); err != nil {
		return nil, fmt.Errorf("definitions.yaml: %w", err)
	}
	return out, unique(len(out), func(i int) string { return out[i].ID })
}

// Results loads the result corpus.
func Results() ([]Result, error) {
	var out []Result
	if err := yaml.Unmarshal(resultsYAML, &out); err != nil {
		return nil, fmt.Errorf("results.yaml: %w", err)
	}
	return out, unique(len(out), func(i int) string { return out[i].ID })
}

func unique(n int, id func(int) string) error {
	seen := map[string]bool{}
	for i := range n {
		if id(i) == "" || seen[id(i)] {
			return fmt.Errorf("entry %d: missing or repeated id %q", i, id(i))
		}
		seen[id(i)] = true
	}
	return nil
}

// Definition turns the YAML definition into what the scanner reads.
func (d Definition) Definition() (pinning.Definition, error) {
	raw, err := json.Marshal(d.Def)
	if err != nil {
		return pinning.Definition{}, err
	}
	var out pinning.Definition
	err = json.Unmarshal(raw, &out)
	return out, err
}

// Outcome is one entry's verdict.
type Outcome struct {
	ID        string
	Attack    bool
	Technique string
	Flagged   bool
	Why       string
}

// Score is how one scanner did on one corpus.
type Score struct {
	Name                 string
	Attacks, Benign      int
	Caught, FalseAlarms  int
	Missed, FalseAlarmed []Outcome
}

// Detection is the share of attacks caught.
func (s Score) Detection() float64 { return ratio(s.Caught, s.Attacks) }

// FalseAlarmRate is the share of benign entries flagged.
func (s Score) FalseAlarmRate() float64 { return ratio(s.FalseAlarms, s.Benign) }

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func (s *Score) add(o Outcome) {
	switch {
	case o.Attack:
		s.Attacks++
		if o.Flagged {
			s.Caught++
		} else {
			s.Missed = append(s.Missed, o)
		}
	default:
		s.Benign++
		if o.Flagged {
			s.FalseAlarms++
			s.FalseAlarmed = append(s.FalseAlarmed, o)
		}
	}
}

// ScoreDefinitions runs the definition scanner over the corpus.
func ScoreDefinitions() (Score, error) {
	defs, err := Definitions()
	if err != nil {
		return Score{}, err
	}
	s := Score{Name: "tool definitions (lock, scan, pinning)"}
	for _, d := range defs {
		def, err := d.Definition()
		if err != nil {
			return s, fmt.Errorf("%s: %w", d.ID, err)
		}
		findings := pinning.Scan(def, d.Others)
		s.add(Outcome{ID: d.ID, Attack: d.Attack, Technique: d.Technique, Flagged: len(findings) > 0, Why: why(findings)})
	}
	return s, nil
}

// ScoreResults runs the result scanner over the corpus.
func ScoreResults() (Score, error) {
	results, err := Results()
	if err != nil {
		return Score{}, err
	}
	s := Score{Name: "tool results (injection-suspected label)"}
	for _, r := range results {
		findings := pinning.ScanResult(r.Text)
		s.add(Outcome{ID: r.ID, Attack: r.Attack, Technique: r.Technique, Flagged: len(findings) > 0, Why: why(findings)})
	}
	return s, nil
}

func why(f []pinning.Finding) string {
	var parts []string
	for _, x := range f {
		parts = append(parts, x.Detail)
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// Markdown is the measurement as a docs block: rates, and every miss and
// false alarm by name.
func Markdown(scores ...Score) string {
	var b strings.Builder
	b.WriteString("| Scanner | Attacks caught | False alarms on ordinary entries |\n|---|---|---|\n")
	for _, s := range scores {
		fmt.Fprintf(&b, "| %s | %d of %d (%.0f%%) | %d of %d (%.0f%%) |\n", s.Name,
			s.Caught, s.Attacks, 100*s.Detection(), s.FalseAlarms, s.Benign, 100*s.FalseAlarmRate())
	}
	for _, s := range scores {
		if len(s.Missed) == 0 && len(s.FalseAlarmed) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\nWhere the %s scanner is wrong:\n\n", strings.SplitN(s.Name, " (", 2)[0])
		for _, o := range s.Missed {
			fmt.Fprintf(&b, "- missed `%s`: %s\n", o.ID, o.Technique)
		}
		for _, o := range s.FalseAlarmed {
			fmt.Fprintf(&b, "- false alarm `%s`: %s (%s)\n", o.ID, o.Technique, o.Why)
		}
	}
	return b.String()
}
