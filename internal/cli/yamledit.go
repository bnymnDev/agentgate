package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bnymnDev/agentgate/internal/policy"
)

// The config file is the user's, and its layout — blank lines, comments,
// spacing inside braces — is part of it. Re-encoding the parsed YAML would
// normalise all of that away, so the pack commands edit the text instead:
// the parser only says where things are, and the lines around the edit stay
// byte for byte what they were.

type yamlText struct {
	lines []string // each with its line break, except perhaps the last
	root  *yaml.Node
}

func parseYAMLText(raw []byte) (*yamlText, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return &yamlText{lines: splitLines(string(raw))}, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode || root.Style&yaml.FlowStyle != 0 {
		return nil, errors.New("expected the file to be a block mapping (key: value lines)")
	}
	return &yamlText{lines: splitLines(string(raw)), root: root}, nil
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func (t *yamlText) String() string { return strings.Join(t.lines, "") }

// insert puts text before 1-based line n; n past the end appends.
func (t *yamlText) insert(n int, text string) {
	if n > len(t.lines) {
		if len(t.lines) > 0 && !strings.HasSuffix(t.lines[len(t.lines)-1], "\n") {
			t.lines[len(t.lines)-1] += "\n"
		}
		t.lines = append(t.lines, splitLines(text)...)
		return
	}
	t.lines = append(t.lines[:n-1], append(splitLines(text), t.lines[n-1:]...)...)
}

// remove deletes 1-based lines from..to, inclusive.
func (t *yamlText) remove(from, to int) {
	t.lines = append(t.lines[:from-1], t.lines[to:]...)
}

func (t *yamlText) line(n int) string {
	if n < 1 || n > len(t.lines) {
		return ""
	}
	return t.lines[n-1]
}

func isFiller(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}

// lastContentLine is the last line of a block that ends before line bound:
// trailing blank lines and comments belong to whatever comes next.
func (t *yamlText) lastContentLine(start, bound int) int {
	j := bound - 1
	for j > start && isFiller(t.line(j)) {
		j--
	}
	return j
}

// keyAt returns the index of key in a mapping's content, or -1.
func keyAt(m *yaml.Node, key string) int {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i
		}
	}
	return -1
}

// boundAfter is the line where whatever follows the value of m.Content[i]
// starts: the next key of m, or failing that the bound m itself sits in.
func boundAfter(m *yaml.Node, i, outer int) int {
	if i+2 < len(m.Content) {
		return m.Content[i+2].Line
	}
	return outer
}

// addPackText adds a pack to policy.packs.
func addPackText(raw []byte, ref policy.PackRef) ([]byte, error) {
	t, err := parseYAMLText(raw)
	if err != nil {
		return nil, err
	}
	eof := len(t.lines) + 1
	if t.root == nil {
		t.insert(eof, "policy:\n  packs:\n"+renderPackItem(ref, "    "))
		return []byte(t.String()), nil
	}
	pi := keyAt(t.root, "policy")
	if pi < 0 {
		t.insert(eof, "policy:\n  packs:\n"+renderPackItem(ref, "    "))
		return []byte(t.String()), nil
	}
	pol := t.root.Content[pi+1]
	if pol.Kind != yaml.MappingNode || pol.Style&yaml.FlowStyle != 0 {
		return nil, errors.New("policy: is not a block mapping; add the pack by hand")
	}
	policyBound := boundAfter(t.root, pi, eof)
	ind := strings.Repeat(" ", pol.Column-1)

	ki := keyAt(pol, "packs")
	if ki < 0 {
		block := ind + "packs:\n" + renderPackItem(ref, ind+"  ")
		at := t.lastContentLine(pol.Line, policyBound) + 1
		for _, before := range []string{"labels", "rules"} {
			if bi := keyAt(pol, before); bi >= 0 {
				at = pol.Content[bi].Line
				// Comments right above a key belong to it.
				for at > pol.Line && strings.HasPrefix(strings.TrimSpace(t.line(at-1)), "#") {
					at--
				}
				if strings.TrimSpace(t.line(at-1)) == "" {
					block += "\n"
				}
				break
			}
		}
		t.insert(at, block)
		return []byte(t.String()), nil
	}

	for _, item := range pol.Content[ki+1].Content {
		if packItemName(item) == ref.Name {
			return nil, fmt.Errorf("pack %s is already in policy.packs", ref.Name)
		}
	}
	key, list := pol.Content[ki], pol.Content[ki+1]
	switch {
	case list.Kind == yaml.ScalarNode && list.Tag == "!!null":
		t.insert(key.Line+1, renderPackItem(ref, ind+"  "))
	case list.Kind == yaml.SequenceNode && list.Style&yaml.FlowStyle != 0:
		line := t.line(list.Line)
		open := list.Column - 1
		close := strings.IndexByte(line[open:], ']')
		if close < 0 {
			return nil, errors.New("policy.packs spans several lines; add the pack by hand")
		}
		close += open
		item := flowPackItem(ref)
		if strings.TrimSpace(line[open+1:close]) != "" {
			item = ", " + item
		}
		t.lines[list.Line-1] = strings.TrimRight(line[:close], " ") + item + line[close:]
	case list.Kind == yaml.SequenceNode:
		dash := strings.Repeat(" ", list.Column-1)
		end := t.lastContentLine(list.Line, boundAfter(pol, ki, policyBound))
		t.insert(end+1, renderPackItem(ref, dash))
	default:
		return nil, errors.New("policy.packs is not a list; fix it by hand")
	}
	return []byte(t.String()), nil
}

// removePackText takes a pack out of policy.packs.
func removePackText(raw []byte, name string) ([]byte, error) {
	t, err := parseYAMLText(raw)
	if err != nil {
		return nil, err
	}
	missing := fmt.Errorf("pack %s is not in policy.packs", name)
	if t.root == nil {
		return nil, missing
	}
	pi := keyAt(t.root, "policy")
	if pi < 0 {
		return nil, missing
	}
	pol := t.root.Content[pi+1]
	ki := keyAt(pol, "packs")
	if ki < 0 || pol.Content[ki+1].Kind != yaml.SequenceNode {
		return nil, missing
	}
	key, list := pol.Content[ki], pol.Content[ki+1]
	idx := -1
	for i, item := range list.Content {
		if packItemName(item) == name {
			idx = i
		}
	}
	if idx < 0 {
		return nil, missing
	}
	rest := append(append([]*yaml.Node{}, list.Content[:idx]...), list.Content[idx+1:]...)

	if list.Style&yaml.FlowStyle != 0 {
		line := t.line(list.Line)
		open := list.Column - 1
		close := strings.IndexByte(line[open:], ']')
		if close < 0 {
			return nil, errors.New("policy.packs spans several lines; remove the pack by hand")
		}
		close += open
		items := make([]string, 0, len(rest))
		for _, item := range rest {
			var ref policy.PackRef
			if err := item.Decode(&ref); err != nil {
				return nil, err
			}
			items = append(items, flowPackItem(ref))
		}
		t.lines[list.Line-1] = line[:open+1] + strings.Join(items, ", ") + line[close:]
		return []byte(t.String()), nil
	}

	policyBound := boundAfter(t.root, pi, len(t.lines)+1)
	listEnd := t.lastContentLine(list.Line, boundAfter(pol, ki, policyBound))
	if len(rest) == 0 {
		t.remove(key.Line, listEnd)
		return []byte(t.String()), nil
	}
	start := itemLine(list.Content[idx])
	end := listEnd
	if idx+1 < len(list.Content) {
		end = t.lastContentLine(start, itemLine(list.Content[idx+1]))
	}
	t.remove(start, end)
	return []byte(t.String()), nil
}

// itemLine is the line of a block sequence item's dash, which is the line
// its content starts on.
func itemLine(item *yaml.Node) int { return item.Line }

// renderPackItem writes a block sequence item at the given indentation.
func renderPackItem(ref policy.PackRef, ind string) string {
	if len(ref.With) == 0 {
		return ind + "- " + yamlScalar(ref.Name) + "\n"
	}
	return ind + "- name: " + yamlScalar(ref.Name) + "\n" + ind + "  with: " + flowWith(ref.With) + "\n"
}

func flowPackItem(ref policy.PackRef) string {
	if len(ref.With) == 0 {
		return yamlScalar(ref.Name)
	}
	return "{ name: " + yamlScalar(ref.Name) + ", with: " + flowWith(ref.With) + " }"
}

func flowWith(with map[string]string) string {
	keys := make([]string, 0, len(with))
	for k := range with {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, yamlScalar(k)+": "+yamlScalar(with[k]))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// yamlScalar renders a string so that YAML reads it back as that string,
// quoting only when it has to.
func yamlScalar(s string) string {
	out, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Sprintf("%q", s)
	}
	v := strings.TrimSuffix(string(out), "\n")
	if strings.ContainsAny(v, "\n{}[],") && !strings.HasPrefix(v, `"`) && !strings.HasPrefix(v, "'") {
		// Plain scalars that are fine in block context can still end a flow
		// collection early.
		return fmt.Sprintf("%q", s)
	}
	return v
}
