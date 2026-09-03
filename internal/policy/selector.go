package policy

import (
	"fmt"
	"strconv"
	"strings"
)

// selector is a compiled JSONPath-lite expression, the left hand side of a
// "when:" condition. The grammar is deliberately tiny:
//
//	args                 the whole arguments object
//	args.path            an object member
//	args.items[0]        an array element
//	args.items[*].sku    a member of every array element
//	tool                 the exposed tool name ("fs__write_file")
//	tool_name            the name the upstream server uses ("write_file")
//	upstream             the upstream name ("fs")
//
// Resolving a selector yields zero or more values: zero when the path is
// missing, more than one when a [*] wildcard fans out.
type selector struct {
	src   string
	root  string
	steps []step
}

type step struct {
	// key is set for object members.
	key string
	// index is set for [n]; wildcard is set for [*].
	index    int
	isIndex  bool
	wildcard bool
}

func compileSelector(src string) (*selector, error) {
	trimmed := strings.TrimSpace(src)
	if trimmed == "" {
		return nil, fmt.Errorf("empty condition path")
	}
	root, rest, _ := strings.Cut(trimmed, ".")
	// A subscript directly on the root ("args[0]") keeps the subscript in rest.
	if i := strings.IndexByte(root, '['); i >= 0 {
		rest = root[i:] + func() string {
			if rest == "" {
				return ""
			}
			return "." + rest
		}()
		root = root[:i]
	}
	switch root {
	case "args", "tool", "tool_name", "upstream":
	default:
		return nil, fmt.Errorf("unknown condition root %q in %q: use args, tool, tool_name or upstream", root, src)
	}
	sel := &selector{src: trimmed, root: root}
	if rest == "" {
		return sel, nil
	}
	if root != "args" {
		return nil, fmt.Errorf("%q takes no sub-path in %q", root, src)
	}
	for _, seg := range strings.Split(rest, ".") {
		if seg == "" {
			return nil, fmt.Errorf("empty path segment in %q", src)
		}
		name, subs, err := splitSubscripts(seg, src)
		if err != nil {
			return nil, err
		}
		if name != "" {
			sel.steps = append(sel.steps, step{key: name})
		}
		sel.steps = append(sel.steps, subs...)
	}
	return sel, nil
}

// splitSubscripts breaks "items[*][0]" into the member name and its subscripts.
func splitSubscripts(seg, src string) (string, []step, error) {
	open := strings.IndexByte(seg, '[')
	if open < 0 {
		return seg, nil, nil
	}
	name, rest := seg[:open], seg[open:]
	var steps []step
	for rest != "" {
		if rest[0] != '[' {
			return "", nil, fmt.Errorf("unexpected %q after subscript in %q", rest, src)
		}
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return "", nil, fmt.Errorf("unterminated subscript in %q", src)
		}
		body := rest[1:end]
		rest = rest[end+1:]
		if body == "*" {
			steps = append(steps, step{wildcard: true})
			continue
		}
		n, err := strconv.Atoi(body)
		if err != nil {
			return "", nil, fmt.Errorf("invalid subscript [%s] in %q: want a number or *", body, src)
		}
		steps = append(steps, step{index: n, isIndex: true})
	}
	return name, steps, nil
}

// resolve walks the call and returns every value the selector points at.
func (s *selector) resolve(call *Call) []any {
	switch s.root {
	case "tool":
		return []any{call.Tool}
	case "tool_name":
		return []any{call.ToolName}
	case "upstream":
		return []any{call.Upstream}
	}
	if call.Args == nil {
		return nil
	}
	current := []any{any(call.Args)}
	for _, st := range s.steps {
		next := make([]any, 0, len(current))
		for _, v := range current {
			next = appendStep(next, v, st)
		}
		if len(next) == 0 {
			return nil
		}
		current = next
	}
	return current
}

func appendStep(out []any, v any, st step) []any {
	switch {
	case st.key != "":
		obj, ok := v.(map[string]any)
		if !ok {
			return out
		}
		child, ok := obj[st.key]
		if !ok {
			return out
		}
		return append(out, child)
	case st.wildcard:
		arr, ok := v.([]any)
		if !ok {
			return out
		}
		return append(out, arr...)
	case st.isIndex:
		arr, ok := v.([]any)
		if !ok {
			return out
		}
		i := st.index
		if i < 0 {
			i += len(arr)
		}
		if i < 0 || i >= len(arr) {
			return out
		}
		return append(out, arr[i])
	}
	return out
}

func (s *selector) String() string { return s.src }
