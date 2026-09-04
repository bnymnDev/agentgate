package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// selector is a compiled JSONPath-lite expression, the left hand side of a
// "when:" condition. The grammar is deliberately tiny:
//
//	args                     the whole arguments object
//	args.path                an object member
//	args.items[0]            an array element
//	args.items[*].sku        a member of every array element
//	tool                     the exposed tool name ("fs__write_file")
//	tool_name                the name the upstream server uses ("write_file")
//	upstream                 the upstream name ("fs")
//	annotations.destructive  what the server says about the tool (also
//	                         read_only, idempotent, open_world, title)
//	time.hour                when the call was made, local time (also
//	                         minute, weekday as "monday".."sunday")
//
// Resolving a selector yields zero or more values: zero when the path is
// missing, more than one when a [*] wildcard fans out. An annotation the
// server did not set, and any time.* path on a call with no timestamp, are
// missing.
type selector struct {
	src   string
	root  string
	steps []step
	// field is the sub-path of an annotations.* or time.* selector.
	field string
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
	sel := &selector{src: trimmed, root: root}
	switch root {
	case "args":
	case "tool", "tool_name", "upstream":
		if rest != "" {
			return nil, fmt.Errorf("%q takes no sub-path in %q", root, src)
		}
		return sel, nil
	case "annotations":
		switch rest {
		case "read_only", "destructive", "idempotent", "open_world", "title":
			sel.field = rest
			return sel, nil
		}
		return nil, fmt.Errorf("unknown annotation %q in %q: use read_only, destructive, idempotent, open_world or title", rest, src)
	case "time":
		switch rest {
		case "hour", "minute", "weekday":
			sel.field = rest
			return sel, nil
		}
		return nil, fmt.Errorf("unknown time field %q in %q: use hour, minute or weekday", rest, src)
	default:
		return nil, fmt.Errorf("unknown condition root %q in %q: use args, tool, tool_name, upstream, annotations or time", root, src)
	}
	if rest == "" {
		return sel, nil
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
	case "annotations":
		return annotationValue(&call.Annotations, s.field)
	case "time":
		return timeValue(call.At, s.field)
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

func annotationValue(a *Annotations, field string) []any {
	var b *bool
	switch field {
	case "title":
		if a.Title == "" {
			return nil
		}
		return []any{a.Title}
	case "read_only":
		b = a.ReadOnly
	case "destructive":
		b = a.Destructive
	case "idempotent":
		b = a.Idempotent
	case "open_world":
		b = a.OpenWorld
	}
	if b == nil {
		return nil
	}
	return []any{*b}
}

func timeValue(at time.Time, field string) []any {
	if at.IsZero() {
		return nil
	}
	local := at.Local()
	switch field {
	case "hour":
		return []any{local.Hour()}
	case "minute":
		return []any{local.Minute()}
	case "weekday":
		return []any{weekdayName(local)}
	}
	return nil
}
