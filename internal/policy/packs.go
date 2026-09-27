package policy

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// PackRef is one entry of policy.packs: a pack name, or a path to a pack
// file, with the values for the pack's parameters.
//
//	packs:
//	  - baseline
//	  - name: filesystem
//	    with: { workspace: /home/me/repo }
//	  - ./packs/company.yaml
type PackRef struct {
	Name string            `yaml:"name" json:"name"`
	With map[string]string `yaml:"with" json:"with,omitempty"`
}

// UnmarshalYAML accepts the bare-name shorthand as well as the mapping.
func (r *PackRef) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		r.Name = strings.TrimSpace(node.Value)
		return nil
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			switch key := node.Content[i].Value; key {
			case "name", "with":
			default:
				return fmt.Errorf("line %d: unknown pack field %q, expected name or with", node.Content[i].Line, key)
			}
		}
		type raw PackRef
		var out raw
		if err := node.Decode(&out); err != nil {
			return err
		}
		*r = PackRef(out)
		return nil
	}
	return fmt.Errorf("line %d: a pack is a name, or a mapping with name and with", node.Line)
}

// IsFile reports whether the reference points at a pack file rather than a
// pack that ships with agentgate.
func (r PackRef) IsFile() bool {
	return strings.ContainsAny(r.Name, `/\`) || strings.HasSuffix(r.Name, ".yaml") || strings.HasSuffix(r.Name, ".yml")
}

// PackFile is the format of a pack: a name, a description, the parameters it
// takes, and the label rules and rules it contributes.
type PackFile struct {
	Name        string               `yaml:"name" json:"name"`
	Description string               `yaml:"description" json:"description"`
	Params      map[string]PackParam `yaml:"params" json:"params,omitempty"`
	Labels      []*LabelRule         `yaml:"labels" json:"labels,omitempty"`
	Rules       []*Rule              `yaml:"rules" json:"rules"`
}

// PackParam describes one parameter of a pack.
type PackParam struct {
	Description string `yaml:"description" json:"description"`
	Default     string `yaml:"default" json:"default,omitempty"`
	Required    bool   `yaml:"required" json:"required,omitempty"`
	// Path marks the value as a filesystem path: it is expanded (~, ${ENV})
	// and cleaned, so "/home/me/repo/" and "/home/me/repo" mean the same.
	Path bool `yaml:"path" json:"path,omitempty"`
}

var (
	packNameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	placeholderRe = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)
)

// ReadPackHeader parses a pack for listing: name, description, parameters.
// Placeholders are left as they are.
func ReadPackHeader(src []byte) (*PackFile, error) {
	var head struct {
		Name        string               `yaml:"name"`
		Description string               `yaml:"description"`
		Params      map[string]PackParam `yaml:"params"`
	}
	if err := yaml.Unmarshal(src, &head); err != nil {
		return nil, err
	}
	if !packNameRe.MatchString(head.Name) {
		return nil, fmt.Errorf("pack name %q must be lower-case letters, digits and dashes", head.Name)
	}
	return &PackFile{Name: head.Name, Description: head.Description, Params: head.Params}, nil
}

// ExpandPack fills in a pack's parameters and returns its rules and label
// rules, ready to be appended to a policy. Rule ids are prefixed with the pack
// name ("baseline/no-rm-rf") so they stay unique and say where they came
// from; label names are left alone, because labels are a vocabulary shared
// between packs and your own rules.
//
// cleanPath normalises the values of parameters marked as paths. The
// substitution happens on the parsed YAML, value by value, so a parameter
// value can never change the structure of the pack.
func ExpandPack(src []byte, ref PackRef, cleanPath func(string) (string, error)) (*PackFile, error) {
	head, err := ReadPackHeader(src)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	var errs []error
	for name := range ref.With {
		if _, ok := head.Params[name]; !ok {
			errs = append(errs, fmt.Errorf("pack %s has no parameter %q", head.Name, name))
		}
	}
	names := make([]string, 0, len(head.Params))
	for name := range head.Params {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		param := head.Params[name]
		v, ok := ref.With[name]
		if !ok || v == "" {
			v = param.Default
		}
		if v == "" && param.Required {
			errs = append(errs, fmt.Errorf("pack %s needs the parameter %q: %s", head.Name, name, param.Description))
			continue
		}
		if param.Path && v != "" && cleanPath != nil {
			if v, err = cleanPath(v); err != nil {
				errs = append(errs, fmt.Errorf("pack %s: parameter %q: %w", head.Name, name, err))
				continue
			}
		}
		values[name] = v
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	if err := substitute(&doc, values, head.Name); err != nil {
		return nil, err
	}
	filled, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, err
	}
	var pack PackFile
	dec := yaml.NewDecoder(bytes.NewReader(filled))
	dec.KnownFields(true)
	if err := dec.Decode(&pack); err != nil {
		return nil, fmt.Errorf("pack %s: %w", head.Name, err)
	}
	for _, r := range pack.Rules {
		r.Pack = pack.Name
		if r.ID != "" {
			r.ID = pack.Name + "/" + r.ID
		}
	}
	for _, lr := range pack.Labels {
		lr.Pack = pack.Name
	}
	return &pack, nil
}

// substitute replaces {{param}} in every scalar value under node. Params are
// only allowed in values, never in keys, and an unknown placeholder is an
// error rather than a silent empty string.
func substitute(node *yaml.Node, values map[string]string, pack string) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if !strings.Contains(node.Value, "{{") {
			return nil
		}
		// A value that is nothing but one placeholder takes the type of what
		// is put in — `lt: "{{last_hour}}"` becomes the number 17. A
		// placeholder inside a longer value stays part of a string.
		whole := false
		if loc := placeholderRe.FindStringIndex(strings.TrimSpace(node.Value)); loc != nil && loc[0] == 0 && loc[1] == len(strings.TrimSpace(node.Value)) {
			whole = true
		}
		var missing []string
		node.Value = placeholderRe.ReplaceAllStringFunc(node.Value, func(m string) string {
			name := placeholderRe.FindStringSubmatch(m)[1]
			v, ok := values[name]
			if !ok {
				missing = append(missing, name)
				return m
			}
			return v
		})
		if len(missing) > 0 {
			return fmt.Errorf("pack %s: line %d uses unknown parameter %q", pack, node.Line, missing[0])
		}
		if whole {
			node.Tag, node.Style = "", 0
		} else {
			node.Tag = "!!str"
		}
		return nil
	case yaml.MappingNode:
		for i := 1; i < len(node.Content); i += 2 {
			if err := substitute(node.Content[i], values, pack); err != nil {
				return err
			}
		}
		return nil
	default:
		for _, c := range node.Content {
			if err := substitute(c, values, pack); err != nil {
				return err
			}
		}
		return nil
	}
}
