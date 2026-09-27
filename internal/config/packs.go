package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bnymnDev/agentgate/internal/packs"
	"github.com/bnymnDev/agentgate/internal/policy"
)

// expandPacks appends the rules and label rules of every pack in
// policy.packs, in the order they are listed, after the policy's own rules.
// Your own rules therefore always get the first say: a pack can be switched
// on wholesale and still be overridden for one tool.
func (c *Config) expandPacks() error {
	var errs []error
	seen := map[string]bool{}
	for i, ref := range c.Policy.Packs {
		where := fmt.Sprintf("policy.packs[%d]", i)
		if ref.Name == "" {
			errs = append(errs, fmt.Errorf("%s: missing pack name", where))
			continue
		}
		src, err := c.packSource(ref)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", where, err))
			continue
		}
		pack, err := policy.ExpandPack(src, ref, ExpandPathClean)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", where, err))
			continue
		}
		if seen[pack.Name] {
			errs = append(errs, fmt.Errorf("%s: pack %s is listed twice", where, pack.Name))
			continue
		}
		seen[pack.Name] = true
		c.Policy.Packs[i].Name = pack.Name
		c.Policy.Rules = append(c.Policy.Rules, pack.Rules...)
		c.Policy.Labels = append(c.Policy.Labels, pack.Labels...)
	}
	return errors.Join(errs...)
}

// packSource returns the YAML of a pack: a built-in one by name, or a file
// relative to the config.
func (c *Config) packSource(ref policy.PackRef) ([]byte, error) {
	if !ref.IsFile() {
		src, ok := packs.Get(ref.Name)
		if !ok {
			return nil, fmt.Errorf("unknown pack %q; run `agentgate policy packs` to see the ones that ship with agentgate", ref.Name)
		}
		return src, nil
	}
	path, err := ExpandPath(ref.Name)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) && c.Path != "" {
		path = filepath.Join(filepath.Dir(c.Path), path)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading pack file: %w", err)
	}
	return src, nil
}

// ExpandPathClean expands ~ and ${ENV} in a path and cleans it, so that
// "/home/me/repo/" and "/home/me/repo" compare the same.
func ExpandPathClean(p string) (string, error) {
	out, err := ExpandPath(p)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(filepath.Clean(out)), nil
}
