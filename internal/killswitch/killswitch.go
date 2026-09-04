// Package killswitch is the freeze: one file whose existence means "deny
// everything". It is a file rather than a socket or a signal so that
// `agentgate freeze` works from any shell, against any number of running
// gateways, with no proxy running at all, and survives a restart.
package killswitch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// State is what the marker file records.
type State struct {
	Reason string    `json:"reason"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
}

// Engage throws the switch. It is idempotent: freezing twice keeps the first
// reason, because the first reason is the interesting one.
func Engage(path, reason, by string) (State, error) {
	if st, ok := Status(path); ok {
		return st, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return State{}, err
	}
	st := State{Reason: reason, By: by, At: time.Now()}
	body, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return State{}, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return State{}, err
	}
	return st, os.Rename(tmp, path)
}

// Release lifts the freeze. Releasing a gateway that is not frozen is fine.
func Release(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Status reports whether the switch is thrown, and what the marker says. A
// marker that cannot be parsed still counts as frozen: failing open is not an
// option for a kill switch.
func Status(path string) (State, bool) {
	body, err := os.ReadFile(path)
	if err != nil {
		return State{}, false
	}
	var st State
	if json.Unmarshal(body, &st) != nil {
		st = State{Reason: "frozen (marker file could not be read)"}
	}
	return st, true
}

// Engaged is the cheap check the proxy makes on every call.
func Engaged(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
