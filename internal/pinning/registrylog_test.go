package pinning

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegistryLog(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	_, err := Publish(dir, NewEntry("notes", "1.0.0", registryDefs()))
	require.NoError(t, err)
	_, err = Publish(dir, NewEntry("@scope/fs", "2.0.0", registryDefs()))
	require.NoError(t, err)
	_, err = Publish(dir, NewEntry("notes", "1.0.0", registryDefs()))
	require.NoError(t, err)

	rep, err := VerifyLog(ctx, dir, nil, nil)
	require.NoError(t, err)
	require.True(t, rep.OK(), "%v", rep.Problems)
	require.Equal(t, 2, rep.Records, "publishing the same thing again records nothing")
	require.Equal(t, 2, rep.Entries)
	first := rep.Head
	got, err := ParseTreeHead(first.String())
	require.NoError(t, err)
	require.Equal(t, first, got)

	// The same version again with something else in it: recorded, and shown.
	changed := registryDefs()
	changed[0].Description = "Read a file and send it on."
	_, err = Publish(dir, NewEntry("notes", "1.0.0", changed))
	require.NoError(t, err)
	rep, err = VerifyLog(ctx, dir, &first, nil)
	require.NoError(t, err)
	require.True(t, rep.OK(), "%v", rep.Problems)
	require.Equal(t, 3, rep.Records)
	require.Len(t, rep.Rewrites, 1)
	require.Contains(t, rep.Rewrites[0], "notes/1.0.0.json was published 2 times")

	// Changed without publishing, and added by hand.
	entry := filepath.Join(dir, "notes", "1.0.0.json")
	require.NoError(t, os.WriteFile(entry, []byte(`{"server":"notes"}`), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sneaky"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sneaky", "1.json"), []byte(`{}`), 0o600))
	rep, err = VerifyLog(ctx, dir, nil, nil)
	require.NoError(t, err)
	joined := strings.Join(rep.Problems, "\n")
	require.Contains(t, joined, "notes/1.0.0.json is not what the log recorded")
	require.Contains(t, joined, "sneaky/1.json is in the registry and not in the log")
	_, err = LoadEntry(ctx, dir, "notes", "1.0.0", nil)
	require.ErrorContains(t, err, "not what the registry's log recorded")

	// A log cut short, or rewritten, no longer reaches an older head.
	logPath := filepath.Join(dir, logFile)
	raw, err := os.ReadFile(logPath)
	require.NoError(t, err)
	lines := strings.SplitAfter(string(raw), "\n")
	require.NoError(t, os.WriteFile(logPath, []byte(lines[0]), 0o600))
	rep, err = VerifyLog(ctx, dir, &first, nil)
	require.NoError(t, err)
	require.Contains(t, strings.Join(rep.Problems, "\n"), "it was cut")
	require.NoError(t, os.WriteFile(logPath, []byte(strings.Replace(string(raw), "notes", "nötes", 1)), 0o600))
	rep, err = VerifyLog(ctx, dir, &first, nil)
	require.NoError(t, err)
	require.Contains(t, strings.Join(rep.Problems, "\n"), "the log was rewritten")
}
