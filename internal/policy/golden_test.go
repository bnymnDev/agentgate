package policy_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/config"
	"github.com/bnymnDev/agentgate/internal/policy"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// time.* conditions read the call's timestamp in local time, which is what a
// policy author expects. The golden files must not depend on where the tests
// happen to run, so they are evaluated in UTC.
func init() { time.Local = time.UTC }

// testdata layout:
//
//	testdata/policies/<name>.yaml   a full agentgate config
//	testdata/calls/<case>.json      the calls to evaluate, naming the policy
//	testdata/golden/<case>.golden   one line per call: decision, rule, reason
//
// Run `go test ./internal/policy -update` to regenerate the golden files after
// an intentional change, then read the diff: it is the policy language's
// documentation, and a surprising line there is a bug.
const testdataDir = "../../testdata"

type caseFile struct {
	Policy string         `json:"policy"`
	Calls  []*policy.Call `json:"calls"`
}

func TestGoldenDecisions(t *testing.T) {
	cases, err := filepath.Glob(filepath.Join(testdataDir, "calls", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, cases, "no golden cases found")

	for _, path := range cases {
		name := trimExt(filepath.Base(path))
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			var tc caseFile
			require.NoError(t, json.Unmarshal(raw, &tc), "parsing %s", path)
			require.NotEmpty(t, tc.Policy, "%s: no policy named", path)

			cfg, err := config.Load(filepath.Join(testdataDir, "policies", tc.Policy+".yaml"))
			require.NoError(t, err)

			var got bytes.Buffer
			for i, call := range tc.Calls {
				d := policy.Evaluate(&cfg.Policy, call)
				fmt.Fprintf(&got, "%2d  %-5s  %-30s  %-28s  %s\n",
					i, d.Action, call.Tool, orDash(d.RuleID), d.Reason)
			}

			goldenPath := filepath.Join(testdataDir, "golden", name+".golden")
			if *update {
				require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o755))
				require.NoError(t, os.WriteFile(goldenPath, got.Bytes(), 0o644))
				return
			}
			want, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "missing golden file; run go test ./internal/policy -update")
			// Line endings are normalised so that a checkout with autocrlf on
			// compares decisions, not carriage returns.
			require.Equal(t, strings.ReplaceAll(string(want), "\r\n", "\n"), got.String(),
				"decisions changed for %s; run go test ./internal/policy -update and review the diff", name)
		})
	}
}

// TestEvaluateIsPure guards the invariant the replay feature rests on: the same
// policy and call must always produce the same decision.
func TestEvaluateIsPure(t *testing.T) {
	cfg, err := config.Load(filepath.Join(testdataDir, "policies", "default.yaml"))
	require.NoError(t, err)
	call := &policy.Call{
		Tool: "shell__exec", Upstream: "shell", ToolName: "exec",
		Args: map[string]any{"command": "rm -rf /"},
	}
	first := policy.Evaluate(&cfg.Policy, call)
	for range 100 {
		require.Equal(t, first, policy.Evaluate(&cfg.Policy, call))
	}
	require.Equal(t, policy.ActionDeny, first.Action)
	require.Equal(t, "no-destructive-shell", first.RuleID)
}

func trimExt(s string) string { return s[:len(s)-len(filepath.Ext(s))] }

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
