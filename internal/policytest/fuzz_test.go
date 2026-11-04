package policytest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/config"
)

const fuzzConfig = `
version: 1
upstreams:
  - name: shell
    stdio: ["x"]
  - name: fs
    stdio: ["x"]
policy:
  default: allow
  rules:
    - id: naive-rm
      tool: shell.exec
      when: { args.command: { regex: '\brm -rf' } }
      action: deny
    - id: robust-drop
      tool: shell.exec
      when: { args.command: { shell_regex: '\bdropdb\b' } }
      action: deny
    - id: naive-repo
      tool: fs.write
      when: { args.path: { not_prefix: /repo/ } }
      action: deny
`

const fuzzTests = `
tests:
  - name: rm
    call: { tool: shell.exec, args: { command: "rm -rf /" } }
    expect: deny
  - name: dropdb
    call: { tool: shell.exec, args: { command: "dropdb prod" } }
    expect: deny
  - name: outside the repo
    call: { tool: fs.write, args: { path: /etc/passwd } }
    expect: deny
  - name: inside the repo
    call: { tool: fs.write, args: { path: /repo/main.go } }
    expect: allow
`

func TestFuzzFindsBypasses(t *testing.T) {
	cfg, err := config.Parse([]byte(fuzzConfig))
	require.NoError(t, err)
	f, err := Parse([]byte(fuzzTests))
	require.NoError(t, err)
	rep := Fuzz(f, Options{Config: cfg})
	require.Equal(t, 3, rep.Tests)
	byTest := map[string][]string{}
	for _, b := range rep.Bypasses {
		byTest[b.Test] = append(byTest[b.Test], b.Technique)
	}
	require.Contains(t, byTest["rm"], "doubled spaces")
	require.Contains(t, byTest["rm"], "short flags split")
	require.Empty(t, byTest["dropdb"], "shell_regex holds: %v", byTest["dropdb"])
	require.Contains(t, byTest["outside the repo"], "an allowed directory, then .. back out")
	require.Contains(t, rep.Markdown(), "got through")
}
