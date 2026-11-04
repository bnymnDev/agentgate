package policy_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnymnDev/agentgate/internal/policy"
)

func TestShellView(t *testing.T) {
	for in, want := range map[string]string{
		`"rm" -rf /`:         "rm -rf /",
		`r''m -rf /`:         "rm -rf /",
		`\rm -rf /`:          "rm -rf /",
		"rm\t-rf  /":         "rm -rf /",
		`rm${IFS}-rf${IFS}/`: "rm -rf /",
		"rm -rf \\\n/":       "rm -rf /",
		`sh -c 'git status'`: "sh -c git status",
		`echo "a \"b\" c"`:   `echo a "b" c`,
	} {
		require.Equal(t, want, policy.ShellView(in), in)
	}
}

func TestSQLView(t *testing.T) {
	for in, want := range map[string]string{
		"DELETE/**/FROM/**/users":            "DELETE FROM users",
		"-- report\nDELETE FROM users":       "DELETE FROM users",
		"DELETE FROM users /* where id=1 */": "DELETE FROM users",
		"DROP\n\tTABLE   users":              "DROP TABLE users",
	} {
		require.Equal(t, want, policy.SQLView(in), in)
	}
}

func TestShellAndSQLRegex(t *testing.T) {
	p := mustCompile(t, `
default: allow
rules:
  - id: no-rm-rf
    when:
      args.command: { shell_regex: '\brm\s+-rf\b' }
    action: deny
  - id: delete-needs-where
    when:
      - args.sql: { sql_regex: '(?i)\bdelete from\b' }
      - args.sql: { not_sql_regex: '(?i)\bwhere\b' }
    action: deny
`)
	call := func(k, v string) policy.Action {
		return policy.Evaluate(p, &policy.Call{Tool: "x", Args: map[string]any{k: v}}).Action
	}
	require.Equal(t, policy.ActionDeny, call("command", `"rm" -rf /tmp/x`))
	require.Equal(t, policy.ActionAllow, call("command", "ls -la"))
	require.Equal(t, policy.ActionDeny, call("sql", "delete/**/from users"))
	require.Equal(t, policy.ActionDeny, call("sql", "DELETE FROM users -- where nothing"), "a where in a comment is not a where")
	require.Equal(t, policy.ActionAllow, call("sql", "DELETE FROM users WHERE id = 1"))
}

func TestPathPrefix(t *testing.T) {
	p := mustCompile(t, `
default: allow
rules:
  - id: stay-in-repo
    when:
      args.path: { not_path_prefix: /home/me/repo/ }
    action: deny
`)
	act := func(path string) policy.Action {
		return policy.Evaluate(p, &policy.Call{Tool: "x", Args: map[string]any{"path": path}}).Action
	}
	require.Equal(t, policy.ActionAllow, act("/home/me/repo/main.go"))
	require.Equal(t, policy.ActionAllow, act("/home/me/repo"))
	require.Equal(t, policy.ActionAllow, act("/home/me/repo/a/../b.go"))
	require.Equal(t, policy.ActionDeny, act("/home/me/repo/../../../etc/passwd"))
	require.Equal(t, policy.ActionDeny, act("/home/me/repository/x"))
	require.Equal(t, policy.ActionDeny, act(`\home\me\repo\..\..\x`))
}
