package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServerName(t *testing.T) {
	require.Equal(t, "server-filesystem", serverName([]string{"npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"}, ""))
	require.Equal(t, "github-mcp-server", serverName([]string{"docker", "run", "-i", "--rm", "ghcr.io/github/github-mcp-server"}, ""))
	require.Equal(t, "notes-server", serverName([]string{"./bin/notes-server"}, ""))
	require.Equal(t, "mcp-example-com", serverName(nil, "https://mcp.example.com/mcp"))
}

func TestAdHocConfig(t *testing.T) {
	cfg, err := adHocConfig(nil, "https://mcp.example.com/mcp", []string{"Authorization: Bearer x"}, nil)
	require.NoError(t, err)
	require.Equal(t, "https://mcp.example.com/mcp", cfg.Upstreams[0].HTTP)
	require.Equal(t, "Bearer x", cfg.Upstreams[0].Headers["Authorization"])

	cfg, err = adHocConfig([]string{"server", "--flag"}, "", nil, []string{"A=b=c"})
	require.NoError(t, err)
	require.Equal(t, []string{"server", "--flag"}, cfg.Upstreams[0].Stdio)
	require.Equal(t, "b=c", cfg.Upstreams[0].Env["A"])

	_, err = adHocConfig([]string{"x"}, "https://x", nil, nil)
	require.Error(t, err)
	_, err = adHocConfig(nil, "https://x", []string{"no colon"}, nil)
	require.Error(t, err)
}
