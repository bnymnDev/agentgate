// Command agentgate is a policy proxy and audit log for MCP tool calls.
//
// It speaks MCP on both sides: an MCP host connects to agentgate, agentgate
// connects to the real MCP servers, and every tools/call in between is checked
// against a YAML policy, recorded, and replayable.
//
// The command tree itself lives in internal/cli, so that the docs generator and
// the tests can build it without shelling out to the binary.
package main

import (
	"os"

	"github.com/bnymnDev/agentgate/internal/cli"
)

// Set at build time with -ldflags "-X main.version=...".
var (
	version = "dev"
	commit  = ""
	date    = ""
)

func main() {
	os.Exit(cli.Main(cli.BuildInfo{Version: version, Commit: commit, Date: date}))
}
