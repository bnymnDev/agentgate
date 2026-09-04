//go:build !windows

package proxy

// ttyDevice is the controlling terminal. Opening it lets agentgate ask for an
// approval even in stdio mode, where stdin and stdout carry MCP traffic.
const ttyDevice = "/dev/tty"
