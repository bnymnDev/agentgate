//go:build windows

package proxy

// ttyDevice is the console input device. Windows has no /dev/tty; CONIN$ is
// the closest equivalent and is opened read-write for the same reason.
const ttyDevice = "CONIN$"
