//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !nacl && !nacljs && !netbsd && !openbsd && !solaris && !windows
// +build !aix,!darwin,!dragonfly,!freebsd,!linux,!nacl,!nacljs,!netbsd,!openbsd,!solaris,!windows

package dtls

import (
	"os"
)

func isOpErrorTemporary(err *os.SyscallError) bool {
	return false
}
