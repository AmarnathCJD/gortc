//go:build aix || darwin || dragonfly || freebsd || linux || nacl || nacljs || netbsd || openbsd || solaris || windows
// +build aix darwin dragonfly freebsd linux nacl nacljs netbsd openbsd solaris windows

// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package dtls

import (
	"errors"
	"os"
	"syscall"
)

func isOpErrorTemporary(err *os.SyscallError) bool {
	return errors.Is(err.Err, syscall.ECONNREFUSED)
}
