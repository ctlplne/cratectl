//go:build darwin || linux

// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"fmt"
	"os"
	"syscall"
)

func regularReadFlags() int { return syscall.O_NONBLOCK | syscall.O_NOFOLLOW }
func platformRootIdentity(root *os.Root, info os.FileInfo) (string, error) {
	return platformFileIdentity(info), nil
}
func platformFileIdentity(info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d:%d", stat.Dev, stat.Ino, stat.Mode)
	}
	return info.Name() + ":" + info.Mode().String()
}
