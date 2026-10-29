//go:build darwin || linux

// SPDX-License-Identifier: BUSL-1.1
package configfile

import "syscall"

func readFlags() int { return syscall.O_NONBLOCK | syscall.O_NOFOLLOW }
