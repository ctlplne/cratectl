//go:build darwin || linux

// SPDX-License-Identifier: BUSL-1.1
package configfile

import (
	"os"
	"syscall"
)

func openBounded(path string, limit int64, private bool) (*os.File, error) {
	return openModeBounded(path, limit, private, syscall.O_NONBLOCK|syscall.O_NOFOLLOW)
}
