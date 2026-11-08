//go:build !darwin && !linux && !windows

// SPDX-License-Identifier: BUSL-1.1
package configfile

import "os"

func openBounded(path string, limit int64, private bool) (*os.File, error) {
	return openModeBounded(path, limit, private, 0)
}
