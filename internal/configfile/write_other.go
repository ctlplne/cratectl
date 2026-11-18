//go:build !windows

// SPDX-License-Identifier: BUSL-1.1
package configfile

import "os"

func createPrivateOutput(path string) (*os.File, func() error, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, err
	}
	return file, func() error { return os.Remove(path) }, nil
}
