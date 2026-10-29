//go:build !darwin && !linux

// SPDX-License-Identifier: BUSL-1.1
package installation

import (
	"errors"
	"os"
)

func lock(root *os.Root) (func(), error) {
	return nil, errors.New("native server initialization requires Linux or macOS; other server platforms remain unqualified")
}
