//go:build !darwin && !linux && !windows

// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"fmt"
	"os"
)

func regularReadFlags() int { return 0 }
func platformRootIdentity(root *os.Root, info os.FileInfo) (string, error) {
	return platformFileIdentity(info), nil
}

// Non-Unix inventory identity and special-file race qualification remains open.
func platformFileIdentity(info os.FileInfo) string {
	if info.IsDir() {
		return fmt.Sprintf("%s:%s", info.Name(), info.Mode())
	}
	return fmt.Sprintf("%s:%s:%d", info.Name(), info.Mode(), info.ModTime().UnixNano())
}
