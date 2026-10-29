//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"fmt"
	"os"
	"syscall"
)

func regularReadFlags() int { return 0 }
func platformFileIdentity(info os.FileInfo) string {
	return fmt.Sprintf("%s:%s:%d", info.Name(), info.Mode(), info.ModTime().UnixNano())
}
func platformRootIdentity(root *os.Root, info os.FileInfo) (string, error) {
	f, e := root.Open(".")
	if e != nil {
		return "", e
	}
	defer f.Close()
	var identity syscall.ByHandleFileInformation
	if e = syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &identity); e != nil {
		return "", e
	}
	return fmt.Sprintf("%d:%d:%d", identity.VolumeSerialNumber, identity.FileIndexHigh, identity.FileIndexLow), nil
}
