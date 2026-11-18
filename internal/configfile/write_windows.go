//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package configfile

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createPrivateOutput(path string) (*os.File, func() error, error) {
	name, err := windowsConfigurationPath(path)
	if err != nil {
		return nil, nil, err
	}
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, nil, errWindowsPrivate
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")")
	if err != nil {
		return nil, nil, errWindowsPrivate
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.DELETE, 0, &attributes,
		windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, nil, errors.New("cannot create a new stable private configuration file")
	}
	discard := func() error {
		// FILE_DISPOSITION_INFO is one BOOLEAN. Delete through the opened
		// handle, so a failed write cannot remove a substituted pathname.
		deleteFile := byte(1)
		return windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &deleteFile, 1)
	}
	kind, kindErr := windows.GetFileType(handle)
	var info windows.ByHandleFileInformation
	if kindErr != nil || kind != windows.FILE_TYPE_DISK || windows.GetFileInformationByHandle(handle, &info) != nil ||
		info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		checkPrivateWindowsHandle(handle) != nil {
		// With a non-disk handle, closing is the only safe action.
		if kindErr == nil && kind == windows.FILE_TYPE_DISK {
			discard()
		}
		windows.CloseHandle(handle)
		return nil, nil, errWindowsPrivate
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		discard()
		windows.CloseHandle(handle)
		return nil, nil, errors.New("cannot retain private configuration file handle")
	}
	return file, discard, nil
}
