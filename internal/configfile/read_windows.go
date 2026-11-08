//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package configfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errWindowsPrivate = errors.New("configuration must have the current Windows owner and a protected DACL granting access only to that owner, SYSTEM or Administrators")

func openBounded(path string, limit int64, private bool) (*os.File, error) {
	if path == "" || len(path) > 128<<10 {
		return nil, errors.New("configuration path exceeds the Windows input budget")
	}
	// A drive/UNC volume may contain its normal colon; an alternate data stream
	// is a separate, unexpected representation of the named configuration file.
	if strings.Contains(strings.TrimPrefix(path, filepath.VolumeName(path)), ":") {
		return nil, errors.New("configuration alternate data streams are unsupported")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return nil, errors.New("configuration must be a bounded regular file")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("invalid configuration path")
	}
	// No final reparse traversal, no writes/deletes through other handles while
	// this reader is open, and no privilege elevation or backup-semantics bypass.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errors.New("cannot open stable configuration file")
	}
	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		windows.CloseHandle(handle)
		return nil, errors.New("cannot retain configuration handle")
	}
	accepted := false
	defer func() {
		if !accepted {
			f.Close()
		}
	}()
	var identity windows.ByHandleFileInformation
	kind, typeErr := windows.GetFileType(handle)
	err = windows.GetFileInformationByHandle(handle, &identity)
	if typeErr != nil || kind != windows.FILE_TYPE_DISK || err != nil || identity.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil, errors.New("configuration handle is not an ordinary disk file")
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() < 0 || after.Size() > limit {
		return nil, errors.New("configuration identity changed or exceeds its byte budget")
	}
	if private {
		if identity.NumberOfLinks != 1 || checkPrivateWindowsHandle(handle) != nil {
			return nil, errWindowsPrivate
		}
	}
	accepted = true
	return f, nil
}

func checkPrivateWindowsHandle(handle windows.Handle) error {
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return errWindowsPrivate
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errWindowsPrivate
	}
	defer func() { runtime.KeepAlive(descriptor) }()
	length := descriptor.Length()
	if length < 20 || length > 128<<10 {
		return errWindowsPrivate
	}
	begin := uintptr(unsafe.Pointer(descriptor))
	end := begin + uintptr(length)
	if end < begin {
		return errWindowsPrivate
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() || !owner.Equals(user.User.Sid) {
		return errWindowsPrivate
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 || control&windows.SE_DACL_PROTECTED == 0 {
		return errWindowsPrivate
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 || acl.AceCount > maxPrivateACEs {
		return errWindowsPrivate // A NULL DACL grants everyone access.
	}
	aces := make([]privateACE, 0, int(acl.AceCount))
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, n, &ace); err != nil || ace == nil {
			return errWindowsPrivate
		}
		address := uintptr(unsafe.Pointer(ace))
		if address < begin || address > end-8 || ace.Header.AceSize < 16 || uintptr(ace.Header.AceSize) > end-address ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			return errWindowsPrivate
		}
		// Ordinary allowed/denied ACEs share the same eight-byte header/mask
		// prefix. Bound the variable SID before calling any native SID decoder.
		raw := unsafe.Slice((*byte)(unsafe.Pointer(&ace.SidStart)), int(ace.Header.AceSize)-8)
		if raw[0] != 1 || raw[1] > 15 || 8+4*int(raw[1]) > len(raw) {
			return errWindowsPrivate
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return errWindowsPrivate
		}
		aces = append(aces, privateACE{kind: ace.Header.AceType, mask: uint32(ace.Mask), principal: sid.String(),
			inheritOnly: ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0})
	}
	if !privateWindowsACL(owner.String(), user.User.Sid.String(), true, aces) {
		return errWindowsPrivate
	}
	return nil
}
