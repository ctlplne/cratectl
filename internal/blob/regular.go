// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"errors"
	"os"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

var ErrUnsupported = errors.New("unsupported storage entry")
var ErrStorageChanged = errors.New("storage identity changed during inventory")

func fileIdentity(info os.FileInfo) string { return crypt.Digest([]byte(platformFileIdentity(info))) }
func storageRootIdentity(base, tenantRoot *os.Root, tenant string) (string, error) {
	baseInfo, e := base.Stat(".")
	if e != nil {
		return "", e
	}
	baseID, e := platformRootIdentity(base, baseInfo)
	if e != nil {
		return "", e
	}
	if tenantRoot == nil {
		return crypt.Digest([]byte(baseID + "/" + tenant + "/absent")), nil
	}
	info, e := tenantRoot.Stat(".")
	if e != nil {
		return "", e
	}
	id, e := platformRootIdentity(tenantRoot, info)
	if e != nil {
		return "", e
	}
	return crypt.Digest([]byte(baseID + "/" + tenant + "/" + id)), nil
}
func checkedDirectory(parent *os.Root, name string) (*os.Root, os.FileInfo, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return nil, nil, ErrUnsupported
	}
	before, e := parent.Lstat(name)
	if e != nil {
		return nil, nil, e
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, nil, ErrUnsupported
	}
	child, e := parent.OpenRoot(name)
	if e != nil {
		return nil, nil, e
	}
	after, e := child.Stat(".")
	if e != nil || !os.SameFile(before, after) {
		child.Close()
		return nil, nil, ErrStorageChanged
	}
	return child, after, nil
}

func createCheckedDirectory(parent *os.Root, name string) (*os.Root, os.FileInfo, error) {
	if e := parent.Mkdir(name, 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return nil, nil, e
	}
	return checkedDirectory(parent, name)
}
func syncRoot(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (s *Local) tenantRoot(tenant string) (*os.Root, string, error) {
	if !namespace.MatchString(tenant) {
		return nil, "", ErrUnsupported
	}
	base, e := os.OpenRoot(s.root)
	if e != nil {
		return nil, "", e
	}
	defer base.Close()
	child, _, e := checkedDirectory(base, tenant)
	if errors.Is(e, os.ErrNotExist) {
		id, identityError := storageRootIdentity(base, nil, tenant)
		if identityError != nil {
			return nil, "", identityError
		}
		return nil, id, e
	}
	if e != nil {
		return nil, "", e
	}
	id, e := storageRootIdentity(base, child, tenant)
	if e != nil {
		child.Close()
		return nil, "", e
	}
	return child, id, nil
}
func (s *Local) InventoryRoot(tenant string) (string, error) {
	root, id, e := s.tenantRoot(tenant)
	if root != nil {
		root.Close()
	}
	if errors.Is(e, os.ErrNotExist) {
		e = nil
	}
	return id, e
}
func (s *Local) openRegularFile(tenant string, parts ...string) (*os.File, error) {
	if len(parts) == 0 {
		return nil, ErrUnsupported
	}
	root, _, e := s.tenantRoot(tenant)
	if e != nil {
		return nil, e
	}
	for _, part := range parts[:len(parts)-1] {
		child, _, e := checkedDirectory(root, part)
		root.Close()
		if e != nil {
			return nil, e
		}
		root = child
	}
	defer root.Close()
	name := parts[len(parts)-1]
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return nil, ErrUnsupported
	}
	before, e := root.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() {
		return nil, ErrUnsupported
	}
	f, e := root.OpenFile(name, os.O_RDONLY|regularReadFlags(), 0)
	if e != nil {
		return nil, e
	}
	after, e := f.Stat()
	if e != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, ErrStorageChanged
	}
	return f, nil
}
