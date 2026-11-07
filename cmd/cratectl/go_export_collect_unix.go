//go:build linux || darwin

// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"errors"
	"os"
	"syscall"
)

func privateCollectionFile(info os.FileInfo, directory bool) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0 && ((directory && info.IsDir()) || (!directory && info.Mode().IsRegular() && s.Nlink == 1))
}
func collectionOpenFlags() int { return syscall.O_NOFOLLOW | syscall.O_NONBLOCK }
func lockCollection(file *os.File) error {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("collection directory is already in use; wait for its collector to stop before resuming")
	}
	return nil
}

// Nonzero only for owner-private regular files; publication recovery permits
// exactly two links solely when both fixed names refer to the same inode.
func collectionFileLinks(info os.FileInfo) uint64 {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return 0
	}
	return uint64(s.Nlink)
}
