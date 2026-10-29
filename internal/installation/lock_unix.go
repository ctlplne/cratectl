//go:build darwin || linux

// SPDX-License-Identifier: BUSL-1.1
package installation

import (
	"errors"
	"os"
	"syscall"
)

func lock(root *os.Root) (func(), error) {
	f, e := root.OpenFile(".init.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, errors.New("cannot open initialization lock")
	}
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("initialization lock must remain a private regular file")
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, errors.New("another initializer is active; retry after it exits")
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
