//go:build !linux && !darwin

// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"errors"
	"os"
)

func privateCollectionFile(os.FileInfo, bool) bool { return false }
func collectionOpenFlags() int                     { return 0 }
func lockCollection(*os.File) error {
	return errors.New("collection requires qualified Linux/macOS private-file and directory-lock semantics")
}

func collectionFileLinks(os.FileInfo) uint64 { return 0 }
