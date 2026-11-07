// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
)

const collectionJSONLimit = 64 << 10
const collectionBindingPending = ".bindings.pending"

func receiptPendingGeneration(name string) (int64, bool) {
	value, ok := strings.CutPrefix(name, "receipt.")
	if !ok {
		return 0, false
	}
	value, ok = strings.CutSuffix(value, ".pending")
	if !ok || len(value) > 19 {
		return 0, false
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return n, err == nil && n > 0 && strconv.FormatInt(n, 10) == value
}
func collectionEntries(root *os.Root, bounds ...int) ([]os.DirEntry, error) {
	maximum := 12
	if len(bounds) > 1 || len(bounds) == 1 && (bounds[0] < 1 || bounds[0] > 780) {
		return nil, errors.New("invalid directory entry bound")
	}
	if len(bounds) == 1 {
		maximum = bounds[0]
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(maximum + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > maximum {
		return nil, errors.New("collection member budget exceeded")
	}
	return entries, nil
}
func validateCollectionEntries(entries []os.DirEntry) error {
	allowed := map[string]bool{"bindings.json": true, "receipt.json": true, "manifest.json": true, "original.zip": true, "original.mod": true, "original.info": true, "journal.jsonl": true, "checkpoint.json": true, "checkpoint.sig": true, "signer-public.pem": true, collectionBindingPending: true}
	receipts := 0
	for _, entry := range entries {
		if allowed[entry.Name()] {
			continue
		}
		if _, ok := receiptPendingGeneration(entry.Name()); !ok {
			return errors.New("collection contains an unexpected member; preserve it and choose another directory")
		}
		receipts++
	}
	if receipts > 1 {
		return errors.New("multiple pending completion intents; preserve them and inspect the collection")
	}
	return nil
}
func publicationPair(root *os.Root, final, pending string) (os.FileInfo, os.FileInfo, error) {
	stat := func(name string) (os.FileInfo, error) {
		if name == "" {
			return nil, nil
		}
		info, err := root.Lstat(name)
		if os.IsNotExist(err) {
			return nil, nil
		}
		return info, err
	}
	a, err := stat(final)
	if err != nil {
		return nil, nil, err
	}
	b, err := stat(pending)
	if err != nil {
		return nil, nil, err
	}
	if a == nil {
		if b != nil && collectionFileLinks(b) != 1 {
			return nil, nil, errors.New("pending metadata is not an unshared private regular file")
		}
	} else {
		links := collectionFileLinks(a)
		if links == 1 && b == nil {
			return a, nil, nil
		}
		if links != 2 || b == nil || collectionFileLinks(b) != 2 || !os.SameFile(a, b) {
			return nil, nil, errors.New("metadata has an unrelated or unsafe link; original files are preserved")
		}
	}
	return a, b, nil
}
func collectionPublicationLimit(bounds []int) (int, error) {
	if len(bounds) == 0 {
		return collectionJSONLimit, nil
	}
	if len(bounds) != 1 || bounds[0] < 1 || bounds[0] > 512<<10 {
		return 0, errors.New("invalid metadata publication bound")
	}
	return bounds[0], nil
}
func readCollectionPublication(root *os.Root, name string, expected os.FileInfo, bounds ...int) ([]byte, error) {
	maximum, err := collectionPublicationLimit(bounds)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile(name, os.O_RDONLY|collectionOpenFlags(), 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !os.SameFile(before, expected) || collectionFileLinks(before) != collectionFileLinks(expected) {
		return nil, errors.New("metadata file changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(maximum)+1))
	after, se := f.Stat()
	if err != nil || se != nil || len(raw) > maximum || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || collectionFileLinks(before) != collectionFileLinks(after) {
		return nil, errors.New("metadata is incomplete, changed or exceeds its byte budget")
	}
	mapped, err := root.Lstat(name)
	if err != nil || !os.SameFile(mapped, after) {
		return nil, errors.New("metadata name changed")
	}
	return raw, nil
}

// The caller holds the directory lock. Never replace a final name: the hard
// link publishes only fully written and synced bytes, and directory sync makes
// that link durable before removing its recoverable pending alias.
func publishCollectionJSON(root *os.Root, final, pending string, expected []byte, resume bool, bounds ...int) error {
	maximum, err := collectionPublicationLimit(bounds)
	if err != nil {
		return err
	}
	if len(expected) == 0 || len(expected) > maximum || final == pending || pending == "" {
		return errors.New("invalid bounded metadata publication")
	}
	complete, staged, err := publicationPair(root, final, pending)
	if err != nil {
		return err
	}
	if complete != nil {
		if !resume {
			return errors.New("completed metadata already exists; explicit resume is required")
		}
		raw, err := readCollectionPublication(root, final, complete, maximum)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, expected) {
			return errors.New("completed metadata differs from the exact immutable collection")
		}
		if staged != nil {
			if err := root.Remove(pending); err != nil {
				return err
			}
			if err := syncCollectionRoot(root); err != nil {
				return err
			}
		}
		file, err := openCollectionMember(root, final)
		if err != nil {
			return err
		}
		defer file.Close()
		if err := file.Sync(); err != nil {
			return err
		}
		return syncCollectionRoot(root)
	}
	if staged != nil && !resume {
		return errors.New("pending metadata requires explicit resume")
	}
	file, err := openCollectionMember(root, pending)
	if err != nil {
		return err
	}
	defer file.Close()
	prefix, err := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
	if err != nil || !bytes.HasPrefix(expected, prefix) {
		return errors.New("pending metadata is not an exact prefix; original bytes are preserved")
	}
	if _, err := file.Seek(int64(len(prefix)), io.SeekStart); err != nil {
		return err
	}
	n, writeErr := file.Write(expected[len(prefix):])
	syncErr := file.Sync()
	if writeErr != nil {
		return writeErr
	}
	if n != len(expected)-len(prefix) {
		return io.ErrShortWrite
	}
	if syncErr != nil {
		return syncErr
	}
	info, err := file.Stat()
	if err != nil || collectionFileLinks(info) != 1 {
		return errors.New("pending metadata changed before publication")
	}
	raw, err := readCollectionPublication(root, pending, info, maximum)
	if err != nil || !bytes.Equal(raw, expected) {
		return errors.New("pending metadata readback differs from the complete record")
	}
	if err := root.Link(pending, final); err != nil {
		return err
	}
	if err := syncCollectionRoot(root); err != nil {
		return err
	}
	if err := root.Remove(pending); err != nil {
		return err
	}
	return syncCollectionRoot(root)
}
func bindCollection(root *os.Root, binding collectionBinding, resume bool) error {
	// No payload/proof may predate a missing durable binding. A lone pending
	// binding is initialization intent, not a committed snapshot reference.
	if _, err := root.Lstat("bindings.json"); os.IsNotExist(err) {
		entries, err := collectionEntries(root)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Name() != collectionBindingPending {
				return errors.New("collection data has no complete immutable binding; preserve it and choose another directory")
			}
		}
	} else if err != nil {
		return err
	}
	return publishCollectionJSON(root, "bindings.json", collectionBindingPending, collectionJSON(binding), resume)
}
func publishCollectionReceipt(root *os.Root, binding collectionBinding, current int64, resume bool) ([]byte, error) {
	entries, err := collectionEntries(root)
	if err != nil {
		return nil, err
	}
	if err := validateCollectionEntries(entries); err != nil {
		return nil, err
	}
	var pending string
	var generation int64
	for _, entry := range entries {
		if n, ok := receiptPendingGeneration(entry.Name()); ok {
			pending, generation = entry.Name(), n
		}
	}
	complete, _, err := publicationPair(root, "receipt.json", pending)
	if err != nil {
		return nil, err
	}
	var expected []byte
	if complete != nil {
		if !resume {
			return nil, errors.New("completed receipt already exists")
		}
		raw, err := readCollectionPublication(root, "receipt.json", complete)
		if err != nil {
			return nil, err
		}
		var original goCollectionReceipt
		if json.Unmarshal(raw, &original) != nil || !bytes.Equal(raw, collectionJSON(original)) || !reflect.DeepEqual(original.Binding, binding) || !original.BytesVerified || original.CollectedGeneration < 1 || original.CollectedGeneration > current || original.CurrentRegistryAdmission || original.ChecksumAuthority || original.DependencyClosure || original.DeliveryVerified {
			return nil, errors.New("saved receipt differs from this verified historical collection")
		}
		if pending != "" && generation != original.CollectedGeneration {
			return nil, errors.New("pending and completed receipt generations differ")
		}
		generation = original.CollectedGeneration
		expected = raw
	} else {
		if pending != "" && (!resume || generation > current) {
			return nil, errors.New("pending completion intent is future or requires explicit resume")
		}
		if pending == "" {
			generation = current
		}
		expected = collectionJSON(goCollectionReceipt{Binding: binding, CollectedGeneration: generation, BytesVerified: true})
	}
	if generation < 1 {
		return nil, errors.New("invalid completion generation")
	}
	if pending == "" {
		pending = fmt.Sprintf("receipt.%d.pending", generation)
	}
	if err := publishCollectionJSON(root, "receipt.json", pending, expected, resume); err != nil {
		return nil, err
	}
	return expected, nil
}
