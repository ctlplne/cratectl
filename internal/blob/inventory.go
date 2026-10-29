// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"container/heap"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

var ErrInventoryBudget = errors.New("inventory directory entry budget exceeded")
var bucketName = regexp.MustCompile(`^[a-f0-9]{2}$`)
var digestName = regexp.MustCompile(`^[a-f0-9]{64}$`)

type InventoryEntry struct {
	Name         string `json:"name"`
	NameB64      string `json:"name_b64"`
	Type         string `json:"type"`
	Size         int64  `json:"size"`
	ModifiedNS   int64  `json:"modified_ns"`
	FileIdentity string `json:"file_identity"`
	Expected     bool   `json:"expected_layout"`
	Digest       string `json:"digest"`
}
type InventoryPage struct {
	Area        string           `json:"area"`
	Bucket      string           `json:"bucket"`
	Entries     []InventoryEntry `json:"entries"`
	More        bool             `json:"more"`
	Missing     bool             `json:"missing"`
	Unsupported bool             `json:"unsupported"`
	Scanned     int              `json:"scanned"`
}

func ValidInventoryArea(area, bucket string) bool {
	switch area {
	case "root", "sha256", "staged", "uploads":
		return bucket == ""
	case "cas":
		return bucketName.MatchString(bucket)
	}
	return false
}
func inventoryName(encoded string) (string, error) {
	if len(encoded) > 344 {
		return "", ErrUnsupported
	}
	data, e := base64.RawURLEncoding.DecodeString(encoded)
	if e != nil || len(data) > 255 || strings.ContainsAny(string(data), "/\x00") || string(data) == "." || string(data) == ".." || base64.RawURLEncoding.EncodeToString(data) != encoded {
		return "", ErrUnsupported
	}
	return string(data), nil
}
func (s *Local) inventoryDirectory(tenant, area, bucket string) (*os.Root, error) {
	if !ValidInventoryArea(area, bucket) {
		return nil, ErrUnsupported
	}
	root, _, e := s.tenantRoot(tenant)
	if e != nil {
		return nil, e
	}
	parts := []string{}
	switch area {
	case "sha256", "staged", "uploads":
		parts = []string{area}
	case "cas":
		parts = []string{"sha256", bucket}
	}
	for _, part := range parts {
		child, _, e := checkedDirectory(root, part)
		root.Close()
		if e != nil {
			return nil, e
		}
		root = child
	}
	return root, nil
}

type nameHeap []string

func (h nameHeap) Len() int           { return len(h) }
func (h nameHeap) Less(i, j int) bool { return h[i] > h[j] }
func (h nameHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *nameHeap) Push(x any)        { *h = append(*h, x.(string)) }
func (h *nameHeap) Pop() any          { old := *h; x := old[len(old)-1]; *h = old[:len(old)-1]; return x }

// ListInventoryPage retains only the next bounded lexical page. The full
// directory scan is separately budgeted; raw filename bytes survive retries.
func (s *Local) ListInventoryPage(ctx context.Context, tenant, rootID, area, bucket, after string, limit, budget int) (InventoryPage, error) {
	page := InventoryPage{Area: area, Bucket: bucket, Entries: []InventoryEntry{}}
	if limit < 1 || limit > 1000 || budget < limit || budget > 2147483646 {
		return page, ErrInventoryBudget
	}
	cursor, e := inventoryName(after)
	if e != nil {
		return page, e
	}
	current, e := s.InventoryRoot(tenant)
	if e != nil {
		return page, e
	}
	if current != rootID {
		return page, ErrStorageChanged
	}
	dir, e := s.inventoryDirectory(tenant, area, bucket)
	if errors.Is(e, os.ErrNotExist) {
		page.Missing = true
		return page, nil
	}
	if errors.Is(e, ErrUnsupported) {
		page.Unsupported = true
		return page, nil
	}
	if e != nil {
		return page, e
	}
	defer dir.Close()
	f, e := dir.Open(".")
	if e != nil {
		return page, e
	}
	defer f.Close()
	names := &nameHeap{}
	heap.Init(names)
	for {
		if e = ctx.Err(); e != nil {
			return page, e
		}
		entries, readErr := f.ReadDir(128)
		for _, entry := range entries {
			page.Scanned++
			if page.Scanned > budget {
				return page, ErrInventoryBudget
			}
			name := entry.Name()
			if name <= cursor {
				continue
			}
			if names.Len() < limit+1 {
				heap.Push(names, name)
			} else if name < (*names)[0] {
				heap.Pop(names)
				heap.Push(names, name)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return page, readErr
		}
	}
	selected := []string(*names)
	sort.Strings(selected)
	page.More = len(selected) > limit
	if page.More {
		selected = selected[:limit]
	}
	for _, name := range selected {
		item := InventoryEntry{Name: strings.ToValidUTF8(name, "�"), NameB64: base64.RawURLEncoding.EncodeToString([]byte(name)), Type: "disappeared"}
		info, e := dir.Lstat(name)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return page, e
		}
		if e == nil {
			item.Size = max(0, info.Size())
			item.ModifiedNS = info.ModTime().UnixNano()
			item.FileIdentity = fileIdentity(info)
			switch {
			case info.Mode().IsRegular():
				item.Type = "file"
			case info.IsDir():
				item.Type = "directory"
			case info.Mode()&os.ModeSymlink != 0:
				item.Type = "symlink"
			default:
				item.Type = "other"
			}
		}
		switch area {
		case "root":
			item.Expected = (name == "sha256" || name == "staged" || name == "uploads") && item.Type == "directory"
		case "sha256":
			item.Expected = bucketName.MatchString(name) && item.Type == "directory"
		case "cas":
			if digestName.MatchString(name) && strings.HasPrefix(name, bucket) {
				item.Digest = name
			}
			item.Expected = item.Digest != "" && item.Type == "file"
		case "staged":
			item.Expected = strings.HasPrefix(name, "upload-") && item.Type == "file"
		case "uploads":
			item.Expected = uploadID.MatchString(name) && item.Type == "file"
		}
		page.Entries = append(page.Entries, item)
	}
	current, e = s.InventoryRoot(tenant)
	if e != nil {
		return page, e
	}
	if current != rootID {
		return page, ErrStorageChanged
	}
	return page, nil
}
func (s *Local) CheckInventoryObject(ctx context.Context, tenant, rootID string, entry InventoryEntry, maxBytes, rate int64) (string, error) {
	current, e := s.InventoryRoot(tenant)
	if e != nil {
		return "io_error", e
	}
	if current != rootID {
		return "changed", ErrStorageChanged
	}
	if !entry.Expected || entry.Type != "file" || !digestName.MatchString(entry.Digest) {
		return "unsupported", nil
	}
	if entry.Size < 0 || entry.Size >= 1<<62 || entry.Size > maxBytes {
		return "limit", nil
	}
	f, e := s.Open(tenant, entry.Digest)
	if errors.Is(e, os.ErrNotExist) {
		return "missing", nil
	}
	if e != nil {
		return "io_error", nil
	}
	defer f.Close()
	matches := func() bool {
		info, e := f.Stat()
		return e == nil && info.Size() == entry.Size && info.ModTime().UnixNano() == entry.ModifiedNS && fileIdentity(info) == entry.FileIdentity
	}
	if !matches() {
		return "changed", nil
	}
	status, e := checkStoredFile(ctx, f, entry.Digest, entry.Size, maxBytes, rate)
	if !matches() {
		return "changed", nil
	}
	return status, e
}
