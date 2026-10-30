// SPDX-License-Identifier: BUSL-1.1
package blob

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

var repairStageName = regexp.MustCompile(`^upload-[A-Za-z0-9_-]{43}$`)

// RepairSource is a private worker receipt, never a serving locator.
type RepairSource struct {
	Name   string `json:"name"`
	Root   string `json:"root"`
	File   string `json:"file"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

func (s *Local) StageRepair(ctx context.Context, tenant, rootID, digest string, size int64, r io.Reader) (RepairSource, error) {
	out := RepairSource{}
	if _, e := s.path(tenant, digest); e != nil {
		return out, e
	}
	if size < 0 || size > s.max {
		return out, ErrLimit
	}
	current, e := s.InventoryRoot(tenant)
	if e != nil {
		return out, e
	}
	if current != rootID {
		return out, ErrStorageChanged
	}
	base, e := os.OpenRoot(s.root)
	if e != nil {
		return out, e
	}
	defer base.Close()
	ns, _, e := createCheckedDirectory(base, tenant)
	if e != nil {
		return out, e
	}
	defer ns.Close()
	root, e := storageRootIdentity(base, ns, tenant)
	if e != nil {
		return out, e
	}
	stage, _, e := createCheckedDirectory(ns, "staged")
	if e != nil {
		return out, e
	}
	defer stage.Close()
	token, e := crypt.Token()
	if e != nil {
		return out, e
	}
	name := "upload-" + token
	f, e := stage.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return out, e
	}
	defer f.Close()
	keep := false
	defer func() {
		if !keep {
			_ = stage.Remove(name)
		}
	}()
	hash := crypt.SHA256()
	n, e := io.CopyBuffer(io.MultiWriter(f, hash), io.LimitReader(contextReader{ctx, r}, size+1), make([]byte, 64<<10))
	if e != nil {
		return out, e
	}
	if n != size {
		return out, ErrLength
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return out, ErrDigest
	}
	if e = f.Sync(); e != nil {
		return out, e
	}
	info, e := f.Stat()
	if e != nil {
		return out, e
	}
	for _, dir := range []*os.Root{stage, ns, base} {
		if e = syncRoot(dir); e != nil {
			return out, e
		}
	}
	current, e = s.InventoryRoot(tenant)
	if e != nil {
		return out, e
	}
	if current != root {
		return out, ErrStorageChanged
	}
	out = RepairSource{Name: name, Root: root, File: fileIdentity(info), Digest: digest, Size: size}
	keep = true
	return out, nil
}

type RepairInstallation struct {
	Before           string `json:"before"`
	PreviousFile     string `json:"previous_file,omitempty"`
	PreviousSize     int64  `json:"previous_size,omitempty"`
	RetainedPrevious bool   `json:"retained_previous"`
	Installed        bool   `json:"installed"`
}

// PreparedRepair keeps the verified source descriptor and checked directories
// open across the short database-fenced installation step.
type PreparedRepair struct {
	store                    *Local
	tenant                   string
	source                   RepairSource
	root, stage, sha, prefix *os.Root
	file                     *os.File
	sourceInfo, targetInfo   os.FileInfo
	status                   string
}

func (p *PreparedRepair) Close() {
	if p == nil {
		return
	}
	for _, f := range []*os.File{p.file} {
		if f != nil {
			_ = f.Close()
		}
	}
	for _, dir := range []*os.Root{p.prefix, p.sha, p.stage, p.root} {
		if dir != nil {
			_ = dir.Close()
		}
	}
}

func (s *Local) PrepareRepair(ctx context.Context, tenant string, source RepairSource, maxBytes, rate int64) (*PreparedRepair, error) {
	if !repairStageName.MatchString(source.Name) || source.Size < 0 || source.Size > s.max || source.Size > maxBytes {
		return nil, ErrLimit
	}
	if _, e := s.path(tenant, source.Digest); e != nil {
		return nil, e
	}
	root, id, e := s.tenantRoot(tenant)
	if e != nil {
		return nil, e
	}
	if id != source.Root {
		root.Close()
		return nil, ErrStorageChanged
	}
	p := &PreparedRepair{store: s, tenant: tenant, source: source, root: root}
	ok := false
	defer func() {
		if !ok {
			p.Close()
		}
	}()
	p.stage, _, e = checkedDirectory(root, "staged")
	if e != nil {
		return nil, e
	}
	p.file, e = s.openRegularFile(tenant, "staged", source.Name)
	if e != nil {
		return nil, e
	}
	p.sourceInfo, e = p.file.Stat()
	if e != nil {
		return nil, e
	}
	if fileIdentity(p.sourceInfo) != source.File {
		return nil, ErrStorageChanged
	}
	status, e := checkStoredFile(ctx, p.file, source.Digest, source.Size, maxBytes, rate)
	if e != nil {
		return nil, e
	}
	if status != "verified" {
		return nil, ErrIntegrity
	}
	p.sha, _, e = createCheckedDirectory(root, "sha256")
	if e != nil {
		return nil, e
	}
	p.prefix, _, e = createCheckedDirectory(p.sha, source.Digest[:2])
	if e != nil {
		return nil, e
	}
	p.targetInfo, e = p.prefix.Lstat(source.Digest)
	if errors.Is(e, os.ErrNotExist) {
		p.status = "missing"
	} else if e != nil {
		return nil, e
	} else {
		if !p.targetInfo.Mode().IsRegular() {
			return nil, ErrUnsupported
		}
		target, e := s.Open(tenant, source.Digest)
		if e != nil {
			return nil, e
		}
		info, e := target.Stat()
		if e != nil || !os.SameFile(info, p.targetInfo) {
			target.Close()
			return nil, ErrStorageChanged
		}
		p.status, e = checkStoredFile(ctx, target, source.Digest, source.Size, maxBytes, rate)
		_ = target.Close()
		if e != nil {
			return nil, e
		}
		if p.status != "verified" && p.status != "corrupt" {
			return nil, ErrIntegrity
		}
	}
	ok = true
	return p, nil
}

// Install performs no unbounded reads. Call only under a live, uncancelled job
// fence. The source is retained for idempotent recovery after a lost DB commit.
func (p *PreparedRepair) Install(ctx context.Context) (RepairInstallation, error) {
	out := RepairInstallation{Before: p.status}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	current, e := p.store.InventoryRoot(p.tenant)
	if e != nil {
		return out, e
	}
	if current != p.source.Root {
		return out, ErrStorageChanged
	}
	source, e := p.stage.Lstat(p.source.Name)
	if e != nil {
		return out, e
	}
	held, e := p.file.Stat()
	if e != nil {
		return out, e
	}
	if !source.Mode().IsRegular() || !os.SameFile(source, p.sourceInfo) || !os.SameFile(held, p.sourceInfo) || held.Size() != p.sourceInfo.Size() || !held.ModTime().Equal(p.sourceInfo.ModTime()) {
		return out, ErrStorageChanged
	}
	target, e := p.prefix.Lstat(p.source.Digest)
	missing := errors.Is(e, os.ErrNotExist)
	if e != nil && !missing {
		return out, e
	}
	if p.status == "missing" && !missing || p.status != "missing" && (missing || !target.Mode().IsRegular() || !os.SameFile(target, p.targetInfo) || target.Size() != p.targetInfo.Size() || !target.ModTime().Equal(p.targetInfo.ModTime())) {
		return out, ErrStorageChanged
	}
	if p.status == "verified" {
		return out, nil
	}
	if p.status == "corrupt" {
		token, e := crypt.Token()
		if e != nil {
			return out, e
		}
		backup := "upload-" + token
		if e = p.root.Link("sha256/"+p.source.Digest[:2]+"/"+p.source.Digest, "staged/"+backup); e != nil {
			return out, e
		}
		retained, e := p.stage.Lstat(backup)
		if e != nil || !retained.Mode().IsRegular() || !os.SameFile(retained, p.targetInfo) {
			return out, ErrStorageChanged
		}
		out.PreviousFile = fileIdentity(retained)
		out.PreviousSize = retained.Size()
		out.RetainedPrevious = true
		// Keep the backup even if installation/commit later fails.
		if e = syncRoot(p.stage); e != nil {
			return out, e
		}
	}
	token, e := crypt.Token()
	if e != nil {
		return out, e
	}
	alias := "upload-" + token
	if e = p.root.Link("staged/"+p.source.Name, "staged/"+alias); e != nil {
		return out, e
	}
	defer p.stage.Remove(alias)
	linked, e := p.stage.Lstat(alias)
	if e != nil || !linked.Mode().IsRegular() || !os.SameFile(linked, p.sourceInfo) {
		return out, ErrStorageChanged
	}
	destination := "sha256/" + p.source.Digest[:2] + "/" + p.source.Digest
	if e = ctx.Err(); e != nil {
		return out, e
	}
	if p.status == "missing" {
		e = p.root.Link("staged/"+alias, destination)
	} else {
		e = p.root.Rename("staged/"+alias, destination)
	}
	if e != nil {
		return out, e
	}
	out.Installed = true
	for _, dir := range []*os.Root{p.prefix, p.sha, p.stage, p.root} {
		if e = syncRoot(dir); e != nil {
			return out, e
		}
	}
	current, e = p.store.InventoryRoot(p.tenant)
	if e != nil {
		return out, e
	}
	if current != p.source.Root {
		return out, ErrStorageChanged
	}
	visible, e := p.store.Open(p.tenant, p.source.Digest)
	if e != nil {
		return out, e
	}
	defer visible.Close()
	info, e := visible.Stat()
	if e != nil || !os.SameFile(info, p.sourceInfo) {
		return out, ErrStorageChanged
	}
	return out, nil
}
