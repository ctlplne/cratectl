// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/ziparchive"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

const goSetOfflineProfile = "cratectl.go.hosted.set-offline.v1"
const maxSetOfflinePaths = 1 << 17
const offlineSetPending = ".receipt.pending"

type goSetOfflineRoot struct {
	Repository string `json:"repository"`
	Module     string `json:"module"`
	Version    string `json:"version"`
	ZIPHash    string `json:"zip_h1"`
	ModHash    string `json:"mod_h1"`
}
type goSetOfflineReceipt struct {
	Profile                  string                     `json:"profile"`
	SetID                    string                     `json:"set_id"`
	Manifest                 blob.Object                `json:"manifest"`
	CollectionReceipt        blob.Object                `json:"collection_receipt"`
	CollectedGeneration      int64                      `json:"collected_generation"`
	Journal                  checksumJournalAttribution `json:"journal_attribution"`
	Roots                    []goSetOfflineRoot         `json:"roots"`
	Proxy                    string                     `json:"goproxy"`
	BytesVerified            bool                       `json:"bytes_verified"`
	SelectedRootsComplete    bool                       `json:"selected_roots_complete"`
	NativeProxyPrepared      bool                       `json:"native_proxy_prepared"`
	CurrentRegistryAdmission bool                       `json:"current_registry_admission"`
	ChecksumAuthority        bool                       `json:"checksum_authority_verified"`
	DependencyClosure        bool                       `json:"dependency_closure"`
	Trust                    string                     `json:"trust"`
}
type goSetOfflineIntent struct {
	Profile           string      `json:"profile"`
	SetID             string      `json:"set_id"`
	Manifest          blob.Object `json:"manifest"`
	CollectionBinding blob.Object `json:"collection_binding"`
	CollectionReceipt blob.Object `json:"collection_receipt"`
	Proxy             string      `json:"goproxy"`
}
type offlineSetInput struct {
	manifest               store.GoExportSetManifest
	raw                    []byte
	attribution            checksumJournalAttribution
	binding                goSetCollectionBinding
	receipt                goSetCollectionReceipt
	bindingRaw, receiptRaw []byte
}

func offlineObject(raw []byte) blob.Object {
	return blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}
}
func openExistingSetFile(root *os.Root, name string) (*os.File, error) {
	before, err := root.Lstat(name)
	if err != nil || !privateCollectionFile(before, false) {
		return nil, errors.New("required private unshared regular member unavailable")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|collectionOpenFlags(), 0)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !privateCollectionFile(after, false) || !os.SameFile(before, after) {
		file.Close()
		return nil, errors.New("private input member changed")
	}
	return file, nil
}
func readExistingSetFile(root *os.Root, name string, maximum int64) ([]byte, error) {
	file, err := openExistingSetFile(root, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || before.Size() > maximum {
		return nil, errors.New("private member exceeds its byte bound")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	after, se := file.Stat()
	mapped, me := root.Lstat(name)
	if err != nil || se != nil || me != nil || len(raw) > int(maximum) || int64(len(raw)) != before.Size() || !os.SameFile(before, after) || !os.SameFile(after, mapped) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !privateCollectionFile(after, false) {
		return nil, errors.New("private member changed while reading")
	}
	return raw, nil
}
func hashExistingSetFile(ctx context.Context, file *os.File, object blob.Object) error {
	before, err := file.Stat()
	if err != nil || !privateCollectionFile(before, false) || before.Size() != object.Size {
		return errors.New("incomplete private member")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := crypt.SHA256()
	n, err := io.CopyBuffer(hash, io.LimitReader(offlineGoReader{ctx, file}, object.Size+1), make([]byte, 64<<10))
	after, se := file.Stat()
	if err != nil || se != nil || n != object.Size || hex.EncodeToString(hash.Sum(nil)) != object.Digest || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !privateCollectionFile(after, false) {
		return errors.New("private member differs from its original immutable identity")
	}
	return nil
}
func commonSourceDirectory(root *os.Root) error {
	entries, err := collectionEntries(root, goSetCollectionEntries)
	if err != nil {
		return err
	}
	known := map[string]bool{"bindings.json": true, "receipt.json": true, "manifest.json": true, "journal.jsonl": true, "checkpoint.json": true, "checkpoint.sig": true, "signer-public.pem": true}
	for n := range store.MaxGoExportSetEntries {
		for _, kind := range []string{"zip", "mod", "info"} {
			known[setCollectionName(n, kind)] = true
		}
	}
	for _, entry := range entries {
		if !known[entry.Name()] {
			return errors.New("collection contains pending or unknown members; finish explicit collector recovery first")
		}
		info, err := entry.Info()
		if err != nil || !privateCollectionFile(info, false) {
			return errors.New("collection members must be private unshared regular files")
		}
	}
	return nil
}
func collectionAuthority(value string) bool {
	u, err := url.Parse(value)
	if err != nil || len(value) > 2048 || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Path != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "http" && ip != nil && ip.IsLoopback()
}

func parseOfflineSetBinding(raw []byte) (goSetCollectionBinding, error) {
	var value goSetCollectionBinding
	if len(raw) < 1 || len(raw) > goSetCollectionJSONLimit || json.Unmarshal(raw, &value) != nil || !bytes.Equal(raw, collectionJSON(value)) || value.Profile != goSetCollectionProfile || !store.ValidGoExportID(value.SetID) || !collectionAuthority(value.Authority) || len(value.Members) < 8 || len(value.Members) > 5+3*store.MaxGoExportSetEntries {
		return goSetCollectionBinding{}, errors.New("invalid bounded canonical private collection binding")
	}
	return value, nil
}
func parseOfflineSetReceipt(raw []byte, expected goSetCollectionBinding) (goSetCollectionReceipt, error) {
	var value goSetCollectionReceipt
	if len(raw) < 1 || len(raw) > goSetCollectionJSONLimit || json.Unmarshal(raw, &value) != nil || !bytes.Equal(raw, collectionJSON(value)) || !reflect.DeepEqual(value.Binding, expected) || value.CollectedGeneration < 1 || !value.BytesVerified || value.CurrentRegistryAdmission || value.ChecksumAuthority || value.DependencyClosure || value.DeliveryVerified {
		return goSetCollectionReceipt{}, errors.New("collection lacks a complete canonical original receipt")
	}
	return value, nil
}
func capsuleProofPaths(directory string, j checksumJournalFlags) error {
	for _, item := range []struct {
		value *string
		name  string
	}{{j.file, "journal.jsonl"}, {j.checkpoint.statement, "checkpoint.json"}, {j.checkpoint.signature, "checkpoint.sig"}} {
		expected := filepath.Join(directory, item.name)
		if *item.value != "" {
			actual, err := filepath.Abs(*item.value)
			if err != nil || actual != expected {
				return errors.New("journal/statement/signature must be the exact retained collection members")
			}
		}
		*item.value = expected
	}
	if *j.checkpoint.key == "" {
		return errors.New("select checkpoint-key-file through an independent trust channel")
	}
	return nil
}
func loadOfflineSetInput(root *os.Root, j checksumJournalFlags, f *flag.FlagSet, id string) (offlineSetInput, error) {
	var empty offlineSetInput
	attribution, event, err := j.selectEvent(f)
	if err != nil {
		return empty, err
	}
	if attribution == nil {
		return empty, errors.New("complete independent signed journal required")
	}
	raw, err := readExistingSetFile(root, "manifest.json", store.MaxGoExportSetManifest)
	if err != nil {
		return empty, err
	}
	manifest, err := store.BindGoExportSetManifest(raw, *j.tenant, id, event)
	if err != nil {
		return empty, errors.New("common manifest is not bound to this original signed creation")
	}
	proofBytes := map[string][]byte{"manifest.json": raw}
	for _, entry := range []struct {
		name    string
		maximum int64
	}{{"checkpoint.json", crypt.MaxJournalCheckpointStatement}, {"checkpoint.sig", crypt.JournalCheckpointSignatureBytes}, {"signer-public.pem", crypt.MaxJournalCheckpointPublicKey}} {
		value, err := readExistingSetFile(root, entry.name, entry.maximum)
		if err != nil {
			return empty, err
		}
		proofBytes[entry.name] = value
	}
	head := crypt.JournalAnchor{Tenant: attribution.Journal.Tenant, Sequence: attribution.Journal.HeadSequence, Hash: attribution.Journal.HeadHash}
	verified, err := crypt.VerifyJournalCheckpoint(proofBytes["checkpoint.json"], proofBytes["checkpoint.sig"], proofBytes["signer-public.pem"], head)
	if err != nil || verified != attribution.CheckpointSignature {
		return empty, errors.New("retained public key/proof differs from independently selected trust")
	}
	bindingRaw, err := readExistingSetFile(root, "bindings.json", goSetCollectionJSONLimit)
	if err != nil {
		return empty, err
	}
	stored, err := parseOfflineSetBinding(bindingRaw)
	if err != nil {
		return empty, err
	}
	expected := goSetCollectionBinding{Profile: goSetCollectionProfile, Authority: stored.Authority, SetID: id, Journal: *attribution}
	for _, name := range []string{"manifest.json", "checkpoint.json", "checkpoint.sig", "signer-public.pem"} {
		expected.Members = append(expected.Members, collectionMember{name, offlineObject(proofBytes[name])})
	}
	journal, err := openExistingSetFile(root, "journal.jsonl")
	if err != nil {
		return empty, err
	}
	js, err := journal.Stat()
	journal.Close()
	if err != nil || js.Size() > *j.maxBytes {
		return empty, errors.New("retained journal exceeds selected bound")
	}
	expected.Members = append(expected.Members, collectionMember{"journal.jsonl", blob.Object{Digest: attribution.Journal.ExportSHA256, Size: js.Size()}})
	for n, entry := range manifest.Entries {
		for k, kind := range []string{"zip", "mod", "info"} {
			a := entry.Artifacts[k]
			expected.Members = append(expected.Members, collectionMember{setCollectionName(n, kind), blob.Object{Digest: a.Digest, Size: a.Size}})
		}
	}
	if !reflect.DeepEqual(expected, stored) {
		return empty, errors.New("collection member map differs from original proof and complete selection")
	}
	receiptRaw, err := readExistingSetFile(root, "receipt.json", goSetCollectionJSONLimit)
	if err != nil {
		return empty, err
	}
	receipt, err := parseOfflineSetReceipt(receiptRaw, expected)
	if err != nil {
		return empty, err
	}
	if err := validateSetCollectionEntries(root, expected); err != nil {
		return empty, err
	}
	entries, err := collectionEntries(root, goSetCollectionEntries)
	if err != nil {
		return empty, err
	}
	if len(entries) != len(expected.Members)+2 {
		return empty, errors.New("collection has missing or extra originals")
	}
	return offlineSetInput{manifest, raw, *attribution, expected, receipt, bindingRaw, receiptRaw}, nil
}

type offlineSetLayout struct {
	paths    map[string]bool // true directory; false regular file
	versions map[string][]string
	prefixes map[string]string
	latest   map[string]int
}

func offlineSetLayoutFor(m store.GoExportSetManifest) (offlineSetLayout, error) {
	if len(m.Entries) < 1 || len(m.Entries) > store.MaxGoExportSetEntries {
		return offlineSetLayout{}, errors.New("invalid bounded offline root count")
	}
	out := offlineSetLayout{paths: map[string]bool{".": true}, versions: map[string][]string{}, prefixes: map[string]string{}, latest: map[string]int{}}
	add := func(name string) error {
		if name == "" || len(name) > 2048 || filepath.IsAbs(name) || filepath.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
			return errors.New("invalid bounded native proxy path")
		}
		if directory, exists := out.paths[name]; exists && directory {
			return errors.New("native path type collision")
		}
		out.paths[name] = false
		for parent := filepath.Dir(name); parent != "."; parent = filepath.Dir(parent) {
			if directory, exists := out.paths[parent]; exists && !directory {
				return errors.New("native directory collides with a file")
			}
			out.paths[parent] = true
		}
		if len(out.paths) > maxSetOfflinePaths {
			return errors.New("native file proxy path budget exceeded")
		}
		return nil
	}
	for n, entry := range m.Entries {
		c, err := gomodule.Canonical(entry.Module, entry.Version)
		if err != nil {
			return offlineSetLayout{}, err
		}
		prefix := c.Prefix()
		split := strings.LastIndex(prefix, "/@v/")
		if split < 1 {
			return offlineSetLayout{}, errors.New("invalid canonical native prefix")
		}
		base := prefix[:split]
		out.prefixes[c.Module] = base
		out.versions[c.Module] = append(out.versions[c.Module], c.Version)
		if old, ok := out.latest[c.Module]; !ok || gomodule.LatestVersion([]string{m.Entries[old].Version, c.Version}) == c.Version {
			out.latest[c.Module] = n
		}
		for _, kind := range []string{"zip", "mod", "info"} {
			if err = add("proxy/" + prefix + "." + kind); err != nil {
				return offlineSetLayout{}, err
			}
		}
	}
	for name, base := range out.prefixes {
		semver.Sort(out.versions[name])
		for _, path := range []string{"proxy/" + base + "/@v/list", "proxy/" + base + "/@latest"} {
			if err := add(path); err != nil {
				return offlineSetLayout{}, err
			}
		}
	}
	for _, name := range []string{"manifest.json", "checkpoint.json", "checkpoint.sig", "signer-public.pem", "journal.jsonl", "bindings.json", "receipt.json"} {
		if err := add("proof/" + name); err != nil {
			return offlineSetLayout{}, err
		}
	}
	for _, name := range []string{"receipt.json", offlineSetPending} {
		if err := add(name); err != nil {
			return offlineSetLayout{}, err
		}
	}
	return out, nil
}
func offlineSetOutputDirectory(root *os.Root) error {
	entries, err := collectionEntries(root, 4)
	if err != nil {
		return err
	}
	trees := 0
	for _, entry := range entries {
		switch entry.Name() {
		case "bindings.json", collectionBindingPending:
		case "staging", "bundle":
			info, err := entry.Info()
			if err != nil || !privateCollectionFile(info, true) {
				return errors.New("offline tree must be a private directory without links")
			}
			trees++
		default:
			return errors.New("offline output contains unexpected state; preserve it")
		}
	}
	if trees > 1 {
		return errors.New("offline output has competing staged/published trees; preserve both")
	}
	_, _, err = publicationPair(root, "bindings.json", collectionBindingPending)
	return err
}
func bindOfflineSetOutput(root *os.Root, intent goSetOfflineIntent, resume bool) error {
	if _, err := root.Lstat("bindings.json"); os.IsNotExist(err) {
		entries, err := collectionEntries(root, 4)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Name() != collectionBindingPending {
				return errors.New("offline payload has no complete immutable intent")
			}
		}
	} else if err != nil {
		return err
	}
	return publishCollectionJSON(root, "bindings.json", collectionBindingPending, collectionJSON(intent), resume, goSetCollectionJSONLimit)
}

// Enumerate fixed-size batches. fs.WalkDir/ReadDir(-1) can allocate an entire
// hostile directory before the overall path limit is checked.
func validateOfflineSetTree(root *os.Root, layout offlineSetLayout, complete bool) error {
	a, b, err := publicationPair(root, "receipt.json", offlineSetPending)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	stack := []string{"."}
	for len(stack) > 0 {
		if len(seen) > maxSetOfflinePaths {
			return errors.New("offline tree path budget exceeded")
		}
		path := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		directory, err := root.OpenFile(path, os.O_RDONLY|collectionOpenFlags(), 0)
		if err != nil {
			return err
		}
		info, err := directory.Stat()
		if err != nil || !privateCollectionFile(info, true) {
			directory.Close()
			return errors.New("offline directory changed or is not private")
		}
		seen[path] = true
		for {
			entries, readErr := directory.ReadDir(128)
			if readErr != nil && readErr != io.EOF {
				directory.Close()
				return readErr
			}
			for _, entry := range entries {
				name := entry.Name()
				if path != "." {
					name = path + "/" + name
				}
				wantDir, known := layout.paths[name]
				if !known {
					directory.Close()
					return errors.New("offline tree contains an unknown path; preserve it")
				}
				info, err := entry.Info()
				if err != nil {
					directory.Close()
					return err
				}
				seen[name] = true
				if len(seen) > maxSetOfflinePaths {
					directory.Close()
					return errors.New("offline tree path budget exceeded")
				}
				if wantDir {
					if !privateCollectionFile(info, true) {
						directory.Close()
						return errors.New("offline directory is linked or not private")
					}
					stack = append(stack, name)
				} else {
					metadata := name == "receipt.json" || name == offlineSetPending
					if metadata {
						expected := a
						if name == offlineSetPending {
							expected = b
						}
						if expected == nil || !os.SameFile(info, expected) || collectionFileLinks(info) != collectionFileLinks(expected) {
							directory.Close()
							return errors.New("offline completion metadata changed")
						}
					} else if !privateCollectionFile(info, false) {
						directory.Close()
						return errors.New("offline data must be private unshared regular files")
					}
				}
			}
			if readErr == io.EOF || len(entries) == 0 {
				break
			}
		}
		directory.Close()
	}
	if complete {
		for path := range layout.paths {
			if path == offlineSetPending {
				continue
			}
			if !seen[path] {
				return errors.New("published offline tree is missing a required member")
			}
		}
		if a == nil {
			return errors.New("published offline tree lacks its final receipt")
		}
	}
	return nil
}
func copyOfflineSetMember(ctx context.Context, source, target *os.Root, from, to string, object blob.Object, chunk int64, published bool) error {
	input, err := openExistingSetFile(source, from)
	if err != nil {
		return err
	}
	defer input.Close()
	before, err := input.Stat()
	if err != nil || before.Size() != object.Size {
		return errors.New("original collection member size changed")
	}
	if err = hashExistingSetFile(ctx, input, object); err != nil {
		return err
	}
	if published {
		output, err := openExistingSetFile(target, to)
		if err != nil {
			return err
		}
		err = hashExistingSetFile(ctx, output, object)
		output.Close()
		if err != nil {
			return err
		}
	} else {
		if err = verifyOfflineSetPrefix(ctx, target, to, input, object.Size); err != nil {
			return err
		}
		if err = target.MkdirAll(filepath.Dir(to), 0700); err != nil {
			return err
		}
		if err = copyCollectionLocal(ctx, target, to, input, object, chunk); err != nil {
			return err
		}
	}
	after, err := input.Stat()
	mapped, me := source.Lstat(from)
	if err != nil || me != nil || !os.SameFile(before, after) || !os.SameFile(after, mapped) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !privateCollectionFile(after, false) {
		return errors.New("original collection member changed while preparing proxy")
	}
	return nil
}

// Compare retained bytes before appending. A failed resume must preserve a
// corrupt prefix exactly, rather than extend it before the final digest fails.
func verifyOfflineSetPrefix(ctx context.Context, target *os.Root, name string, source io.ReaderAt, maximum int64) error {
	if _, err := target.Lstat(name); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	file, err := openExistingSetFile(target, name)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || before.Size() > maximum {
		return errors.New("retained offline prefix exceeds its original size")
	}
	a, b := make([]byte, 64<<10), make([]byte, 64<<10)
	for offset := int64(0); offset < before.Size(); {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := int(min(int64(len(a)), before.Size()-offset))
		an, ae := file.ReadAt(a[:n], offset)
		bn, be := source.ReadAt(b[:n], offset)
		if an != n || bn != n || ae != nil || be != nil || !bytes.Equal(a[:n], b[:n]) {
			return errors.New("retained offline prefix differs; corrupt bytes preserved")
		}
		offset += int64(n)
	}
	after, err := file.Stat()
	mapped, me := target.Lstat(name)
	if err != nil || me != nil || !os.SameFile(before, after) || !os.SameFile(after, mapped) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !privateCollectionFile(after, false) {
		return errors.New("retained offline prefix changed during comparison")
	}
	return nil
}
func writeOfflineSetDerived(ctx context.Context, target *os.Root, name string, raw []byte, chunk int64, published bool) error {
	object := offlineObject(raw)
	if published {
		file, err := openExistingSetFile(target, name)
		if err != nil {
			return err
		}
		defer file.Close()
		return hashExistingSetFile(ctx, file, object)
	}
	if err := verifyOfflineSetPrefix(ctx, target, name, bytes.NewReader(raw), object.Size); err != nil {
		return err
	}
	if err := target.MkdirAll(filepath.Dir(name), 0700); err != nil {
		return err
	}
	return copyCollectionLocal(ctx, target, name, bytes.NewReader(raw), object, chunk)
}
func inspectOfflineSetRoot(ctx context.Context, root *os.Root, entry store.GoExportManifest) (goSetOfflineRoot, error) {
	var empty goSetOfflineRoot
	c := gomodule.Coordinate{Module: entry.Module, Version: entry.Version}
	prefix := "proxy/" + c.Prefix()
	files := [3]*os.File{}
	defer func() {
		for _, f := range files {
			if f != nil {
				f.Close()
			}
		}
	}()
	for k, kind := range []string{"zip", "mod", "info"} {
		f, err := openExistingSetFile(root, prefix+"."+kind)
		if err != nil {
			return empty, err
		}
		files[k] = f
		if err = hashExistingSetFile(ctx, f, blob.Object{Digest: entry.Artifacts[k].Digest, Size: entry.Artifacts[k].Size}); err != nil {
			return empty, err
		}
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			return empty, err
		}
	}
	mod, err := io.ReadAll(io.LimitReader(files[1], gomodule.MaxGoMod+1))
	if err != nil {
		return empty, err
	}
	info, err := io.ReadAll(io.LimitReader(files[2], gomodule.MaxVersionInfo+1))
	if err != nil {
		return empty, err
	}
	result, err := gomodule.InspectRepresentations(ctx, files[0], entry.Artifacts[0].Size, c, mod, info, ziparchive.Limits{CompressedBytes: 512 << 20, ExpandedBytes: 512 << 20, DirectoryBytes: 16 << 20, Files: 16384})
	if err != nil {
		return empty, errors.New("offline original representations fail bounded native consistency")
	}
	for k, file := range files {
		if err = hashExistingSetFile(ctx, file, blob.Object{Digest: entry.Artifacts[k].Digest, Size: entry.Artifacts[k].Size}); err != nil {
			return empty, err
		}
	}
	return goSetOfflineRoot{entry.Repository, entry.Module, entry.Version, result.ZIPHash, result.GoModHash}, nil
}
func syncOfflineSetTree(ctx context.Context, tree *os.Root, layout offlineSetLayout) error {
	directories := []string{}
	for path, directory := range layout.paths {
		if directory {
			directories = append(directories, path)
		}
	}
	sort.Slice(directories, func(a, b int) bool {
		if len(directories[a]) != len(directories[b]) {
			return len(directories[a]) > len(directories[b])
		}
		return directories[a] < directories[b]
	})
	for _, name := range directories {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := tree.Open(name)
		if err != nil {
			return err
		}
		err = file.Sync()
		file.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func rejectNestedOfflineOutput(source *os.Root, destination string) error {
	handle, err := source.Open(".")
	if err != nil {
		return err
	}
	info, err := handle.Stat()
	handle.Close()
	if err != nil {
		return err
	}
	for parent := filepath.Dir(destination); ; parent = filepath.Dir(parent) {
		actual, err := os.Stat(parent)
		if err == nil && os.SameFile(info, actual) {
			return errors.New("offline output must be outside the retained source collection")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return nil
}
func assembleOfflineSet(ctx context.Context, source *os.Root, input offlineSetInput, destination string, resume bool, chunk, budget int64) ([]byte, error) {
	m, err := store.ParseGoExportSetManifest(input.raw)
	if err != nil || !reflect.DeepEqual(m, input.manifest) || input.binding.Profile != goSetCollectionProfile || !store.ValidGoExportID(input.binding.SetID) || !input.attribution.CheckpointSignature.SignatureVerified || !input.attribution.Journal.MatchesSuppliedCheckpoint || len(input.binding.Members) != 5+3*len(m.Entries) || chunk < 64<<10 || chunk > 8<<20 || budget < 1 || budget > 65<<30 {
		return nil, errors.New("invalid complete bounded offline selection")
	}
	var total int64
	for _, member := range input.binding.Members {
		if member.Object.Size < 0 || member.Object.Size > budget-total {
			return nil, errors.New("offline package/proof bytes exceed max-bytes before output")
		}
		total += member.Object.Size
	}
	for _, raw := range [][]byte{input.bindingRaw, input.receiptRaw} {
		if int64(len(raw)) > budget-total {
			return nil, errors.New("offline metadata exceeds combined max-bytes before output")
		}
		total += int64(len(raw))
	}
	layout, err := offlineSetLayoutFor(m)
	if err != nil {
		return nil, err
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return nil, err
	}
	if err = rejectNestedOfflineOutput(source, destination); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	proxy := (&url.URL{Scheme: "file", Path: filepath.Join(destination, "bundle", "proxy")}).String()
	intent := goSetOfflineIntent{Profile: "cratectl.go.hosted.set-offline.intent.v1", SetID: input.binding.SetID, Manifest: offlineObject(input.raw), CollectionBinding: offlineObject(input.bindingRaw), CollectionReceipt: offlineObject(input.receiptRaw), Proxy: proxy}
	output, lock, err := openCollectionDirectoryChecked(destination, resume, offlineSetOutputDirectory)
	if err != nil {
		return nil, err
	}
	defer output.Close()
	defer lock.Close()
	fail := func(err error) ([]byte, error) {
		return nil, fmt.Errorf("offline proxy incomplete or publication uncertain: %w; private state preserved for explicit same-input --resume", err)
	}
	if err = bindOfflineSetOutput(output, intent, resume); err != nil {
		return fail(err)
	}
	published := false
	name := "staging"
	if _, err = output.Lstat("bundle"); err == nil {
		published = true
		name = "bundle"
	} else if !os.IsNotExist(err) {
		return fail(err)
	}
	if !published {
		if _, err = output.Lstat(name); os.IsNotExist(err) {
			err = output.Mkdir(name, 0700)
		}
		if err != nil {
			return fail(err)
		}
	}
	tree, err := output.OpenRoot(name)
	if err != nil {
		return fail(err)
	}
	defer tree.Close()
	if err = validateOfflineSetTree(tree, layout, published); err != nil {
		return fail(err)
	}
	// Every original proof byte remains independently usable at the destination.
	for _, member := range input.binding.Members[:5] {
		if err = copyOfflineSetMember(ctx, source, tree, member.Name, "proof/"+member.Name, member.Object, chunk, published); err != nil {
			return fail(err)
		}
	}
	for _, member := range []struct {
		name string
		raw  []byte
	}{{"bindings.json", input.bindingRaw}, {"receipt.json", input.receiptRaw}} {
		if err = copyOfflineSetMember(ctx, source, tree, member.name, "proof/"+member.name, offlineObject(member.raw), chunk, published); err != nil {
			return fail(err)
		}
	}
	receipt := goSetOfflineReceipt{Profile: goSetOfflineProfile, SetID: input.binding.SetID, Manifest: offlineObject(input.raw), CollectionReceipt: offlineObject(input.receiptRaw), CollectedGeneration: input.receipt.CollectedGeneration, Journal: input.attribution, Proxy: proxy, BytesVerified: true, SelectedRootsComplete: true, NativeProxyPrepared: true, Trust: "Every explicitly selected original and complete retained proof was independently reverified before this native file proxy was published. Discovery covers this selected set only. This grants no current or destination admission, public checksum authority, automatically selected dependency/permission/provenance closure or history beyond the independently selected signed head."}
	for n, entry := range m.Entries {
		coordinate := gomodule.Coordinate{Module: entry.Module, Version: entry.Version}
		for k, kind := range []string{"zip", "mod", "info"} {
			a := entry.Artifacts[k]
			if err = copyOfflineSetMember(ctx, source, tree, setCollectionName(n, kind), "proxy/"+coordinate.Prefix()+"."+kind, blob.Object{Digest: a.Digest, Size: a.Size}, chunk, published); err != nil {
				return fail(err)
			}
		}
		verified, err := inspectOfflineSetRoot(ctx, tree, entry)
		if err != nil {
			return fail(err)
		}
		receipt.Roots = append(receipt.Roots, verified)
	}
	modules := []string{}
	for name := range layout.versions {
		modules = append(modules, name)
	}
	sort.Strings(modules)
	for _, name := range modules {
		var list strings.Builder
		for _, version := range layout.versions[name] {
			if !module.IsPseudoVersion(version) {
				list.WriteString(version)
				list.WriteByte('\n')
			}
		}
		if err = writeOfflineSetDerived(ctx, tree, "proxy/"+layout.prefixes[name]+"/@v/list", []byte(list.String()), chunk, published); err != nil {
			return fail(err)
		}
		chosen := m.Entries[layout.latest[name]]
		coordinate := gomodule.Coordinate{Module: chosen.Module, Version: chosen.Version}
		info, err := readExistingSetFile(tree, "proxy/"+coordinate.Prefix()+".info", gomodule.MaxVersionInfo)
		if err != nil {
			return fail(err)
		}
		if err = writeOfflineSetDerived(ctx, tree, "proxy/"+layout.prefixes[name]+"/@latest", info, chunk, published); err != nil {
			return fail(err)
		}
	}
	expected := collectionJSON(receipt)
	if len(expected) > goSetCollectionJSONLimit {
		return fail(errors.New("offline receipt exceeds metadata bound"))
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	if published {
		// Published data is never repaired or rewritten by replay. All members above
		// have been rehashed; original completion bytes must match exactly.
		info, _, err := publicationPair(tree, "receipt.json", offlineSetPending)
		if err != nil || info == nil {
			return fail(errors.New("published offline completion unavailable"))
		}
		saved, err := readCollectionPublication(tree, "receipt.json", info, goSetCollectionJSONLimit)
		if err != nil || !bytes.Equal(saved, expected) {
			return fail(errors.New("published offline receipt differs from this exact selection"))
		}
	}
	if err = publishCollectionJSON(tree, "receipt.json", offlineSetPending, expected, resume, goSetCollectionJSONLimit); err != nil {
		return fail(err)
	}
	if err = validateOfflineSetTree(tree, layout, true); err != nil {
		return fail(err)
	}
	if err = syncOfflineSetTree(ctx, tree, layout); err != nil {
		return fail(err)
	}
	if !published {
		if _, err = output.Lstat("bundle"); !os.IsNotExist(err) {
			return fail(errors.New("final bundle name appeared; existing state preserved"))
		}
		if err = output.Rename("staging", "bundle"); err != nil {
			return fail(err)
		}
	}
	if err = syncCollectionRoot(output); err != nil {
		return fail(err)
	}
	return expected, nil
}
func runGoExportSetOffline(args []string, out io.Writer) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("common offline preparation requires Linux/macOS private-file and directory-sync semantics")
	}
	f := flag.NewFlagSet("go-export-set-offline", flag.ContinueOnError)
	j := checksumJournalArguments(f)
	directory := f.String("collection-directory", "", "complete private common-set collection")
	id := f.String("set-id", "", "exact independently selected original common set")
	destination := f.String("output-directory", "", "new private output, or same immutable output with explicit resume")
	resume := f.Bool("resume", false, "resume only this same immutable unpublished tree, or reverify the original published result")
	chunk := f.Int64("chunk-bytes", 4<<20, "bounded copy/fsync checkpoint,64KiB through8MiB")
	budget := f.Int64("max-bytes", 2<<30, "combined retained original/proof bytes,positive through65GiB")
	timeout := f.Duration("timeout", 5*time.Minute, "copy/inspection deadline,positive through1h; journal verification has a separate deadline")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *directory == "" || len(*directory) > 4096 || *destination == "" || len(*destination) > 4096 || !store.ValidGoExportID(*id) || *chunk < 64<<10 || *chunk > 8<<20 || *budget < 1 || *budget > 65<<30 || *timeout <= 0 || *timeout > time.Hour {
		return errors.New("supply a complete private collection/exact set/new private output, independent journal trust and bounded copy budgets")
	}
	absolute, err := filepath.Abs(*directory)
	if err != nil {
		return err
	}
	if err = capsuleProofPaths(absolute, j); err != nil {
		return err
	}
	source, lock, err := openCollectionDirectoryChecked(absolute, true, commonSourceDirectory)
	if err != nil {
		return err
	}
	defer source.Close()
	defer lock.Close()
	input, err := loadOfflineSetInput(source, j, f, *id)
	if err != nil {
		return err
	}
	defer clear(input.raw)
	defer clear(input.bindingRaw)
	defer clear(input.receiptRaw)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	receipt, err := assembleOfflineSet(ctx, source, input, *destination, *resume, *chunk, *budget)
	if err != nil {
		return err
	}
	n, err := out.Write(receipt)
	if err == nil && n != len(receipt) {
		err = io.ErrShortWrite
	}
	return err
}
