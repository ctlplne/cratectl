// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/ziparchive"
)

const goSetCollectionProfile = "cratectl.go.hosted.set-collection.v1"
const goSetCollectionJSONLimit = 512 << 10
const goSetCollectionEntries = 780

type goSetCollectionBinding struct {
	Profile   string                     `json:"profile"`
	Authority string                     `json:"authority"`
	SetID     string                     `json:"set_id"`
	Journal   checksumJournalAttribution `json:"journal"`
	Members   []collectionMember         `json:"members"`
}
type goSetCollectionReceipt struct {
	Binding                  goSetCollectionBinding `json:"binding"`
	CollectedGeneration      int64                  `json:"collected_generation"`
	BytesVerified            bool                   `json:"bytes_verified"`
	CurrentRegistryAdmission bool                   `json:"current_registry_admission"`
	ChecksumAuthority        bool                   `json:"checksum_authority_verified"`
	DependencyClosure        bool                   `json:"dependency_closure"`
	DeliveryVerified         bool                   `json:"delivery_verified"`
}

func setCollectionName(root int, kind string) string { return fmt.Sprintf("root.%03d.%s", root, kind) }
func validateSetCollectionEntries(root *os.Root, b goSetCollectionBinding) error {
	entries, err := collectionEntries(root, goSetCollectionEntries)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"bindings.json": true, "receipt.json": true, collectionBindingPending: true}
	for _, m := range b.Members {
		allowed[m.Name] = true
	}
	pending := 0
	for _, entry := range entries {
		if allowed[entry.Name()] {
			continue
		}
		if _, ok := receiptPendingGeneration(entry.Name()); !ok {
			return errors.New("common collection contains an unexpected member; preserve it and choose another directory")
		}
		pending++
	}
	if pending > 1 {
		return errors.New("common collection has multiple pending receipts")
	}
	return nil
}
func bindSetCollection(root *os.Root, b goSetCollectionBinding, resume bool) error {
	if _, err := root.Lstat("bindings.json"); os.IsNotExist(err) {
		entries, err := collectionEntries(root, goSetCollectionEntries)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Name() != collectionBindingPending {
				return errors.New("common payload/proof has no complete immutable binding")
			}
		}
	} else if err != nil {
		return err
	}
	return publishCollectionJSON(root, "bindings.json", collectionBindingPending, collectionJSON(b), resume, goSetCollectionJSONLimit)
}
func publishSetCollectionReceipt(root *os.Root, b goSetCollectionBinding, current int64, resume bool) ([]byte, error) {
	if err := validateSetCollectionEntries(root, b); err != nil {
		return nil, err
	}
	entries, err := collectionEntries(root, goSetCollectionEntries)
	if err != nil {
		return nil, err
	}
	pending := ""
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
			return nil, errors.New("completed common receipt requires explicit resume")
		}
		raw, err := readCollectionPublication(root, "receipt.json", complete, goSetCollectionJSONLimit)
		if err != nil {
			return nil, err
		}
		var original goSetCollectionReceipt
		if json.Unmarshal(raw, &original) != nil || !bytes.Equal(raw, collectionJSON(original)) || !reflect.DeepEqual(original.Binding, b) || !original.BytesVerified || original.CollectedGeneration < 1 || original.CollectedGeneration > current || original.CurrentRegistryAdmission || original.ChecksumAuthority || original.DependencyClosure || original.DeliveryVerified {
			return nil, errors.New("saved receipt differs from this complete common collection")
		}
		if pending != "" && generation != original.CollectedGeneration {
			return nil, errors.New("common pending/completed receipt generations differ")
		}
		generation = original.CollectedGeneration
		expected = raw
	} else {
		if pending != "" && (!resume || generation > current) {
			return nil, errors.New("common pending completion requires explicit nonfuture resume")
		}
		if pending == "" {
			generation = current
		}
		expected = collectionJSON(goSetCollectionReceipt{Binding: b, CollectedGeneration: generation, BytesVerified: true})
	}
	if generation < 1 {
		return nil, errors.New("invalid common completion generation")
	}
	if pending == "" {
		pending = fmt.Sprintf("receipt.%d.pending", generation)
	}
	if err := publishCollectionJSON(root, "receipt.json", pending, expected, resume, goSetCollectionJSONLimit); err != nil {
		return nil, err
	}
	return expected, nil
}
func (c *collectionHTTP) checkSetCurrent(ctx context.Context, m store.GoExportSetManifest, o blob.Object, event int64) error {
	r, err := c.get(ctx, "", "GET", -1, 0)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	if err != nil || r.StatusCode != 200 || len(raw) > 8192 {
		return errors.New("current common-set metadata unavailable")
	}
	var s store.GoExportSetSession
	if json.Unmarshal(raw, &s) != nil || !bytes.Equal(raw, collectionJSON(s)) || s.ID != c.id || s.Generation != c.generation || s.Manifest != o || s.CreatedSequence != event || s.RootCount != len(m.Entries) || s.ArtifactBytes != m.DeclaredArtifactBytes || (s.State != "open" && s.State != "acknowledged") || s.ServerTime.IsZero() || !s.ExpiresAt.After(s.ServerTime) {
		return errors.New("common set or generation changed; inspect current state before resuming")
	}
	return nil
}
func inspectSetCollection(ctx context.Context, root *os.Root, m store.GoExportSetManifest) error {
	for n, entry := range m.Entries {
		files := [3]*os.File{}
		err := func() error {
			defer func() {
				for _, file := range files {
					if file != nil {
						file.Close()
					}
				}
			}()
			for k, kind := range []string{"zip", "mod", "info"} {
				f, err := openCollectionMember(root, setCollectionName(n, kind))
				if err != nil {
					return err
				}
				files[k] = f
				if err = verifyCollectionFile(ctx, f, blob.Object{Digest: entry.Artifacts[k].Digest, Size: entry.Artifacts[k].Size}); err != nil {
					return err
				}
				if _, err = f.Seek(0, io.SeekStart); err != nil {
					return err
				}
			}
			mod, err := io.ReadAll(io.LimitReader(files[1], gomodule.MaxGoMod+1))
			if err != nil {
				return err
			}
			info, err := io.ReadAll(io.LimitReader(files[2], gomodule.MaxVersionInfo+1))
			if err != nil {
				return err
			}
			_, err = gomodule.InspectRepresentations(ctx, files[0], entry.Artifacts[0].Size, gomodule.Coordinate{Module: entry.Module, Version: entry.Version}, mod, info, ziparchive.Limits{CompressedBytes: 512 << 20, ExpandedBytes: 512 << 20, DirectoryBytes: 16 << 20, Files: 16384})
			if err != nil {
				return errors.New("common member fails bounded native representation consistency")
			}
			for k, file := range files {
				if err = verifyCollectionFile(ctx, file, blob.Object{Digest: entry.Artifacts[k].Digest, Size: entry.Artifacts[k].Size}); err != nil {
					return err
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
func runGoExportSetCollect(args []string, out io.Writer) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("common collection requires Linux/macOS private-file locking and sync semantics; Windows remains unsupported")
	}
	f := flag.NewFlagSet("go-export-set-collect", flag.ContinueOnError)
	j := checksumJournalArguments(f)
	config := f.String("config", "", "private current source client configuration")
	id := f.String("set-id", "", "exact original common-set identity")
	generation := f.Int64("generation", 0, "explicit current common serving generation")
	destination := f.String("output-directory", "", "private flat collection directory")
	resume := f.Bool("resume", false, "explicitly resume this same immutable common binding")
	chunk := f.Int64("chunk-bytes", 4<<20, "range and sync checkpoint,64KiB through8MiB")
	budget := f.Int64("max-bytes", 2<<30, "combined package/proof byte budget, positive through65GiB")
	timeout := f.Duration("timeout", 5*time.Minute, "whole collection deadline, positive through1h")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *config == "" || !store.ValidGoExportID(*id) || *generation < 1 || *destination == "" || *j.file == "" || *chunk < 64<<10 || *chunk > 8<<20 || *budget < 1 || *budget > 65<<30 || *timeout <= 0 || *timeout > time.Hour {
		return errors.New("supply current config/exact set/generation, complete signed journal, private output and bounded transfer budgets")
	}
	attribution, event, err := j.selectEvent(f)
	if err != nil {
		return err
	}
	if attribution == nil {
		return errors.New("independent complete signed journal attribution required")
	}
	client, base, token, closeClient, err := collectionClient(*config)
	if err != nil {
		return err
	}
	defer closeClient()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	transport := &collectionHTTP{client: client, base: base, token: token, id: *id, generation: *generation, chunk: *chunk, commonSet: true}
	response, err := transport.get(ctx, "manifest", "GET", -1, 0)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, store.MaxGoExportSetManifest+1))
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || len(raw) > store.MaxGoExportSetManifest {
		return errors.New("cannot collect bounded original common manifest under current authority")
	}
	manifest, err := store.BindGoExportSetManifest(raw, *j.tenant, *id, event)
	if err != nil {
		return errors.New("common manifest is not bound to its exact original signed creation")
	}
	mo := blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}
	if !collectionHeaders(response, mo, *generation) {
		return errors.New("common manifest serving identity changed")
	}
	if err = transport.checkSetCurrent(ctx, manifest, mo, event.Sequence); err != nil {
		return err
	}
	statement, err := configfile.ReadBytes(*j.checkpoint.statement, crypt.MaxJournalCheckpointStatement, true)
	if err != nil {
		return err
	}
	signature, err := configfile.ReadBytes(*j.checkpoint.signature, crypt.JournalCheckpointSignatureBytes, false)
	if err != nil {
		return err
	}
	key, err := configfile.ReadBytes(*j.checkpoint.key, crypt.MaxJournalCheckpointPublicKey, false)
	if err != nil {
		return err
	}
	head := crypt.JournalAnchor{Tenant: attribution.Journal.Tenant, Sequence: attribution.Journal.HeadSequence, Hash: attribution.Journal.HeadHash}
	proof, err := crypt.VerifyJournalCheckpoint(statement, signature, key, head)
	if err != nil || proof != attribution.CheckpointSignature {
		return errors.New("common checkpoint/signature/independent key changed")
	}
	journal, err := configfile.OpenBounded(*j.file, *j.maxBytes, true)
	if err != nil {
		return err
	}
	defer journal.Close()
	js, err := journal.Stat()
	if err != nil {
		return err
	}
	binding := goSetCollectionBinding{Profile: goSetCollectionProfile, Authority: base, SetID: *id, Journal: *attribution}
	sources := []io.ReaderAt{}
	for _, entry := range []struct {
		name string
		raw  []byte
	}{{"manifest.json", raw}, {"checkpoint.json", statement}, {"checkpoint.sig", signature}, {"signer-public.pem", key}} {
		binding.Members = append(binding.Members, collectionMember{entry.name, blob.Object{Digest: crypt.Digest(entry.raw), Size: int64(len(entry.raw))}})
		sources = append(sources, bytes.NewReader(entry.raw))
	}
	binding.Members = append(binding.Members, collectionMember{"journal.jsonl", blob.Object{Digest: attribution.Journal.ExportSHA256, Size: js.Size()}})
	sources = append(sources, journal)
	for n, entry := range manifest.Entries {
		for k, kind := range []string{"zip", "mod", "info"} {
			a := entry.Artifacts[k]
			binding.Members = append(binding.Members, collectionMember{setCollectionName(n, kind), blob.Object{Digest: a.Digest, Size: a.Size}})
		}
	}
	var total int64
	for _, member := range binding.Members {
		if member.Object.Size < 0 || member.Object.Size > *budget-total {
			return errors.New("complete common collection exceeds max-bytes before any output")
		}
		total += member.Object.Size
	}
	if len(collectionJSON(binding)) > goSetCollectionJSONLimit {
		return errors.New("common collection binding exceeds512KiB")
	}
	root, dir, err := openCollectionDirectoryChecked(*destination, *resume, func(root *os.Root) error { return validateSetCollectionEntries(root, binding) })
	if err != nil {
		return err
	}
	defer root.Close()
	defer dir.Close()
	if err = bindSetCollection(root, binding, *resume); err != nil {
		return err
	}
	if err = dir.Sync(); err != nil {
		return err
	}
	for n, source := range sources {
		member := binding.Members[n]
		if err = copyCollectionLocal(ctx, root, member.Name, source, member.Object, *chunk); err != nil {
			return collectionFailure(err)
		}
	}
	for n := range manifest.Entries {
		for k, kind := range []string{"zip", "mod", "info"} {
			member := binding.Members[5+n*3+k]
			if err = transport.download(ctx, root, member.Name, fmt.Sprintf("roots/%d/%s", n, kind), member.Object); err != nil {
				return collectionFailure(err)
			}
		}
	}
	if err = inspectSetCollection(ctx, root, manifest); err != nil {
		return collectionFailure(err)
	}
	// One current whole-set manifest check covers every policy/epoch/identity.
	// Repeating a whole-set check for all768objects would be quadratic SQL work.
	current, err := transport.get(ctx, "manifest", "HEAD", -1, 0)
	if err != nil {
		return collectionFailure(err)
	}
	current.Body.Close()
	if current.StatusCode != 200 || !collectionHeaders(current, mo, *generation) || current.ContentLength != mo.Size {
		return collectionFailure(errors.New("complete-set authority changed before completion"))
	}
	if err = transport.checkSetCurrent(ctx, manifest, mo, event.Sequence); err != nil {
		return collectionFailure(err)
	}
	if err = dir.Sync(); err != nil {
		return collectionFailure(err)
	}
	if err = ctx.Err(); err != nil {
		return collectionFailure(err)
	}
	receipt, err := publishSetCollectionReceipt(root, binding, *generation, *resume)
	if err != nil {
		return collectionFailure(err)
	}
	n, err := out.Write(receipt)
	if err == nil && n != len(receipt) {
		err = io.ErrShortWrite
	}
	return err
}
