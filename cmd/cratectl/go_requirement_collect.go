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
	"runtime"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func (c *collectionHTTP) checkRequirementCurrent(ctx context.Context, m store.GoRequirementExportManifest, object blob.Object, event int64) error {
	r, err := c.get(ctx, "", "GET", -1, 0)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	if err != nil || r.StatusCode != 200 || len(raw) > 8192 {
		return errors.New("current requirement session unavailable")
	}
	selection, err := m.Selection.Bytes()
	if err != nil {
		return err
	}
	var s store.GoRequirementExportSession
	if json.Unmarshal(raw, &s) != nil || !bytes.Equal(raw, collectionJSON(s)) || s.Profile != store.GoRequirementExportProfile || s.ID != c.id || s.Generation != c.generation || s.Manifest != object || s.SelectionManifest != offlineObject(selection) || s.MainGoMod != m.MainGoMod || s.RequirementProof != m.RequirementProof || s.SourceCount != len(m.Sources) || s.CreatedSequence != event || s.RootCount != len(m.Selection.Entries) || s.ArtifactBytes != m.Selection.DeclaredArtifactBytes || (s.State != "open" && s.State != "acknowledged") || s.ServerTime.IsZero() || !s.ExpiresAt.After(s.ServerTime) {
		return errors.New("requirement session/generation changed; inspect current state before resuming")
	}
	return nil
}

func runGoRequirementCollect(args []string, out io.Writer) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("requirement collection needs Linux/macOS private-file locking and sync semantics")
	}
	f := flag.NewFlagSet("go-requirement-export-collect", flag.ContinueOnError)
	j := checksumJournalArguments(f)
	config := f.String("config", "", "private current source client configuration")
	id := f.String("set-id", "", "exact independently selected original requirement set")
	generation := f.Int64("generation", 0, "explicit current serving generation")
	destination := f.String("output-directory", "", "private flat original/proof collection")
	resume := f.Bool("resume", false, "resume only this immutable requirement binding")
	chunk := f.Int64("chunk-bytes", 4<<20, "range/sync checkpoint,64KiB through8MiB")
	budget := f.Int64("max-bytes", 2<<30, "combined original/proof budget,positive through65GiB")
	timeout := f.Duration("timeout", 5*time.Minute, "whole transfer deadline,positive through1h")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *config == "" || !store.ValidGoExportID(*id) || *generation < 1 || *destination == "" || len(*destination) > 4096 || *j.file == "" || *chunk < 64<<10 || *chunk > 8<<20 || *budget < 1 || *budget > 65<<30 || *timeout <= 0 || *timeout > time.Hour {
		return errors.New("supply current config/exact requirement set/generation, complete independent signed journal and bounded private output")
	}
	attribution, event, err := j.selectEvent(f)
	if err != nil {
		return err
	}
	if attribution == nil {
		return errors.New("complete independent signed journal required")
	}
	client, base, token, closeClient, err := collectionClient(*config)
	if err != nil {
		return err
	}
	defer closeClient()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	transport := &collectionHTTP{client: client, base: base, token: token, id: *id, generation: *generation, chunk: *chunk, requirementSet: true}
	response, err := transport.get(ctx, "manifest", "GET", -1, 0)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, store.MaxGoRequirementExportManifest+1))
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || len(raw) > store.MaxGoRequirementExportManifest {
		return errors.New("cannot collect bounded original requirement parent under current authority")
	}
	parent, err := store.BindGoRequirementExportManifest(raw, *j.tenant, *id, event)
	if err != nil {
		return errors.New("requirement parent is not bound to its exact original signed creation")
	}
	object := offlineObject(raw)
	if !collectionHeaders(response, object, *generation) {
		return errors.New("requirement parent serving identity changed")
	}
	if err = transport.checkRequirementCurrent(ctx, parent, object, event.Sequence); err != nil {
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
		return errors.New("requirement checkpoint/key/signature changed")
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
	local := []struct {
		name string
		raw  []byte
	}{{"manifest.json", raw}, {"checkpoint.json", statement}, {"checkpoint.sig", signature}, {"signer-public.pem", key}}
	proofMembers := []collectionMember{{"checkpoint.json", offlineObject(statement)}, {"checkpoint.sig", offlineObject(signature)}, {"signer-public.pem", offlineObject(key)}, {"journal.jsonl", blob.Object{Digest: attribution.Journal.ExportSHA256, Size: js.Size()}}}
	members, err := requirementMembers(raw, parent, proofMembers)
	if err != nil {
		return err
	}
	binding := goSetCollectionBinding{Profile: goRequirementCollectionProfile, Authority: base, SetID: *id, Journal: *attribution, Members: members}
	var total int64
	for _, member := range members {
		if member.Object.Size < 0 || member.Object.Size > *budget-total {
			return errors.New("complete requirement collection exceeds max-bytes before output")
		}
		total += member.Object.Size
	}
	bindingRaw := collectionJSON(binding)
	completionRaw := collectionJSON(goRequirementCollectionReceipt{Binding: binding, CollectedGeneration: *generation, BytesVerified: true, OriginalInputsComplete: true, RequirementsReplayed: true})
	for _, metadata := range [][]byte{bindingRaw, completionRaw} {
		if int64(len(metadata)) > *budget-total {
			return errors.New("complete requirement metadata exceeds max-bytes before output")
		}
		total += int64(len(metadata))
	}
	if _, err := parseRequirementBinding(bindingRaw); err != nil {
		return err
	}
	root, dir, err := openCollectionDirectoryChecked(*destination, *resume, func(root *os.Root) error { return validateRequirementEntries(root, binding, false) })
	if err != nil {
		return err
	}
	defer root.Close()
	defer dir.Close()
	if err := bindRequirementCollection(root, binding, *resume); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	copyLocal := func(name string, source io.ReaderAt, object blob.Object) error {
		if err := verifyOfflineSetPrefix(ctx, root, name, source, object.Size); err != nil {
			return err
		}
		return copyCollectionLocal(ctx, root, name, source, object, *chunk)
	}
	for _, item := range local {
		if err := copyLocal(item.name, bytes.NewReader(item.raw), offlineObject(item.raw)); err != nil {
			return collectionFailure(err)
		}
	}
	if err := copyLocal("journal.jsonl", journal, proofMembers[3].Object); err != nil {
		return collectionFailure(err)
	}
	selection, err := parent.Selection.Bytes()
	if err != nil {
		return collectionFailure(err)
	}
	if err := copyLocal("selection.json", bytes.NewReader(selection), offlineObject(selection)); err != nil {
		return collectionFailure(err)
	}
	for _, item := range []struct {
		name, kind string
		object     blob.Object
	}{{"main.mod", "main", parent.MainGoMod}, {"requirements.json", "proof", parent.RequirementProof}} {
		if err := transport.download(ctx, root, item.name, item.kind, item.object); err != nil {
			return collectionFailure(err)
		}
	}
	for n, source := range parent.Sources {
		for _, item := range []struct {
			name, kind string
			object     blob.Object
		}{{requirementInputName(n, "manifest.json"), fmt.Sprintf("inputs/%d/manifest", n), source.Manifest}, {requirementInputName(n, "mod"), fmt.Sprintf("inputs/%d/mod", n), source.Mod}} {
			if err := transport.download(ctx, root, item.name, item.kind, item.object); err != nil {
				return collectionFailure(err)
			}
		}
	}
	if err := verifyRequirementOriginals(ctx, root, parent); err != nil {
		return collectionFailure(err)
	}
	for n, entry := range parent.Selection.Entries {
		for k, kind := range []string{"zip", "mod", "info"} {
			a := entry.Artifacts[k]
			if err := transport.download(ctx, root, setCollectionName(n, kind), fmt.Sprintf("roots/%d/%s", n, kind), blob.Object{Digest: a.Digest, Size: a.Size}); err != nil {
				return collectionFailure(err)
			}
		}
	}
	if err := inspectSetCollection(ctx, root, parent.Selection); err != nil {
		return collectionFailure(err)
	}
	current, err := transport.get(ctx, "manifest", "HEAD", -1, 0)
	if err != nil {
		return collectionFailure(err)
	}
	current.Body.Close()
	if current.StatusCode != 200 || !collectionHeaders(current, object, *generation) || current.ContentLength != object.Size {
		return collectionFailure(errors.New("complete requirement authority changed before completion"))
	}
	if err := transport.checkRequirementCurrent(ctx, parent, object, event.Sequence); err != nil {
		return collectionFailure(err)
	}
	if err := dir.Sync(); err != nil {
		return collectionFailure(err)
	}
	if err := ctx.Err(); err != nil {
		return collectionFailure(err)
	}
	receipt, err := publishRequirementReceipt(root, binding, *generation, *resume)
	if err != nil {
		return collectionFailure(err)
	}
	n, err := out.Write(receipt)
	if err == nil && n != len(receipt) {
		err = io.ErrShortWrite
	}
	return err
}
