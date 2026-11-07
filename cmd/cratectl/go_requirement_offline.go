// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

const goRequirementOfflineProfile = "cratectl.go.hosted.requirement-offline.v1"

type goRequirementOfflineEvidence struct {
	SelectionManifest       blob.Object `json:"selection_manifest"`
	MainGoMod               blob.Object `json:"main_go_mod"`
	RequirementProof        blob.Object `json:"requirement_proof"`
	ExaminedSources         int         `json:"examined_sources"`
	OriginalInputsComplete  bool        `json:"original_inputs_complete"`
	RequirementsReplayed    bool        `json:"requirements_replayed"`
	MetadataInputsAvailable bool        `json:"metadata_inputs_available"`
}

type requirementOfflineInput struct {
	raw    []byte
	parent store.GoRequirementExportManifest
}

func addRequirementMetadataPaths(layout *offlineSetLayout, parent store.GoRequirementExportManifest) error {
	for _, source := range parent.Sources {
		c, err := gomodule.Canonical(source.Module, source.Version)
		if err != nil {
			return err
		}
		name := "proxy/" + c.Prefix() + ".mod"
		if len(name) > 2048 || filepath.Clean(name) != name {
			return errors.New("requirement metadata native path exceeds its bound")
		}
		if directory, exists := layout.paths[name]; exists && directory {
			return errors.New("requirement metadata path collides with a directory")
		}
		layout.paths[name] = false
		for path := filepath.Dir(name); path != "."; path = filepath.Dir(path) {
			if directory, exists := layout.paths[path]; exists && !directory {
				return errors.New("requirement metadata directory collides with a file")
			}
			layout.paths[path] = true
		}
		if len(layout.paths) > maxSetOfflinePaths {
			return errors.New("requirement native metadata path budget exceeded")
		}
	}
	return nil
}

// Files are accepted only after the caller independently selects key/head/event.
// Reverify the retained whole chain and exact production creation here, too.
func loadRequirementInput(ctx context.Context, root *os.Root, attribution checksumJournalAttribution, id string, journalLimit, budget int64) (offlineSetInput, error) {
	var empty offlineSetInput
	if !store.ValidGoExportID(id) || journalLimit < 1 || journalLimit > crypt.MaxJournalInputBytes || budget < 1 || budget > 65<<30 {
		return empty, errors.New("invalid bounded requirement verification inputs")
	}
	proofBytes := map[string][]byte{}
	for _, item := range []struct {
		name    string
		maximum int64
	}{{"manifest.json", store.MaxGoRequirementExportManifest}, {"checkpoint.json", crypt.MaxJournalCheckpointStatement}, {"checkpoint.sig", crypt.JournalCheckpointSignatureBytes}, {"signer-public.pem", crypt.MaxJournalCheckpointPublicKey}} {
		raw, err := readExistingSetFile(root, item.name, item.maximum)
		if err != nil {
			return empty, err
		}
		proofBytes[item.name] = raw
	}
	head := crypt.JournalAnchor{Tenant: attribution.Journal.Tenant, Sequence: attribution.Journal.HeadSequence, Hash: attribution.Journal.HeadHash}
	verifiedSignature, err := crypt.VerifyJournalCheckpoint(proofBytes["checkpoint.json"], proofBytes["checkpoint.sig"], proofBytes["signer-public.pem"], head)
	if err != nil || verifiedSignature != attribution.CheckpointSignature {
		return empty, errors.New("retained key/proof differs from independently selected requirement trust")
	}
	journal, err := openExistingSetFile(root, "journal.jsonl")
	if err != nil {
		return empty, err
	}
	defer journal.Close()
	js, err := journal.Stat()
	if err != nil || js.Size() < 1 || js.Size() > journalLimit {
		return empty, errors.New("retained requirement journal exceeds its bound")
	}
	start := crypt.JournalAnchor{Tenant: attribution.Journal.Tenant, Sequence: attribution.Journal.StartSequence, Hash: attribution.Journal.StartHash}
	verifiedJournal, event, err := crypt.VerifyJournalExportEvent(ctx, journal, start, head, journalLimit, attribution.EventSequence)
	if err != nil || verifiedJournal != attribution.Journal || event.Hash != attribution.EventHash {
		return empty, errors.New("complete retained requirement journal/event changed")
	}
	raw := proofBytes["manifest.json"]
	parent, err := store.BindGoRequirementExportManifest(raw, attribution.Journal.Tenant, id, event)
	if err != nil {
		return empty, errors.New("requirement parent is not bound to the original signed production creation")
	}
	bindingRaw, err := readExistingSetFile(root, "bindings.json", goSetCollectionJSONLimit)
	if err != nil {
		return empty, err
	}
	stored, err := parseRequirementBinding(bindingRaw)
	if err != nil {
		return empty, err
	}
	proofMembers := []collectionMember{}
	for _, name := range []string{"checkpoint.json", "checkpoint.sig", "signer-public.pem"} {
		proofMembers = append(proofMembers, collectionMember{name, offlineObject(proofBytes[name])})
	}
	proofMembers = append(proofMembers, collectionMember{"journal.jsonl", blob.Object{Digest: attribution.Journal.ExportSHA256, Size: js.Size()}})
	members, err := requirementMembers(raw, parent, proofMembers)
	if err != nil {
		return empty, err
	}
	expected := goSetCollectionBinding{Profile: goRequirementCollectionProfile, Authority: stored.Authority, SetID: id, Journal: attribution, Members: members}
	if !reflect.DeepEqual(expected, stored) {
		return empty, errors.New("requirement collection member map differs from signed originals")
	}
	receiptRaw, err := readExistingSetFile(root, "receipt.json", goSetCollectionJSONLimit)
	if err != nil {
		return empty, err
	}
	receipt, err := parseRequirementReceipt(receiptRaw, expected)
	if err != nil {
		return empty, err
	}
	if err := validateRequirementEntries(root, expected, true); err != nil {
		return empty, err
	}
	total := int64(len(bindingRaw) + len(receiptRaw))
	if total > budget {
		return empty, errors.New("requirement metadata exceeds max-bytes before output")
	}
	for _, member := range members {
		if member.Object.Size < 0 || member.Object.Size > budget-total {
			return empty, errors.New("requirement originals exceed max-bytes before output")
		}
		total += member.Object.Size
	}
	for _, member := range members {
		file, err := openExistingSetFile(root, member.Name)
		if err != nil {
			return empty, err
		}
		err = hashExistingSetFile(ctx, file, member.Object)
		file.Close()
		if err != nil {
			return empty, err
		}
	}
	if err := verifyRequirementOriginals(ctx, root, parent); err != nil {
		return empty, err
	}
	if err := inspectSetCollection(ctx, root, parent.Selection); err != nil {
		return empty, err
	}
	selection, err := parent.Selection.Bytes()
	if err != nil {
		return empty, err
	}
	return offlineSetInput{manifest: parent.Selection, raw: selection, attribution: attribution, binding: expected, receipt: goSetCollectionReceipt{Binding: expected, CollectedGeneration: receipt.CollectedGeneration, BytesVerified: true}, bindingRaw: bindingRaw, receiptRaw: receiptRaw, requirement: &requirementOfflineInput{raw: bytes.Clone(raw), parent: parent}}, nil
}

func requirementSourceDirectory(root *os.Root) error {
	entries, err := readCollectionEntries(root, maxRequirementCollectionEntries)
	if err != nil {
		return err
	}
	known := map[string]bool{"bindings.json": true, "receipt.json": true, "manifest.json": true, "checkpoint.json": true, "checkpoint.sig": true, "signer-public.pem": true, "journal.jsonl": true, "main.mod": true, "requirements.json": true, "selection.json": true}
	for n := range store.MaxGoExportSetEntries {
		for _, kind := range []string{"zip", "mod", "info"} {
			known[setCollectionName(n, kind)] = true
		}
	}
	for n := 0; n < (maxRequirementCollectionMembers-8-3*store.MaxGoExportSetEntries)/2; n++ {
		known[requirementInputName(n, "manifest.json")] = true
		known[requirementInputName(n, "mod")] = true
	}
	for _, entry := range entries {
		if !known[entry.Name()] {
			return errors.New("requirement collection has pending/unknown members; finish explicit collection recovery")
		}
		info, err := entry.Info()
		if err != nil || !privateCollectionFile(info, false) {
			return errors.New("requirement originals must be private unshared regular files")
		}
	}
	return nil
}

func runGoRequirementOffline(args []string, out io.Writer, verifyOnly bool) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("requirement offline verification needs Linux/macOS private-file locking/sync semantics")
	}
	name := "go-requirement-export-offline"
	if verifyOnly {
		name = "go-requirement-export-verify"
	}
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	j := checksumJournalArguments(f)
	directory := f.String("collection-directory", "", "complete private requirement collection")
	id := f.String("set-id", "", "independently selected exact original requirement set")
	destination := f.String("output-directory", "", "new private output or explicit same-input resume")
	resume := f.Bool("resume", false, "resume only identical immutable unpublished or published output")
	chunk := f.Int64("chunk-bytes", 4<<20, "copy/sync checkpoint,64KiB through8MiB")
	budget := f.Int64("max-bytes", 2<<30, "combined original/proof bound,positive through65GiB")
	timeout := f.Duration("timeout", 5*time.Minute, "verification/copy deadline,positive through1h")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *directory == "" || len(*directory) > 4096 || !store.ValidGoExportID(*id) || !verifyOnly && (*destination == "" || len(*destination) > 4096) || verifyOnly && (*destination != "" || *resume) || *chunk < 64<<10 || *chunk > 8<<20 || *budget < 1 || *budget > 65<<30 || *timeout <= 0 || *timeout > time.Hour {
		return errors.New("supply complete private requirement collection/exact set/independent journal trust and bounded output")
	}
	absolute, err := filepath.Abs(*directory)
	if err != nil {
		return err
	}
	if err := capsuleProofPaths(absolute, j); err != nil {
		return err
	}
	source, lock, err := openCollectionDirectoryChecked(absolute, true, requirementSourceDirectory)
	if err != nil {
		return err
	}
	defer source.Close()
	defer lock.Close()
	attribution, _, err := j.selectEvent(f)
	if err != nil {
		return err
	}
	if attribution == nil {
		return errors.New("complete independently selected journal signature required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	input, err := loadRequirementInput(ctx, source, *attribution, *id, *j.maxBytes, *budget)
	if err != nil {
		return err
	}
	defer clear(input.raw)
	defer clear(input.requirement.raw)
	if verifyOnly {
		return json.NewEncoder(out).Encode(struct {
			Profile                string                     `json:"profile"`
			SetID                  string                     `json:"set_id"`
			Manifest               blob.Object                `json:"manifest"`
			ExaminedSources        int                        `json:"examined_sources"`
			SelectedRoots          int                        `json:"selected_roots"`
			Attribution            checksumJournalAttribution `json:"attribution"`
			BytesVerified          bool                       `json:"bytes_verified"`
			OriginalInputsComplete bool                       `json:"original_inputs_complete"`
			RequirementsReplayed   bool                       `json:"requirements_replayed"`
			Closure                bool                       `json:"dependency_closure"`
			Authority              bool                       `json:"checksum_authority_verified"`
			Admission              bool                       `json:"current_registry_admission"`
		}{"cratectl.go.requirement-verification.v1", *id, offlineObject(input.requirement.raw), len(input.requirement.parent.Sources), len(input.manifest.Entries), input.attribution, true, true, true, false, false, false})
	}
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

// New paths are flat generated names; no caller-controlled path is projected.
func requirementMemberName(name string) bool {
	return name != "" && len(name) <= 64 && !strings.ContainsAny(name, "/\\") && name != "." && name != ".."
}
