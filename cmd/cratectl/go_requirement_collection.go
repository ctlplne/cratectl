// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

const goRequirementCollectionProfile = "cratectl.go.hosted.requirement-collection.v1"
const maxRequirementCollectionMembers = 8 + 2*gomodule.MaxRequirementProofSources + 3*store.MaxGoExportSetEntries
const maxRequirementCollectionEntries = maxRequirementCollectionMembers + 4

type goRequirementCollectionReceipt struct {
	Binding                  goSetCollectionBinding `json:"binding"`
	CollectedGeneration      int64                  `json:"collected_generation"`
	BytesVerified            bool                   `json:"bytes_verified"`
	OriginalInputsComplete   bool                   `json:"original_inputs_complete"`
	RequirementsReplayed     bool                   `json:"requirements_replayed"`
	CurrentRegistryAdmission bool                   `json:"current_registry_admission"`
	ChecksumAuthority        bool                   `json:"checksum_authority_verified"`
	DependencyClosure        bool                   `json:"dependency_closure"`
	DeliveryVerified         bool                   `json:"delivery_verified"`
}

func requirementInputName(n int, kind string) string { return fmt.Sprintf("input.%04d.%s", n, kind) }

// Bound members before typed JSON allocation. Canonical re-encoding below also
// rejects aliases, duplicate/extra fields and alternate scalar representations.
func preflightRequirementJSON(raw []byte, receipt bool) error {
	if len(raw) < 1 || len(raw) > goSetCollectionJSONLimit {
		return errors.New("requirement collection metadata exceeds its bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return errors.New("requirement collection metadata must be an object")
	}
	fields := []string{"profile", "authority", "set_id", "journal", "members"}
	if receipt {
		fields = []string{"binding", "collected_generation", "bytes_verified", "original_inputs_complete", "requirements_replayed", "current_registry_admission", "checksum_authority_verified", "dependency_closure", "delivery_verified"}
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		allowed := false
		for _, field := range fields {
			allowed = allowed || name == field
		}
		if err != nil || !ok || !allowed || seen[name] {
			return errors.New("unknown or duplicate requirement collection field")
		}
		seen[name] = true
		if name == "members" && !receipt {
			if token, err := d.Token(); err != nil || token != json.Delim('[') {
				return errors.New("requirement members must be a bounded array")
			}
			count := 0
			for d.More() {
				if count >= maxRequirementCollectionMembers {
					return errors.New("requirement collection member count exceeded")
				}
				var member json.RawMessage
				if d.Decode(&member) != nil || len(member) > 512 {
					return errors.New("requirement member descriptor exceeds its bound")
				}
				count++
			}
			if token, err := d.Token(); err != nil || token != json.Delim(']') {
				return errors.New("invalid requirement member array")
			}
		} else {
			var value json.RawMessage
			if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return errors.New("invalid requirement collection value")
			}
			if receipt && name == "binding" {
				if err := preflightRequirementJSON(value, false); err != nil {
					return err
				}
			}
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || len(seen) != len(fields) {
		return errors.New("incomplete requirement collection metadata")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing requirement collection metadata")
	}
	return nil
}

func parseRequirementBinding(raw []byte) (goSetCollectionBinding, error) {
	var b goSetCollectionBinding
	if err := preflightRequirementJSON(raw, false); err != nil {
		return b, err
	}
	if json.Unmarshal(raw, &b) != nil || !bytes.Equal(raw, collectionJSON(b)) || b.Profile != goRequirementCollectionProfile || !store.ValidGoExportID(b.SetID) || !collectionAuthority(b.Authority) || len(b.Members) < 13 || len(b.Members) > maxRequirementCollectionMembers {
		return goSetCollectionBinding{}, errors.New("invalid canonical requirement collection binding")
	}
	seen := map[string]bool{}
	for _, member := range b.Members {
		if !requirementMemberName(member.Name) || member.Name == "bindings.json" || member.Name == "receipt.json" || member.Name == collectionBindingPending || seen[member.Name] || !store.ValidGoExportID(member.Object.Digest) || member.Object.Size < 1 || member.Object.Size > 65<<30 {
			return goSetCollectionBinding{}, errors.New("invalid or duplicate flat requirement member identity")
		}
		seen[member.Name] = true
	}
	return b, nil
}

func parseRequirementReceipt(raw []byte, binding goSetCollectionBinding) (goRequirementCollectionReceipt, error) {
	var r goRequirementCollectionReceipt
	if err := preflightRequirementJSON(raw, true); err != nil {
		return r, err
	}
	if json.Unmarshal(raw, &r) != nil || !bytes.Equal(raw, collectionJSON(r)) || !reflect.DeepEqual(r.Binding, binding) || r.CollectedGeneration < 1 || !r.BytesVerified || !r.OriginalInputsComplete || !r.RequirementsReplayed || r.CurrentRegistryAdmission || r.ChecksumAuthority || r.DependencyClosure || r.DeliveryVerified {
		return goRequirementCollectionReceipt{}, errors.New("requirement collection lacks its complete original receipt")
	}
	return r, nil
}

func requirementMembers(raw []byte, m store.GoRequirementExportManifest, proof []collectionMember) ([]collectionMember, error) {
	if len(proof) != 4 || proof[0].Name != "checkpoint.json" || proof[1].Name != "checkpoint.sig" || proof[2].Name != "signer-public.pem" || proof[3].Name != "journal.jsonl" {
		return nil, errors.New("complete original journal proof identities required")
	}
	selection, err := m.Selection.Bytes()
	if err != nil {
		return nil, err
	}
	members := []collectionMember{{"manifest.json", offlineObject(raw)}}
	members = append(members, proof...)
	members = append(members, collectionMember{"main.mod", m.MainGoMod}, collectionMember{"requirements.json", m.RequirementProof}, collectionMember{"selection.json", offlineObject(selection)})
	for n, source := range m.Sources {
		members = append(members, collectionMember{requirementInputName(n, "manifest.json"), source.Manifest}, collectionMember{requirementInputName(n, "mod"), source.Mod})
	}
	for n, entry := range m.Selection.Entries {
		for k, kind := range []string{"zip", "mod", "info"} {
			a := entry.Artifacts[k]
			members = append(members, collectionMember{setCollectionName(n, kind), blob.Object{Digest: a.Digest, Size: a.Size}})
		}
	}
	if len(members) > maxRequirementCollectionMembers {
		return nil, errors.New("requirement collection member count exceeded")
	}
	return members, nil
}

func validateRequirementEntries(root *os.Root, b goSetCollectionBinding, complete bool) error {
	entries, err := readCollectionEntries(root, maxRequirementCollectionEntries)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"bindings.json": true, "receipt.json": true}
	for _, member := range b.Members {
		allowed[member.Name] = true
	}
	pending := 0
	for _, entry := range entries {
		if allowed[entry.Name()] {
			continue
		}
		if !complete && entry.Name() == collectionBindingPending {
			continue
		}
		if _, ok := receiptPendingGeneration(entry.Name()); !complete && ok {
			pending++
			continue
		}
		return errors.New("requirement collection contains an unknown or pending member; preserve it")
	}
	if pending > 1 || complete && len(entries) != len(b.Members)+2 {
		return errors.New("requirement collection is incomplete or has competing receipts")
	}
	return nil
}

func bindRequirementCollection(root *os.Root, b goSetCollectionBinding, resume bool) error {
	if _, err := parseRequirementBinding(collectionJSON(b)); err != nil {
		return err
	}
	if _, err := root.Lstat("bindings.json"); os.IsNotExist(err) {
		entries, err := readCollectionEntries(root, maxRequirementCollectionEntries)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Name() != collectionBindingPending {
				return errors.New("requirement payload has no complete immutable binding")
			}
		}
	} else if err != nil {
		return err
	}
	return publishCollectionJSON(root, "bindings.json", collectionBindingPending, collectionJSON(b), resume, goSetCollectionJSONLimit)
}

func publishRequirementReceipt(root *os.Root, b goSetCollectionBinding, current int64, resume bool) ([]byte, error) {
	if err := validateRequirementEntries(root, b, false); err != nil {
		return nil, err
	}
	entries, err := readCollectionEntries(root, maxRequirementCollectionEntries)
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
			return nil, errors.New("complete requirement receipt needs explicit resume")
		}
		raw, err := readCollectionPublication(root, "receipt.json", complete, goSetCollectionJSONLimit)
		if err != nil {
			return nil, err
		}
		r, err := parseRequirementReceipt(raw, b)
		if err != nil || r.CollectedGeneration > current || pending != "" && generation != r.CollectedGeneration {
			return nil, errors.New("saved requirement receipt or generation differs")
		}
		generation, expected = r.CollectedGeneration, raw
	} else {
		if pending != "" && (!resume || generation > current) {
			return nil, errors.New("requirement pending receipt needs nonfuture explicit resume")
		}
		if pending == "" {
			generation = current
		}
		expected = collectionJSON(goRequirementCollectionReceipt{Binding: b, CollectedGeneration: generation, BytesVerified: true, OriginalInputsComplete: true, RequirementsReplayed: true})
	}
	if generation < 1 {
		return nil, errors.New("invalid requirement completion generation")
	}
	if pending == "" {
		pending = fmt.Sprintf("receipt.%d.pending", generation)
	}
	if err := publishCollectionJSON(root, "receipt.json", pending, expected, resume, goSetCollectionJSONLimit); err != nil {
		return nil, err
	}
	return expected, nil
}

func verifyRequirementOriginals(ctx context.Context, root *os.Root, parent store.GoRequirementExportManifest) error {
	main, err := readExistingSetFile(root, "main.mod", gomodule.MaxGoMod)
	if err != nil || offlineObject(main) != parent.MainGoMod {
		return errors.New("original project differs from its authenticated reference")
	}
	proof, err := readExistingSetFile(root, "requirements.json", gomodule.MaxRequirementProof)
	if err != nil {
		return err
	}
	index, err := store.BindGoRequirementProof(parent, proof)
	if err != nil {
		return err
	}
	selection, err := parent.Selection.Bytes()
	if err != nil {
		return err
	}
	saved, err := readExistingSetFile(root, "selection.json", store.MaxGoExportSetManifest)
	if err != nil || !bytes.Equal(saved, selection) {
		return errors.New("original selected manifest differs from graph parent")
	}
	bySource := make(map[gomodule.Coordinate]int, len(parent.Sources))
	for n, source := range parent.Sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := readExistingSetFile(root, requirementInputName(n, "manifest.json"), store.MaxGoExportManifest)
		if err != nil {
			return err
		}
		if _, err := store.BindGoRequirementSourceManifest(parent, n, raw); err != nil {
			return err
		}
		bySource[gomodule.Coordinate{Module: source.Module, Version: source.Version}] = n
	}
	expected := make([]gomodule.GraphSelection, 0, len(index.Selected))
	for _, selected := range index.Selected {
		expected = append(expected, gomodule.GraphSelection{Logical: gomodule.Coordinate{Module: selected.Module, Version: selected.Version}, Source: gomodule.Coordinate{Module: selected.SourceModule, Version: selected.SourceVersion}})
	}
	_, err = gomodule.VerifyRequirementProof(ctx, proof, main, func(ctx context.Context, c gomodule.Coordinate, maximum int64) ([]byte, error) {
		n, ok := bySource[c]
		if !ok || ctx.Err() != nil || parent.Sources[n].Mod.Size > maximum {
			return nil, gomodule.ErrRequirementProof
		}
		return readExistingSetFile(root, requirementInputName(n, "mod"), maximum)
	}, expected)
	return err
}

// Compare every retained unpublished byte before appending. A corrupt prefix is
// preserved unchanged, rather than extended and only rejected at final hashing.
func (c *collectionHTTP) verifyRequirementPrefix(ctx context.Context, file *os.File, kind string, object blob.Object) error {
	before, err := file.Stat()
	if err != nil || !privateCollectionFile(before, false) || before.Size() > object.Size {
		return errors.New("invalid retained requirement prefix")
	}
	local, remote := make([]byte, 64<<10), make([]byte, 64<<10)
	for start := int64(0); start < before.Size(); {
		end := min(before.Size()-1, start+c.chunk-1)
		r, err := c.get(ctx, kind, "GET", start, end)
		if err != nil {
			return err
		}
		err = func() error {
			defer r.Body.Close()
			if r.StatusCode != 206 || !collectionHeaders(r, object, c.generation) || r.ContentLength != end-start+1 || len(r.Header.Values("Content-Range")) != 1 || r.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", start, end, object.Size) {
				return errors.New("requirement prefix range identity changed")
			}
			for offset := start; offset <= end; {
				n := int(min(int64(len(local)), end-offset+1))
				if _, err := io.ReadFull(offlineGoReader{ctx, r.Body}, remote[:n]); err != nil {
					return errors.New("requirement prefix response interrupted")
				}
				if _, err := file.ReadAt(local[:n], offset); err != nil || !bytes.Equal(local[:n], remote[:n]) {
					return errors.New("retained requirement prefix differs; original partial bytes preserved")
				}
				offset += int64(n)
			}
			var extra [1]byte
			if _, err := io.ReadFull(offlineGoReader{ctx, r.Body}, extra[:]); err != io.EOF {
				return errors.New("requirement prefix response has excess bytes")
			}
			return nil
		}()
		if err != nil {
			return err
		}
		start = end + 1
	}
	after, err := file.Stat()
	if err != nil || !privateCollectionFile(after, false) || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return errors.New("retained requirement prefix changed while comparing")
	}
	return nil
}
