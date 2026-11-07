// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

// Owned metadata/filesystem stand-in. Its real public signature authenticates
// another story, not this graph creation. Public entrypoints must refuse it.
func requirementCollectionFixture(t *testing.T) (*os.Root, string, store.GoRequirementExportManifest, goSetCollectionBinding, map[string][]byte) {
	t.Helper()
	_, parentDir, old, oldFiles := offlineSetFixture(t)
	selection := old.manifest
	selection.Entries = append([]store.GoExportManifest(nil), old.manifest.Entries[:2]...)
	selection.DeclaredArtifactBytes = 0
	for _, e := range selection.Entries {
		for _, a := range e.Artifacts {
			selection.DeclaredArtifactBytes += a.Size
		}
	}
	main := []byte("module owned/main\ngo 1.27.0\nrequire " + selection.Entries[0].Module + " " + selection.Entries[0].Version + "\n")
	coordinate := gomodule.Coordinate{Module: selection.Entries[0].Module, Version: selection.Entries[0].Version}
	proof, _, err := gomodule.BuildRequirementProof(context.Background(), main, []gomodule.RequirementInput{{Source: coordinate, Mod: oldFiles[setCollectionName(0, "mod")]}})
	if err != nil {
		t.Fatal(err)
	}
	inputManifest, err := selection.Entries[0].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	graph := store.GoRequirementExportManifest{Profile: store.GoRequirementExportProfile, Selection: selection, MainGoMod: offlineObject(main), RequirementProof: offlineObject(proof), Sources: []store.GoRequirementExportSource{{Repository: selection.Entries[0].Repository, SourceRevision: selection.Entries[0].SourceRevision, Module: coordinate.Module, Version: coordinate.Version, Manifest: offlineObject(inputManifest), Mod: offlineObject(oldFiles[setCollectionName(0, "mod")])}}}
	raw, err := graph.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	selectedRaw, _ := selection.Bytes()
	files := map[string][]byte{"manifest.json": raw, "main.mod": main, "requirements.json": proof, "selection.json": selectedRaw, requirementInputName(0, "manifest.json"): inputManifest, requirementInputName(0, "mod"): oldFiles[setCollectionName(0, "mod")]}
	proofMembers := []collectionMember{}
	for _, name := range []string{"checkpoint.json", "checkpoint.sig", "signer-public.pem", "journal.jsonl"} {
		files[name] = oldFiles[name]
		proofMembers = append(proofMembers, collectionMember{name, offlineObject(files[name])})
	}
	for n := range selection.Entries {
		for _, kind := range []string{"zip", "mod", "info"} {
			name := setCollectionName(n, kind)
			files[name] = oldFiles[name]
		}
	}
	members, err := requirementMembers(raw, graph, proofMembers)
	if err != nil {
		t.Fatal(err)
	}
	b := goSetCollectionBinding{Profile: goRequirementCollectionProfile, Authority: old.binding.Authority, SetID: old.binding.SetID, Journal: old.attribution, Members: members}
	files["bindings.json"] = collectionJSON(b)
	files["receipt.json"] = collectionJSON(goRequirementCollectionReceipt{Binding: b, CollectedGeneration: 1, BytesVerified: true, OriginalInputsComplete: true, RequirementsReplayed: true})
	directory := filepath.Join(parentDir, "requirement originals")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, lock, err := openCollectionDirectoryChecked(directory, true, requirementSourceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close(); root.Close() })
	return root, directory, graph, b, files
}

func TestRequirementCollectionReplaysOriginalMetadataAndRefusesChangedInputsWithoutRepair(t *testing.T) {
	for _, changed := range []string{"original", "main.mod", "requirements.json", "selection.json", "input.0000.mod", "input.0000.manifest.json"} {
		t.Run(changed, func(t *testing.T) {
			root, directory, graph, binding, files := requirementCollectionFixture(t)
			if changed != "original" {
				raw := bytes.Clone(files[changed])
				raw[len(raw)/2] ^= 1
				if err := os.WriteFile(filepath.Join(directory, changed), raw, 0600); err != nil {
					t.Fatal(err)
				}
				files[changed] = raw
			}
			err := verifyRequirementOriginals(context.Background(), root, graph)
			if (err == nil) != (changed == "original") {
				t.Fatal("original requirement replay changed", err)
			}
			if err := validateRequirementEntries(root, binding, true); err != nil {
				t.Fatal(err)
			}
			for name, expected := range files {
				got, err := os.ReadFile(filepath.Join(directory, name))
				if err != nil || !bytes.Equal(got, expected) {
					t.Fatal("verification modified private originals", name, err)
				}
			}
		})
	}
}

func TestRequirementCollectionReceiptRetainsOriginalGenerationAndRefusesUnsupportedClaims(t *testing.T) {
	root, directory, _, binding, files := requirementCollectionFixture(t)
	first, err := publishRequirementReceipt(root, binding, 2, true)
	if err != nil || !bytes.Equal(first, files["receipt.json"]) {
		t.Fatal("immutable original completion changed on renewal", err)
	}
	var receipt goRequirementCollectionReceipt
	json.Unmarshal(first, &receipt)
	for _, scenario := range []string{"inputs", "replay", "bytes", "closure", "authority", "admission", "delivery", "future", "binding"} {
		changed := receipt
		switch scenario {
		case "inputs":
			changed.OriginalInputsComplete = false
		case "replay":
			changed.RequirementsReplayed = false
		case "bytes":
			changed.BytesVerified = false
		case "closure":
			changed.DependencyClosure = true
		case "authority":
			changed.ChecksumAuthority = true
		case "admission":
			changed.CurrentRegistryAdmission = true
		case "delivery":
			changed.DeliveryVerified = true
		case "future":
			changed.CollectedGeneration = 3
		case "binding":
			changed.Binding.SetID = strings.Repeat("b", 64)
		}
		raw := collectionJSON(changed)
		if err := os.WriteFile(filepath.Join(directory, "receipt.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := publishRequirementReceipt(root, binding, 2, true); err == nil {
			t.Fatal("unsupported completion accepted", scenario)
		}
		if got, _ := os.ReadFile(filepath.Join(directory, "receipt.json")); !bytes.Equal(got, raw) {
			t.Fatal("invalid completion was rewritten")
		}
	}
}

func TestRequirementCollectionMaximumDescriptorCountFitsExistingMetadataBound(t *testing.T) {
	b := setCollectionBindingFixture(t, 0)
	b.Profile = goRequirementCollectionProfile
	b.Authority = "https://" + strings.Repeat("a", 2000)
	b.Members = nil
	add := func(name string) {
		b.Members = append(b.Members, collectionMember{name, blob.Object{Digest: strings.Repeat("a", 64), Size: 65 << 30}})
	}
	for _, name := range []string{"manifest.json", "checkpoint.json", "checkpoint.sig", "signer-public.pem", "journal.jsonl", "main.mod", "requirements.json", "selection.json"} {
		add(name)
	}
	for n := range gomodule.MaxRequirementProofSources {
		add(requirementInputName(n, "manifest.json"))
		add(requirementInputName(n, "mod"))
	}
	for n := range store.MaxGoExportSetEntries {
		for _, kind := range []string{"zip", "mod", "info"} {
			add(setCollectionName(n, kind))
		}
	}
	raw := collectionJSON(b)
	if len(b.Members) != maxRequirementCollectionMembers || len(raw) > goSetCollectionJSONLimit {
		t.Fatal("maximum original descriptor map exceeds existing bound", len(raw))
	}
	if _, err := parseRequirementBinding(raw); err != nil {
		t.Fatal(err)
	}
	receipt := collectionJSON(goRequirementCollectionReceipt{Binding: b, CollectedGeneration: 9223372036854775807, BytesVerified: true, OriginalInputsComplete: true, RequirementsReplayed: true})
	if len(receipt) > goSetCollectionJSONLimit {
		t.Fatal("maximum completion exceeds unchanged metadata bound", len(receipt))
	}
	if _, err := parseRequirementReceipt(receipt, b); err != nil {
		t.Fatal("maximum canonical completion refused", err)
	}
	add("extra.mod")
	if _, err := parseRequirementBinding(collectionJSON(b)); err == nil {
		t.Fatal("excess members reached typed allocation")
	}
	for _, raw := range [][]byte{[]byte(`{"members":[` + strings.Repeat(`{},`, maxRequirementCollectionMembers) + `{}` + `]}`), []byte(strings.Repeat(" ", goSetCollectionJSONLimit+1))} {
		if preflightRequirementJSON(raw, false) == nil {
			t.Fatal("oversized member/input budget accepted")
		}
	}
}

func TestRequirementCollectionRefusesUnknownFilesAndUnrelatedSignedCreationBeforeOutput(t *testing.T) {
	root, directory, _, b, _ := requirementCollectionFixture(t)
	if _, err := loadRequirementInput(context.Background(), root, b.Journal, b.SetID, 1<<20, 2<<30); err == nil {
		t.Fatal("unrelated signed story became graph-creation proof")
	}
	if err := os.WriteFile(filepath.Join(directory, "input.1024.mod"), []byte("unknown"), 0600); err != nil {
		t.Fatal(err)
	}
	if validateRequirementEntries(root, b, true) == nil || requirementSourceDirectory(root) == nil {
		t.Fatal("unknown original accepted")
	}
	var out bytes.Buffer
	if err := runGoRequirementOffline([]string{"--collection-directory", directory, "--set-id", b.SetID, "--checkpoint-key-file", filepath.Join(directory, "signer-public.pem")}, &out, true); err == nil || out.Len() != 0 {
		t.Fatal("unrelated/unknown collection emitted success")
	}
}

func TestRequirementCollectionTransportRoutesAndCorruptPrefixRefusesBeforeAppend(t *testing.T) {
	body := bytes.Repeat([]byte("owned original data"), 8000)
	object := offlineObject(body)
	id := strings.Repeat("a", 64)
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("ETag", `"sha256:`+object.Digest+`"`)
		w.Header().Set("X-Checksum-Sha256", object.Digest)
		w.Header().Set("X-Cratectl-Export-Generation", "1")
		var start, end int
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(body)))
		w.Header().Set("Content-Length", strconv.Itoa(end-start+1))
		w.WriteHeader(206)
		w.Write(body[start : end+1])
	}))
	defer server.Close()
	transport := &collectionHTTP{client: server.Client(), base: server.URL, id: id, generation: 1, chunk: 64 << 10, requirementSet: true}
	directory := t.TempDir()
	os.Chmod(directory, 0700)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	prefix := bytes.Clone(body[:1000])
	prefix[0] ^= 1
	if err := os.WriteFile(filepath.Join(directory, "input.0000.mod"), prefix, 0600); err != nil {
		t.Fatal(err)
	}
	if err := transport.download(context.Background(), root, "input.0000.mod", "inputs/0/mod", object); err == nil {
		t.Fatal("corrupt partial prefix accepted")
	}
	if got, _ := os.ReadFile(filepath.Join(directory, "input.0000.mod")); !bytes.Equal(got, prefix) {
		t.Fatal("corrupt prefix was extended or repaired")
	}
	if err := os.WriteFile(filepath.Join(directory, "input.0000.mod"), body[:1000], 0600); err != nil {
		t.Fatal(err)
	}
	if err := transport.download(context.Background(), root, "input.0000.mod", "inputs/0/mod", object); err != nil {
		t.Fatal(err)
	}
	if err := transport.download(context.Background(), root, "root.000.zip", "roots/0/zip", object); err != nil {
		t.Fatal(err)
	}
	if paths[0] != "/api/v1/go/export-sets/requirements/"+id+"/inputs/0/mod" || paths[len(paths)-1] != "/api/v1/go/export-sets/"+id+"/roots/0/zip" {
		t.Fatal("requirement and payload routes were mixed", paths)
	}
}

func TestRequirementCollectionNativeMetadataKeepsUnselectedModWithoutDiscoveryOrPayload(t *testing.T) {
	_, _, parent, _, _ := requirementCollectionFixture(t)
	lower := parent.Sources[0]
	lower.Version = "v1.0.0"
	parent.Sources = append(parent.Sources, lower)
	layout, err := offlineSetLayoutFor(parent.Selection)
	if err != nil {
		t.Fatal(err)
	}
	originalVersions := append([]string(nil), layout.versions[lower.Module]...)
	c := gomodule.Coordinate{Module: lower.Module, Version: lower.Version}
	if _, exists := layout.paths["proxy/"+c.Prefix()+".mod"]; exists {
		t.Fatal("legacy selected-only layout unexpectedly supplies lower metadata")
	}
	if err := addRequirementMetadataPaths(&layout, parent); err != nil {
		t.Fatal(err)
	}
	if directory, exists := layout.paths["proxy/"+c.Prefix()+".mod"]; !exists || directory {
		t.Fatal("examined lower metadata omitted from native replay")
	}
	for _, kind := range []string{"zip", "info"} {
		if _, exists := layout.paths["proxy/"+c.Prefix()+"."+kind]; exists {
			t.Fatal("unselected original advertised an unavailable payload", kind)
		}
	}
	if fmt.Sprint(layout.versions[lower.Module]) != fmt.Sprint(originalVersions) {
		t.Fatal("metadata-only input changed selected discovery")
	}
	for _, collision := range []string{"proxy/" + c.Prefix() + ".mod", "proxy/" + strings.Split(c.Prefix(), "/")[0]} {
		broken, err := offlineSetLayoutFor(parent.Selection)
		if err != nil {
			t.Fatal(err)
		}
		// The metadata target cannot be a directory; its ancestor cannot be a file.
		if strings.HasSuffix(collision, ".mod") {
			broken.paths[collision] = true
		} else {
			broken.paths[collision] = false
		}
		if err := addRequirementMetadataPaths(&broken, parent); err == nil {
			t.Fatal("metadata path type collision accepted")
		}
	}
}

func TestRequirementCollectionClosedMetadataRejectsAmbiguousFields(t *testing.T) {
	_, _, _, binding, _ := requirementCollectionFixture(t)
	original := collectionJSON(binding)
	for _, raw := range [][]byte{
		bytes.Replace(original, []byte(`"profile":`), []byte(`"profile":"duplicate","profile":`), 1),
		bytes.Replace(original, []byte(`"members":`), []byte(`"unknown":false,"members":`), 1),
		bytes.Replace(original, []byte(`"members":`), []byte(`"members":null,"discarded":`), 1),
		append(bytes.Clone(original), []byte(`{}`)...),
		bytes.Replace(original, []byte(`"size":`), []byte(`"extra":true,"size":`), 1),
	} {
		if _, err := parseRequirementBinding(raw); err == nil {
			t.Fatal("ambiguous/extra requirement binding accepted")
		}
	}
}

func FuzzRequirementCollectionMetadata(f *testing.F) {
	f.Add([]byte(`{"profile":"unknown"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > goSetCollectionJSONLimit+1 {
			return
		}
		b, err := parseRequirementBinding(raw)
		if err == nil && !bytes.Equal(raw, collectionJSON(b)) {
			t.Fatal("noncanonical binding accepted")
		}
		_, _ = parseRequirementReceipt(raw, goSetCollectionBinding{})
	})
}
