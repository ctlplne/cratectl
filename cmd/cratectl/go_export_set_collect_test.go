// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

// Metadata/file-system stand-ins. No copied boolean or synthetic package is a
// complete signed-journal/native collection qualification.
func setCollectionBindingFixture(t *testing.T, count int) goSetCollectionBinding {
	t.Helper()
	f := journalSignedCLI(t)
	b := goSetCollectionBinding{Profile: goSetCollectionProfile, Authority: "https://127.0.0.1:38443", SetID: crypt.Digest([]byte("owned-common-collection")), Journal: checksumJournalAttribution{EventSequence: 1, EventHash: f.Head.Hash}}
	for _, name := range []string{"manifest.json", "checkpoint.json", "checkpoint.sig", "signer-public.pem", "journal.jsonl"} {
		b.Members = append(b.Members, collectionMember{name, blob.Object{Digest: crypt.Digest([]byte(name)), Size: int64(len(name))}})
	}
	for n := range count {
		for _, kind := range []string{"zip", "mod", "info"} {
			b.Members = append(b.Members, collectionMember{setCollectionName(n, kind), blob.Object{Digest: crypt.Digest([]byte("owned")), Size: 5}})
		}
	}
	return b
}
func openSetMetadataFixture(t *testing.T, b goSetCollectionBinding) (*os.Root, string) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "common")
	root, dir, err := openCollectionDirectoryChecked(path, false, func(root *os.Root) error { return validateSetCollectionEntries(root, b) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close(); root.Close() })
	return root, path
}
func TestCommonCollectionMaximumBindingPreservesLegacyMetadataBounds(t *testing.T) {
	b := setCollectionBindingFixture(t, 256)
	raw := collectionJSON(b)
	if len(raw) <= collectionJSONLimit || len(raw) > goSetCollectionJSONLimit || len(b.Members) != 773 {
		t.Fatal("maximum fixture does not exercise larger bounded metadata", len(raw), len(b.Members))
	}
	root, _ := openSetMetadataFixture(t, b)
	if err := publishCollectionJSON(root, "legacy.json", "legacy.pending", raw, false); err == nil {
		t.Fatal("legacy64KiBbound silently grew")
	}
	if _, err := root.Lstat("legacy.json"); !os.IsNotExist(err) {
		t.Fatal("legacy overbudget publication became visible")
	}
	if err := bindSetCollection(root, b, false); err != nil {
		t.Fatal("maximum common binding", err)
	}
	info, err := root.Lstat("bindings.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := readCollectionPublication(root, "bindings.json", info, goSetCollectionJSONLimit)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("maximum common identity readback", err)
	}
	if err := bindSetCollection(root, b, true); err != nil {
		t.Fatal("exact maximum replay", err)
	}
	changed := b
	changed.SetID = crypt.Digest([]byte("other-set"))
	if err := bindSetCollection(root, changed, true); err == nil {
		t.Fatal("different common selection reused immutable binding")
	}
}
func TestCommonCollectionBindingRecoversOnlyExactPrefixAndOwnedLinkPair(t *testing.T) {
	for _, scenario := range []string{"prefix", "linked", "corrupt", "unrelated-link", "payload-before-binding", "unexpected-member", "too-many-entries"} {
		t.Run(scenario, func(t *testing.T) {
			b := setCollectionBindingFixture(t, 2)
			root, path := openSetMetadataFixture(t, b)
			raw := collectionJSON(b)
			switch scenario {
			case "prefix":
				if err := os.WriteFile(filepath.Join(path, collectionBindingPending), raw[:len(raw)/2], 0600); err != nil {
					t.Fatal(err)
				}
			case "linked":
				if err := os.WriteFile(filepath.Join(path, collectionBindingPending), raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := root.Link(collectionBindingPending, "bindings.json"); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(filepath.Join(path, collectionBindingPending), []byte("wrong-prefix"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unrelated-link":
				if err := os.WriteFile(filepath.Join(path, "bindings.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(filepath.Join(path, "bindings.json"), filepath.Join(filepath.Dir(path), "unrelated-alias")); err != nil {
					t.Fatal(err)
				}
			case "payload-before-binding":
				if err := os.WriteFile(filepath.Join(path, "root.000.zip"), []byte("unbound"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unexpected-member":
				if err := os.WriteFile(filepath.Join(path, "root.256.zip"), []byte("outside-selection"), 0600); err != nil {
					t.Fatal(err)
				}
			case "too-many-entries":
				for n := 0; n <= goSetCollectionEntries; n++ {
					if err := os.WriteFile(filepath.Join(path, setCollectionName(n, "zip")), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := validateSetCollectionEntries(root, b)
			if err == nil {
				err = bindSetCollection(root, b, true)
			}
			if scenario == "prefix" || scenario == "linked" {
				if err != nil {
					t.Fatal("exact declared recovery failed", err)
				}
				got, err := os.ReadFile(filepath.Join(path, "bindings.json"))
				if err != nil || !bytes.Equal(got, raw) {
					t.Fatal("recovery changed immutable common metadata", err)
				}
				if _, err := root.Lstat(collectionBindingPending); !os.IsNotExist(err) {
					t.Fatal("owned pending alias remained")
				}
			} else if err == nil {
				t.Fatal("unsafe common initialization accepted", scenario)
			}
		})
	}
}
func TestCommonCollectionReceiptReplayRetainsOriginalGenerationAndRejectsChangedIntent(t *testing.T) {
	b := setCollectionBindingFixture(t, 2)
	root, path := openSetMetadataFixture(t, b)
	if err := bindSetCollection(root, b, false); err != nil {
		t.Fatal(err)
	}
	original, err := publishSetCollectionReceipt(root, b, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := publishSetCollectionReceipt(root, b, 2, true)
	if err != nil || !bytes.Equal(replay, original) {
		t.Fatal("renewed resume rewrote original receipt", err)
	}
	var r goSetCollectionReceipt
	if json.Unmarshal(original, &r) != nil || r.CollectedGeneration != 1 || !r.BytesVerified || r.CurrentRegistryAdmission || r.ChecksumAuthority || r.DependencyClosure || r.DeliveryVerified {
		t.Fatal("metadata completion supplied unsupported claims")
	}
	if err := os.Rename(filepath.Join(path, "receipt.json"), filepath.Join(path, "receipt.1.pending")); err != nil {
		t.Fatal(err)
	}
	replay, err = publishSetCollectionReceipt(root, b, 2, true)
	if err != nil || !bytes.Equal(replay, original) {
		t.Fatal("uncertain completion lost original generation", err)
	}
	if err := os.WriteFile(filepath.Join(path, "receipt.3.pending"), original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := publishSetCollectionReceipt(root, b, 2, true); err == nil {
		t.Fatal("future pending receipt accepted")
	}
	retained, err := os.ReadFile(filepath.Join(path, "receipt.json"))
	if err != nil || !bytes.Equal(retained, original) {
		t.Fatal("failed recovery changed prior receipt", err)
	}
}
func TestCommonCollectionInspectsOriginalRepresentationsAndRejectsLateCorruption(t *testing.T) {
	index, _, manifests := exportIndexUnitFixture(t, 1)
	m, err := store.ParseGoExportManifest(manifests[index.Entries[0].ManifestFile])
	if err != nil {
		t.Fatal(err)
	}
	_, files := offlineGoFiles(t)
	b := setCollectionBindingFixture(t, 1)
	root, path := openSetMetadataFixture(t, b)
	for k, kind := range []string{"zip", "mod", "info"} {
		if crypt.Digest(files[k]) != m.Artifacts[k].Digest {
			t.Fatal("original inert fixture mismatch")
		}
		if err := os.WriteFile(filepath.Join(path, setCollectionName(0, kind)), files[k], 0600); err != nil {
			t.Fatal(err)
		}
	}
	common := store.GoExportSetManifest{Entries: []store.GoExportManifest{m}}
	if err := inspectSetCollection(context.Background(), root, common); err != nil {
		t.Fatal("actual inert ZIP/mod/info consistency", err)
	}
	name := filepath.Join(path, setCollectionName(0, "info"))
	changed := bytes.Clone(files[2])
	changed[len(changed)/2] ^= 1
	if err := os.WriteFile(name, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := inspectSetCollection(context.Background(), root, common); err == nil {
		t.Fatal("changed later representation certified")
	}
	if _, err := os.Stat(filepath.Join(path, "receipt.json")); !os.IsNotExist(err) {
		t.Fatal("failed physical check published a receipt")
	}
}
func TestCommonCollectionRejectsMissingIndependentProofBeforeConfigurationOrOutput(t *testing.T) {
	for _, args := range [][]string{nil, {"--config", "/private/nonexistent", "--set-id", crypt.Digest([]byte("owned")), "--generation", "1", "--output-directory", filepath.Join(t.TempDir(), "never-created"), "--journal-file", "/private/nonexistent", "--journal-through", "1", "--journal-through-hash", crypt.Digest([]byte("head")), "--journal-tenant", "owned-team", "--journal-event-sequence", "1"}} {
		var out bytes.Buffer
		if err := runGoExportSetCollect(args, &out); err == nil || out.Len() != 0 {
			t.Fatal("incomplete independent trust returned result", err)
		}
	}
}
