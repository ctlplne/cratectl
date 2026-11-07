// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

// This is a filesystem stand-in for the internal assembler, not an authenticated
// common creation. The public signature fixture authenticates its own original
// journal only. The CLI must reject it as a common creation (tested below).
func offlineSetFixture(t *testing.T) (*os.Root, string, offlineSetInput, map[string][]byte) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "collection")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	signed := journalSignedCLI(t)
	verified, event, err := crypt.VerifyJournalExportEvent(context.Background(), bytes.NewReader(signed.Export), crypt.JournalAnchor{Tenant: signed.Head.Tenant}, signed.Head, int64(len(signed.Export)), 1)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := crypt.VerifyJournalCheckpoint(signed.Statement, signed.Signature, signed.PublicKey, signed.Head)
	if err != nil {
		t.Fatal(err)
	}
	input := offlineSetInput{attribution: checksumJournalAttribution{verified, event.Sequence, event.Hash, signature}}
	prepared := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	common := store.GoExportSetManifest{Profile: store.GoExportSetProfile, Tenant: signed.Head.Tenant, PreparedAt: prepared, ObservedJournal: crypt.JournalAnchor{Tenant: signed.Head.Tenant}, PolicyScope: "historical explicitly selected source decisions; not dependency closure or destination admission"}
	files := map[string][]byte{"checkpoint.json": signed.Statement, "checkpoint.sig": signed.Signature, "signer-public.pem": signed.PublicKey, "journal.jsonl": signed.Export}
	coordinates := []gomodule.Coordinate{{Module: "go.cratectl.invalid/Owned/app", Version: "v1.10.0"}, {Module: "go.cratectl.invalid/Owned/dependency", Version: "v1.1.0"}, {Module: "go.cratectl.invalid/Owned/app", Version: "v1.2.0"}}
	for n, c := range coordinates {
		mod := []byte("module " + c.Module + "\n\ngo 1.26.0\n")
		if n != 1 {
			mod = append(mod, []byte("require "+coordinates[1].Module+" "+coordinates[1].Version+"\n")...)
		}
		info, err := gomodule.VersionInfo(c, prepared.Format(time.RFC3339))
		if err != nil {
			t.Fatal(err)
		}
		var archive bytes.Buffer
		z := zip.NewWriter(&archive)
		for _, item := range []struct {
			name string
			raw  []byte
		}{{"go.mod", mod}, {"assets/inert.txt", []byte("retained original, never executed")}} {
			w, err := z.Create(c.Module + "@" + c.Version + "/" + item.name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(item.raw); err != nil {
				t.Fatal(err)
			}
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		originals := [3][]byte{archive.Bytes(), mod, info}
		digests := map[string]string{}
		for k, kind := range []string{"zip", "mod", "info"} {
			digests[kind] = crypt.Digest(originals[k])
		}
		metadata, err := json.Marshal(store.GoModuleMetadata{Profile: store.GoModuleProfile, Module: c.Module, Version: c.Version, Digests: digests})
		if err != nil {
			t.Fatal(err)
		}
		m := store.GoExportManifest{Profile: store.GoExportProfile, Tenant: common.Tenant, Repository: "owned", Module: c.Module, Version: c.Version, RequireReview: true, Access: "restricted", PreparedAt: prepared, ObservedJournal: common.ObservedJournal, PolicyScope: "historical source decisions; not destination admission"}
		if n == 1 {
			m.Repository = "other"
		}
		for k, kind := range []string{"zip", "mod", "info"} {
			path := c.Prefix() + "." + kind
			m.Artifacts = append(m.Artifacts, store.GoExportArtifact{Path: path, Digest: digests[kind], Size: int64(len(originals[k])), MediaType: []string{"application/zip", "text/plain; charset=utf-8", "application/json"}[k], Metadata: metadata, CreatedAt: prepared, Decision: "allowed", DecisionVersion: 1, Lifecycle: store.ArtifactState{Repository: m.Repository, Path: path}})
			common.DeclaredArtifactBytes += int64(len(originals[k]))
			files[setCollectionName(n, kind)] = originals[k]
		}
		common.Entries = append(common.Entries, m)
	}
	input.raw, err = common.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	input.manifest = common
	files["manifest.json"] = input.raw
	input.binding = goSetCollectionBinding{Profile: goSetCollectionProfile, Authority: "https://127.0.0.1:38443", SetID: crypt.Digest([]byte("owned-offline-set")), Journal: input.attribution}
	for _, name := range []string{"manifest.json", "checkpoint.json", "checkpoint.sig", "signer-public.pem", "journal.jsonl"} {
		input.binding.Members = append(input.binding.Members, collectionMember{name, offlineObject(files[name])})
	}
	for n := range common.Entries {
		for _, kind := range []string{"zip", "mod", "info"} {
			name := setCollectionName(n, kind)
			input.binding.Members = append(input.binding.Members, collectionMember{name, offlineObject(files[name])})
		}
	}
	input.receipt = goSetCollectionReceipt{Binding: input.binding, CollectedGeneration: 2, BytesVerified: true}
	input.bindingRaw, input.receiptRaw = collectionJSON(input.binding), collectionJSON(input.receipt)
	files["bindings.json"], files["receipt.json"] = input.bindingRaw, input.receiptRaw
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, lock, err := openCollectionDirectoryChecked(directory, true, commonSourceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close(); root.Close() })
	return root, parent, input, files
}

func TestCommonOfflineProxyPublishesAllOriginalsAndReplaysExactReceipt(t *testing.T) {
	source, parent, input, originals := offlineSetFixture(t)
	output := filepath.Join(parent, "offline union")
	raw, err := assembleOfflineSet(context.Background(), source, input, output, false, 64<<10, 2<<30)
	if err != nil {
		t.Fatal(err)
	}
	var receipt goSetOfflineReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.Profile != goSetOfflineProfile || len(receipt.Roots) != 3 || !receipt.BytesVerified || !receipt.SelectedRootsComplete || !receipt.NativeProxyPrepared || receipt.CurrentRegistryAdmission || receipt.ChecksumAuthority || receipt.DependencyClosure || receipt.CollectedGeneration != 2 {
		t.Fatal("unsupported or incomplete offline claims")
	}
	for n, entry := range input.manifest.Entries {
		if receipt.Roots[n].ZIPHash == "" || receipt.Roots[n].ModHash == "" {
			t.Fatal("native original hashes absent")
		}
		c := gomodule.Coordinate{Module: entry.Module, Version: entry.Version}
		for _, kind := range []string{"zip", "mod", "info"} {
			got, err := os.ReadFile(filepath.Join(output, "bundle", "proxy", c.Prefix()+"."+kind))
			if err != nil || !bytes.Equal(got, originals[setCollectionName(n, kind)]) {
				t.Fatal("original changed", n, kind, err)
			}
		}
	}
	for _, name := range []string{"manifest.json", "checkpoint.json", "checkpoint.sig", "signer-public.pem", "journal.jsonl", "bindings.json", "receipt.json"} {
		got, err := os.ReadFile(filepath.Join(output, "bundle", "proof", name))
		if err != nil || !bytes.Equal(got, originals[name]) {
			t.Fatal("original proof changed", name, err)
		}
	}
	base := filepath.Join(output, "bundle", "proxy", "go.cratectl.invalid", "!owned", "app")
	list, err := os.ReadFile(filepath.Join(base, "@v", "list"))
	if err != nil || string(list) != "v1.2.0\nv1.10.0\n" {
		t.Fatal("discovery not semantic version ordered", string(list), err)
	}
	latest, err := os.ReadFile(filepath.Join(base, "@latest"))
	if err != nil || !bytes.Equal(latest, originals[setCollectionName(0, "info")]) {
		t.Fatal("latest not selected original", err)
	}
	proxy, err := url.Parse(receipt.Proxy)
	if err != nil || proxy.Scheme != "file" || proxy.Path != filepath.Join(output, "bundle", "proxy") {
		t.Fatal("native proxy path differs", err)
	}
	if _, err := os.Stat(filepath.Join(output, "staging")); !os.IsNotExist(err) {
		t.Fatal("unpublished tree retained after successful publication")
	}
	replay, err := assembleOfflineSet(context.Background(), source, input, output, true, 64<<10, 2<<30)
	if err != nil || !bytes.Equal(raw, replay) {
		t.Fatal("same-input replay changed original receipt", err)
	}
}

func TestCommonOfflineProxyResumesOnlyExactUnpublishedPrefixes(t *testing.T) {
	for _, scenario := range []string{"prefix", "corrupt-prefix", "unknown", "symlink", "hardlink", "competing", "changed-intent", "late-source-corruption"} {
		t.Run(scenario, func(t *testing.T) {
			source, parent, input, originals := offlineSetFixture(t)
			output := filepath.Join(parent, "offline")
			proxy := (&url.URL{Scheme: "file", Path: filepath.Join(output, "bundle", "proxy")}).String()
			intent := goSetOfflineIntent{"cratectl.go.hosted.set-offline.intent.v1", input.binding.SetID, offlineObject(input.raw), offlineObject(input.bindingRaw), offlineObject(input.receiptRaw), proxy}
			root, lock, err := openCollectionDirectoryChecked(output, false, offlineSetOutputDirectory)
			if err != nil {
				t.Fatal(err)
			}
			if err := bindOfflineSetOutput(root, intent, false); err != nil {
				t.Fatal(err)
			}
			c := gomodule.Coordinate{Module: input.manifest.Entries[0].Module, Version: input.manifest.Entries[0].Version}
			name := filepath.Join(output, "staging", "proxy", c.Prefix()+".zip")
			if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
				t.Fatal(err)
			}
			prefix := bytes.Clone(originals[setCollectionName(0, "zip")][:91])
			if scenario == "corrupt-prefix" {
				prefix[13] ^= 1
			}
			if err := os.WriteFile(name, prefix, 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "unknown":
				if err := os.WriteFile(filepath.Join(output, "staging", "unexpected"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				original := filepath.Join(parent, "outside-original")
				if err := os.Rename(name, original); err != nil {
					t.Fatal(err)
				}
				if scenario == "symlink" {
					err = os.Symlink(original, name)
				} else {
					err = os.Link(original, name)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "competing":
				if err := os.Mkdir(filepath.Join(output, "bundle"), 0700); err != nil {
					t.Fatal(err)
				}
			case "changed-intent":
				input.receiptRaw = append(bytes.Clone(input.receiptRaw), ' ')
			case "late-source-corruption":
				last := filepath.Join(source.Name(), setCollectionName(2, "info"))
				bad := bytes.Clone(originals[setCollectionName(2, "info")])
				bad[len(bad)/2] ^= 1
				if err := os.WriteFile(last, bad, 0600); err != nil {
					t.Fatal(err)
				}
			}
			lock.Close()
			root.Close()
			raw, err := assembleOfflineSet(context.Background(), source, input, output, true, 64<<10, 2<<30)
			if scenario == "prefix" {
				if err != nil || len(raw) == 0 {
					t.Fatal("exact prefix recovery failed", err)
				}
				return
			}
			if err == nil || len(raw) != 0 {
				t.Fatal("unsafe partial tree accepted", scenario)
			}
			if scenario != "competing" {
				if _, err := os.Stat(filepath.Join(output, "bundle")); !os.IsNotExist(err) {
					t.Fatal("late failure published final tree")
				}
			}
			if scenario == "corrupt-prefix" || scenario == "changed-intent" {
				retained, err := os.ReadFile(name)
				if err != nil || !bytes.Equal(retained, prefix) {
					t.Fatal("unsafe prefix overwritten", err)
				}
			}
		})
	}
}

func TestCommonOfflineProxyRefusesChangedPublishedDataWithoutRepair(t *testing.T) {
	for _, scenario := range []string{"corrupt-output", "missing-output", "corrupt-source", "changed-receipt"} {
		t.Run(scenario, func(t *testing.T) {
			source, parent, input, originals := offlineSetFixture(t)
			output := filepath.Join(parent, "offline")
			raw, err := assembleOfflineSet(context.Background(), source, input, output, false, 64<<10, 2<<30)
			if err != nil {
				t.Fatal(err)
			}
			c := gomodule.Coordinate{Module: input.manifest.Entries[2].Module, Version: input.manifest.Entries[2].Version}
			path := filepath.Join(output, "bundle", "proxy", c.Prefix()+".info")
			bad := bytes.Clone(originals[setCollectionName(2, "info")])
			bad[len(bad)/2] ^= 1
			switch scenario {
			case "corrupt-output":
				err = os.WriteFile(path, bad, 0600)
			case "missing-output":
				err = os.Remove(path)
			case "corrupt-source":
				err = os.WriteFile(filepath.Join(source.Name(), setCollectionName(2, "info")), bad, 0600)
			case "changed-receipt":
				err = os.WriteFile(filepath.Join(output, "bundle", "receipt.json"), []byte("retain invalid completion"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(output, "bundle", "receipt.json"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := assembleOfflineSet(context.Background(), source, input, output, true, 64<<10, 2<<30)
			if err == nil || len(got) != 0 {
				t.Fatal("changed published data accepted")
			}
			after, err := os.ReadFile(filepath.Join(output, "bundle", "receipt.json"))
			if err != nil || !bytes.Equal(before, after) || scenario != "changed-receipt" && !bytes.Equal(raw, after) {
				t.Fatal("historical completion rewritten", err)
			}
			if scenario == "corrupt-output" {
				got, _ := os.ReadFile(path)
				if !bytes.Equal(got, bad) {
					t.Fatal("published corruption silently repaired")
				}
			}
			if scenario == "missing-output" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("missing published member silently created")
				}
			}
		})
	}
}

func TestCommonOfflineProxyPreflightBudgetsCancellationAndInputSeparation(t *testing.T) {
	for _, scenario := range []string{"budget", "cancelled", "nested", "aliased-nested", "existing", "invalid-chunk"} {
		t.Run(scenario, func(t *testing.T) {
			source, parent, input, _ := offlineSetFixture(t)
			output := filepath.Join(parent, "offline")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			budget, chunk := int64(2<<30), int64(64<<10)
			switch scenario {
			case "budget":
				budget = 1
			case "cancelled":
				cancel()
			case "nested":
				output = filepath.Join(source.Name(), "offline")
			case "aliased-nested":
				alias := filepath.Join(parent, "source-alias")
				if err := os.Symlink(source.Name(), alias); err != nil {
					t.Fatal(err)
				}
				output = filepath.Join(alias, "offline")
			case "existing":
				if err := os.Mkdir(output, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(output, "sentinel"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid-chunk":
				chunk = 1
			}
			got, err := assembleOfflineSet(ctx, source, input, output, false, chunk, budget)
			if err == nil || len(got) != 0 {
				t.Fatal("unsafe preflight accepted", scenario)
			}
			if scenario == "existing" {
				got, err := os.ReadFile(filepath.Join(output, "sentinel"))
				if err != nil || string(got) != "keep" {
					t.Fatal("existing data changed", err)
				}
			} else if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("failed preflight left output")
			}
		})
	}
}

func TestCommonOfflineCLIRequiresIndependentTrustAndOriginalCommonCreation(t *testing.T) {
	_, parent, input, _ := offlineSetFixture(t)
	signed := journalSignedCLI(t)
	// Use another private directory so the CLI can verify the real public
	// signature, then reject its original non-common event.
	collection := filepath.Join(parent, "collection")
	other := filepath.Join(parent, "different-collection")
	if err := os.Mkdir(other, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "checkpoint.json", "checkpoint.sig", "signer-public.pem", "journal.jsonl", "bindings.json", "receipt.json"} {
		raw, err := os.ReadFile(filepath.Join(collection, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(other, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(parent, "independently-selected.pem")
	if err := os.WriteFile(key, signed.PublicKey, 0600); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"missing-independent-key", "wrong-event-kind"} {
		output := filepath.Join(parent, scenario)
		args := []string{"--collection-directory", other, "--set-id", input.binding.SetID, "--output-directory", output, "--journal-tenant", signed.Head.Tenant, "--journal-event-sequence", "1", "--journal-through", strconv.FormatInt(signed.Head.Sequence, 10), "--journal-through-hash", signed.Head.Hash}
		if scenario == "wrong-event-kind" {
			args = append(args, "--checkpoint-key-file", key)
		}
		var stdout bytes.Buffer
		if err := runGoExportSetOffline(args, &stdout); err == nil || stdout.Len() != 0 {
			t.Fatal("copied metadata conferred common trust", scenario)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("untrusted input created output")
		}
	}
}

func TestCommonOfflineLayoutBoundsAndNativeVersionSelection(t *testing.T) {
	_, _, input, _ := offlineSetFixture(t)
	layout, err := offlineSetLayoutFor(input.manifest)
	if err != nil || !reflect.DeepEqual(layout.versions["go.cratectl.invalid/Owned/app"], []string{"v1.2.0", "v1.10.0"}) {
		t.Fatal("wrong native discovery", err)
	}
	for _, count := range []int{0, store.MaxGoExportSetEntries + 1} {
		m := input.manifest
		m.Entries = make([]store.GoExportManifest, count)
		if _, err := offlineSetLayoutFor(m); err == nil {
			t.Fatal("unbounded root layout", count)
		}
	}
}

func TestCommonOfflineMetadataRejectsAliasesDuplicatesAndUnsupportedClaims(t *testing.T) {
	_, _, input, _ := offlineSetFixture(t)
	for _, raw := range [][]byte{nil, []byte("null\n"), append(bytes.Clone(input.bindingRaw), ' '), bytes.Replace(input.bindingRaw, []byte(`"profile":`), []byte(`"Profile":`), 1), bytes.Replace(input.bindingRaw, []byte(`"set_id":`), []byte(`"set_id":"ignored","set_id":`), 1), bytes.Replace(input.bindingRaw, []byte(`https://127.0.0.1:38443`), []byte(`https://user:secret@127.0.0.1:38443`), 1), bytes.Repeat([]byte("x"), goSetCollectionJSONLimit+1)} {
		if _, err := parseOfflineSetBinding(raw); err == nil {
			t.Fatal("ambiguous/unsafe collection identity accepted")
		}
	}
	for _, field := range []string{"bytes_verified", "current_registry_admission", "checksum_authority_verified", "dependency_closure", "delivery_verified"} {
		old, next := []byte(`"`+field+`":false`), []byte(`"`+field+`":true`)
		if field == "bytes_verified" {
			old, next = next, old
		}
		raw := bytes.Replace(input.receiptRaw, old, next, 1)
		if bytes.Equal(raw, input.receiptRaw) {
			t.Fatal("negative control did not change its target", field)
		}
		if _, err := parseOfflineSetReceipt(raw, input.binding); err == nil {
			t.Fatal("copied receipt supplied an unsupported claim", field)
		}
	}
}

func FuzzOfflineSetMetadata(f *testing.F) {
	// Parser stand-in only. Full independent journal/creation binding is mandatory
	// after decoding; metadata alone cannot authenticate this synthetic input.
	b := goSetCollectionBinding{Profile: goSetCollectionProfile, Authority: "https://127.0.0.1:38443", SetID: crypt.Digest([]byte("owned-fuzz-set")), Members: make([]collectionMember, 8)}
	r := goSetCollectionReceipt{Binding: b, CollectedGeneration: 1, BytesVerified: true}
	f.Add(collectionJSON(b), collectionJSON(r))
	f.Add([]byte("null\n"), []byte("{}\n"))
	f.Fuzz(func(t *testing.T, bindingRaw, receiptRaw []byte) {
		value, err := parseOfflineSetBinding(bindingRaw)
		if err != nil {
			return
		}
		if len(value.Members) > 773 || len(value.Members) < 8 || !collectionAuthority(value.Authority) || !bytes.Equal(bindingRaw, collectionJSON(value)) {
			t.Fatal("invalid metadata escaped parser bounds")
		}
		completion, err := parseOfflineSetReceipt(receiptRaw, value)
		if err == nil && (completion.CollectedGeneration < 1 || !completion.BytesVerified || completion.CurrentRegistryAdmission || completion.ChecksumAuthority || completion.DependencyClosure || completion.DeliveryVerified || !bytes.Equal(receiptRaw, collectionJSON(completion))) {
			t.Fatal("metadata supplied unsupported completion claims")
		}
	})
}
