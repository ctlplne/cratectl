// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

func exportIndexUnitFixture(t *testing.T, count int) (goExportIndex, []crypt.JournalEvent, map[string][]byte) {
	t.Helper()
	publication, files := offlineGoFiles(t)
	index := goExportIndex{Profile: goExportIndexProfile}
	events := make([]crypt.JournalEvent, 0, count)
	manifests := map[string][]byte{}
	for n := 0; n < count; n++ {
		c := gomodule.Coordinate{Module: publication.Coordinate.Module, Version: fmt.Sprintf("v1.0.%d", n)}
		entry := goExportIndexEntry{Repository: publication.Repository, Module: c.Module, Version: c.Version, ExportID: crypt.Digest([]byte(fmt.Sprintf("owned-export/%d", n))), EventSequence: int64(n + 1), ManifestFile: filepath.Join(t.TempDir(), "manifest.json")}
		m := store.GoExportManifest{Profile: store.GoExportProfile, Tenant: publication.Tenant, Repository: entry.Repository, Module: c.Module, Version: c.Version, RequireReview: true, Access: "restricted", PreparedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), ObservedJournal: crypt.JournalAnchor{Tenant: publication.Tenant}, PolicyScope: "historical source decisions; not destination admission"}
		metadata, _ := json.Marshal(store.GoModuleMetadata{Profile: store.GoModuleProfile, Module: c.Module, Version: c.Version, Digests: map[string]string{"zip": publication.ZIP, "mod": publication.Mod, "info": publication.Info}})
		for k, kind := range []string{"zip", "mod", "info"} {
			p := c.Prefix() + "." + kind
			m.Artifacts = append(m.Artifacts, store.GoExportArtifact{Path: p, Digest: crypt.Digest(files[k]), Size: int64(len(files[k])), MediaType: []string{"application/zip", "text/plain; charset=utf-8", "application/json"}[k], Metadata: metadata, CreatedAt: m.PreparedAt, Decision: "allowed", DecisionVersion: 1, Lifecycle: store.ArtifactState{Repository: m.Repository, Path: p}})
		}
		raw, err := m.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(map[string]any{"tenant": m.Tenant, "sequence": entry.EventSequence, "kind": "go.export.created", "data": map[string]any{"id": entry.ExportID, "repository": m.Repository, "module": m.Module, "version": m.Version, "source_revision": m.SourceRevision, "manifest": blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}, "created_sequence": entry.EventSequence}})
		event := crypt.JournalEvent{Sequence: entry.EventSequence, Payload: string(payload)}
		if n > 0 {
			event.PreviousHash = events[n-1].Hash
		}
		event.Hash = crypt.Digest([]byte(event.PreviousHash + "\n" + event.Payload))
		index.Entries = append(index.Entries, entry)
		events = append(events, event)
		manifests[entry.ManifestFile] = raw
	}
	return index, events, manifests
}

func encodeExportIndex(t testing.TB, index goExportIndex) []byte {
	t.Helper()
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func TestExportIndexCanonicalShapeAndPreflightBounds(t *testing.T) {
	base, _, _ := exportIndexUnitFixture(t, 2)
	for _, scenario := range []string{"original", "empty", "null", "duplicate-field", "alias", "unknown", "trailing", "no-newline", "oversize", "wrong-profile", "no-entries", "too-many", "duplicate-coordinate", "duplicate-export", "duplicate-event", "bad-module", "bad-version", "bad-repo", "bad-id", "zero-event", "relative-path", "unclean-path", "long-path"} {
		t.Run(scenario, func(t *testing.T) {
			index := base
			index.Entries = append([]goExportIndexEntry(nil), base.Entries...)
			raw := encodeExportIndex(t, index)
			switch scenario {
			case "empty":
				raw = nil
			case "null":
				raw = []byte("null\n")
			case "duplicate-field":
				raw = bytes.Replace(raw, []byte(`"profile":`), []byte(`"profile":"ignored","profile":`), 1)
			case "alias":
				raw = bytes.Replace(raw, []byte(`"profile":`), []byte(`"Profile":`), 1)
			case "unknown":
				raw = bytes.Replace(raw, []byte(`"profile":`), []byte(`"extra":true,"profile":`), 1)
			case "trailing":
				raw = append(raw, []byte("{}\n")...)
			case "no-newline":
				raw = bytes.TrimSuffix(raw, []byte("\n"))
			case "oversize":
				raw = bytes.Repeat([]byte("x"), maxGoExportIndexBytes+1)
			default:
				switch scenario {
				case "wrong-profile":
					index.Profile = "unknown"
				case "no-entries":
					index.Entries = nil
				case "too-many":
					index.Entries = make([]goExportIndexEntry, crypt.MaxJournalSelectedEvents+1)
				case "duplicate-coordinate":
					index.Entries[1].Version = index.Entries[0].Version
				case "duplicate-export":
					index.Entries[1].ExportID = index.Entries[0].ExportID
				case "duplicate-event":
					index.Entries[1].EventSequence = index.Entries[0].EventSequence
				case "bad-module":
					index.Entries[0].Module = "../escape"
				case "bad-version":
					index.Entries[0].Version = "latest"
				case "bad-repo":
					index.Entries[0].Repository = "Other/tenant"
				case "bad-id":
					index.Entries[0].ExportID = "invalid"
				case "zero-event":
					index.Entries[0].EventSequence = 0
				case "relative-path":
					index.Entries[0].ManifestFile = "manifest.json"
				case "unclean-path":
					index.Entries[0].ManifestFile = "/owned/../manifest.json"
				case "long-path":
					index.Entries[0].ManifestFile = "/" + strings.Repeat("x", 4096)
				}
				raw = encodeExportIndex(t, index)
			}
			got, err := parseGoExportIndex(raw)
			if scenario == "original" {
				if err != nil || !reflect.DeepEqual(got, base) {
					t.Fatal("canonical index changed", err)
				}
			} else if err == nil || got.Profile != "" || len(got.Entries) != 0 {
				t.Fatal("invalid index returned partial members", scenario, err)
			}
		})
	}
}

func TestExportIndexAllBindingsOrNoPartialResult(t *testing.T) {
	for _, scenario := range []string{"original", "exact-byte-budget", "reversed-order", "last-manifest-changed", "last-event-changed", "wrong-order", "wrong-tenant", "missing-manifest", "over-byte-budget", "zero-byte-budget", "oversize-budget", "missing-event", "cancelled", "cancelled-late"} {
		t.Run(scenario, func(t *testing.T) {
			index, events, files := exportIndexUnitFixture(t, 2)
			tenant := "owned-team"
			maximum := int64(1 << 30)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var expected int64
			for _, raw := range files {
				m, err := store.ParseGoExportManifest(raw)
				if err != nil {
					t.Fatal(err)
				}
				for _, a := range m.Artifacts {
					expected += a.Size
				}
			}
			switch scenario {
			case "reversed-order":
				index.Entries[0], index.Entries[1] = index.Entries[1], index.Entries[0]
				events[0], events[1] = events[1], events[0]
			case "last-manifest-changed":
				files[index.Entries[1].ManifestFile] = append(files[index.Entries[1].ManifestFile], []byte("{}")...)
			case "last-event-changed":
				events[1].Hash = strings.Repeat("a", 64)
			case "wrong-order":
				events[0], events[1] = events[1], events[0]
			case "wrong-tenant":
				tenant = "other-team"
			case "missing-manifest":
				delete(files, index.Entries[1].ManifestFile)
			case "exact-byte-budget":
				maximum = expected
			case "over-byte-budget":
				maximum = expected - 1
			case "zero-byte-budget":
				maximum = 0
			case "oversize-budget":
				maximum = crypt.MaxJournalInputBytes + 1
			case "missing-event":
				events = events[:1]
			case "cancelled":
				cancel()
			}
			read := func(name string) ([]byte, error) {
				if scenario == "cancelled-late" && name == index.Entries[1].ManifestFile {
					cancel()
				}
				raw, ok := files[name]
				if !ok {
					return nil, errors.New("owned absent manifest")
				}
				return bytes.Clone(raw), nil
			}
			got, total, err := bindGoExportIndex(ctx, index, tenant, events, read, maximum)
			if scenario != "original" && scenario != "reversed-order" && scenario != "exact-byte-budget" {
				if err == nil || got != nil || total != 0 {
					t.Fatal("invalid later member returned partial bindings", err, total)
				}
				return
			}
			if err != nil || total != expected || len(got) != 2 {
				t.Fatal("exact selected manifests rejected", err, total)
			}
			for n, binding := range got {
				entry := index.Entries[n]
				if binding.EventSequence != events[n].Sequence || binding.EventHash != events[n].Hash || binding.ManifestSHA256 != crypt.Digest(files[entry.ManifestFile]) || binding.ManifestBytes != len(files[entry.ManifestFile]) || binding.ExportID != entry.ExportID {
					t.Fatal("original order/identity changed")
				}
			}
			raw, _ := json.Marshal(got)
			if bytes.Contains(raw, []byte(index.Entries[0].ManifestFile)) || bytes.Contains(raw, []byte("metadata")) {
				t.Fatal("index binding exposed private path/policy body")
			}
		})
	}
}

func TestExportIndexCommandRejectsIncompleteTrustWithoutReceipt(t *testing.T) {
	fixture := journalSignedCLI(t)
	index, _, manifests := exportIndexUnitFixture(t, 1)
	for name, raw := range manifests {
		if err := os.WriteFile(name, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	for name, raw := range map[string][]byte{"index": encodeExportIndex(t, index), "journal": fixture.Export, "statement": fixture.Statement, "signature": fixture.Signature, "key": fixture.PublicKey} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	base := []string{"--index-file", filepath.Join(dir, "index"), "--journal-file", filepath.Join(dir, "journal"), "--journal-tenant", fixture.Head.Tenant, "--journal-through", strconv.FormatInt(fixture.Head.Sequence, 10), "--journal-through-hash", fixture.Head.Hash}
	trust := []string{"--checkpoint-file", filepath.Join(dir, "statement"), "--checkpoint-signature-file", filepath.Join(dir, "signature"), "--checkpoint-key-file", filepath.Join(dir, "key")}
	for _, scenario := range []string{"no-input", "missing-signature", "wrong-event-kind", "single-selector", "trailing-journal", "public-index", "symlink-index", "zero-budget"} {
		t.Run(scenario, func(t *testing.T) {
			args := append([]string(nil), base...)
			if scenario != "missing-signature" {
				args = append(args, trust...)
			}
			switch scenario {
			case "no-input":
				args = nil
			case "single-selector":
				args = append(args, "--journal-event-sequence", "1")
			case "zero-budget":
				args = append(args, "--max-artifact-bytes", "0")
			case "trailing-journal":
				p := filepath.Join(dir, "trailing")
				if err := os.WriteFile(p, append(bytes.Clone(fixture.Export), []byte("{}\n")...), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--journal-file", p)
			case "public-index":
				p := filepath.Join(dir, "public")
				if err := os.WriteFile(p, encodeExportIndex(t, index), 0644); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--index-file", p)
			case "symlink-index":
				p := filepath.Join(dir, "link")
				if err := os.Symlink(filepath.Join(dir, "index"), p); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--index-file", p)
			}
			var out bytes.Buffer
			if err := runGoExportIndexVerify(args, &out); err == nil || out.Len() != 0 {
				t.Fatal("incomplete/foreign trust returned a receipt", scenario, err)
			}
		})
	}
}

func TestExportIndexExactMaximumMemberCount(t *testing.T) {
	index, events, files := exportIndexUnitFixture(t, crypt.MaxJournalSelectedEvents)
	raw := encodeExportIndex(t, index)
	parsed, err := parseGoExportIndex(raw)
	if err != nil || len(parsed.Entries) != crypt.MaxJournalSelectedEvents {
		t.Fatal("exact count refused", err, len(raw))
	}
	got, _, err := bindGoExportIndex(context.Background(), parsed, "owned-team", events, func(name string) ([]byte, error) { return bytes.Clone(files[name]), nil }, 1<<30)
	if err != nil || len(got) != crypt.MaxJournalSelectedEvents {
		t.Fatal("maximum bindings refused", err)
	}
}

func FuzzGoExportIndexCanonical(f *testing.F) {
	f.Add(encodeExportIndex(f, goExportIndex{Profile: goExportIndexProfile, Entries: []goExportIndexEntry{{Repository: "owned", Module: "go.cratectl.invalid/Owned/index", Version: "v1.0.0", ExportID: strings.Repeat("a", 64), EventSequence: 1, ManifestFile: "/owned/manifest.json"}}}))
	f.Add([]byte(`{}`))
	f.Add([]byte("null\n"))
	f.Add([]byte(`{"profile":"cratectl.go.export.index.v1","entries":[]}` + "\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		index, err := parseGoExportIndex(raw)
		if err != nil {
			if index.Profile != "" || len(index.Entries) != 0 {
				t.Fatal("invalid index retained partial members")
			}
			return
		}
		if len(index.Entries) < 1 || len(index.Entries) > crypt.MaxJournalSelectedEvents || !bytes.Equal(encodeExportIndex(t, index), raw) {
			t.Fatal("invalid canonical bound")
		}
	})
}
