// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
)

func goExportManifestFixture(t testing.TB) (GoExportManifest, []byte, string, crypt.JournalEvent) {
	t.Helper()
	as := goArtifactFixture()
	meta, err := ValidateGoModuleArtifact(as[0])
	if err != nil {
		t.Fatal(err)
	}
	m := GoExportManifest{Profile: GoExportProfile, Tenant: "export-team", Repository: "owned", Module: meta.Module, Version: meta.Version, RequireReview: true, Access: "restricted", PreparedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), ObservedJournal: crypt.JournalAnchor{Tenant: "export-team"}, PolicyScope: "historical source decisions; not destination admission"}
	for n, a := range as {
		m.Artifacts = append(m.Artifacts, GoExportArtifact{Path: a.Path, Digest: a.Digest, Size: int64(n + 1), MediaType: a.MediaType, Metadata: bytes.Clone(a.Metadata), CreatedAt: m.PreparedAt, Decision: "allowed", DecisionVersion: 1, Lifecycle: ArtifactState{Repository: m.Repository, Path: a.Path}})
	}
	raw, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("d", 64)
	payload, err := json.Marshal(map[string]any{"tenant": m.Tenant, "sequence": 7, "kind": "go.export.created", "data": map[string]any{"id": id, "repository": m.Repository, "module": m.Module, "version": m.Version, "source_revision": m.SourceRevision, "manifest": blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}, "created_sequence": 7}})
	if err != nil {
		t.Fatal(err)
	}
	event := crypt.JournalEvent{Sequence: 7, Payload: string(payload), PreviousHash: strings.Repeat("e", 64)}
	event.Hash = crypt.Digest([]byte(event.PreviousHash + "\n" + event.Payload))
	return m, raw, id, event
}

func TestGoExportManifestCanonicalShapeAndHistoricalPolicy(t *testing.T) {
	for _, scenario := range []string{"original", "duplicate", "alias", "unknown", "null", "trailing", "no-newline", "invalid-json", "oversize", "wrong-profile", "claimed-admission", "claimed-authority", "claimed-closure", "wrong-order", "missing-item", "wrong-path", "wrong-media", "bad-digest", "big-zip", "big-mod", "big-info", "big-metadata", "wrong-bundle", "denied", "missing-approval", "invalid-policy-version", "wrong-lifecycle", "deleted", "big-actor", "wrong-anchor"} {
		t.Run(scenario, func(t *testing.T) {
			m, raw, _, _ := goExportManifestFixture(t)
			encoded := false
			switch scenario {
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"profile":`), []byte(`"profile":"ignored","profile":`), 1)
			case "alias":
				raw = bytes.Replace(raw, []byte(`"profile":`), []byte(`"Profile":`), 1)
			case "unknown":
				raw = bytes.Replace(raw, []byte(`"profile":`), []byte(`"unknown":true,"profile":`), 1)
			case "null":
				raw = bytes.Replace(raw, []byte(`"require_review":true`), []byte(`"require_review":null`), 1)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "no-newline":
				raw = bytes.TrimSuffix(raw, []byte("\n"))
			case "invalid-json":
				raw = []byte("not-json")
			case "oversize":
				raw = bytes.Repeat([]byte("x"), MaxGoExportManifest+1)
			default:
				encoded = true
				switch scenario {
				case "wrong-profile":
					m.Profile = "other"
				case "claimed-admission":
					m.CurrentRegistryAdmission = true
				case "claimed-authority":
					m.ChecksumAuthority = true
				case "claimed-closure":
					m.DependencyClosure = true
				case "wrong-order":
					m.Artifacts[0], m.Artifacts[1] = m.Artifacts[1], m.Artifacts[0]
				case "missing-item":
					m.Artifacts = m.Artifacts[:2]
				case "wrong-path":
					m.Artifacts[0].Path += "/other"
				case "wrong-media":
					m.Artifacts[0].MediaType = "text/html"
				case "bad-digest":
					m.Artifacts[0].Digest = "bad"
				case "big-zip":
					m.Artifacts[0].Size = 512<<20 + 1
				case "big-mod":
					m.Artifacts[1].Size = gomodule.MaxGoMod + 1
				case "big-info":
					m.Artifacts[2].Size = gomodule.MaxVersionInfo + 1
				case "big-metadata":
					m.Artifacts[0].Metadata = json.RawMessage(`{"padding":"` + strings.Repeat("x", MaxGoModuleMetadata) + `"}`)
				case "wrong-bundle":
					m.Artifacts[0].Metadata = json.RawMessage(`{}`)
				case "denied":
					m.Artifacts[0].Decision = "denied"
				case "missing-approval":
					m.Artifacts[0].Decision = "unassessed"
				case "invalid-policy-version":
					m.Artifacts[0].DecisionVersion = -1
				case "wrong-lifecycle":
					m.Artifacts[0].Lifecycle.Path = "other"
				case "deleted":
					m.Artifacts[0].Lifecycle.Deleted = true
				case "big-actor":
					m.Artifacts[0].Lifecycle.Actor = strings.Repeat("x", 257)
				case "wrong-anchor":
					m.ObservedJournal.Tenant = "other"
				}
			}
			if encoded {
				var err error
				raw, err = json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				raw = append(raw, '\n')
			}
			got, err := ParseGoExportManifest(raw)
			if scenario == "original" {
				if err != nil || !reflect.DeepEqual(got, m) {
					t.Fatal("original canonical manifest rejected", err)
				}
			} else if err == nil || got.Profile != "" {
				t.Fatal("invalid manifest exposed partial historical policy", scenario, err)
			}
		})
	}
}

func TestGoExportManifestBindsExactOriginalCreationEvent(t *testing.T) {
	for _, scenario := range []string{"original", "wrong-tenant", "wrong-repository", "wrong-coordinate", "wrong-id", "wrong-kind", "wrong-source", "wrong-sequence", "wrong-digest", "wrong-size", "duplicate-manifest", "manifest-alias", "missing-digest", "changed-link", "changed-manifest"} {
		t.Run(scenario, func(t *testing.T) {
			m, raw, id, event := goExportManifestFixture(t)
			tenant, repo, c := m.Tenant, m.Repository, gomodule.Coordinate{Module: m.Module, Version: m.Version}
			rehash := true
			switch scenario {
			case "wrong-tenant":
				tenant = "other"
			case "wrong-repository":
				repo = "other"
			case "wrong-coordinate":
				c.Version = "v1.1.0"
			case "wrong-id":
				id = strings.Repeat("a", 64)
			case "wrong-kind":
				event.Payload = strings.Replace(event.Payload, "go.export.created", "go.export.changed", 1)
			case "wrong-source":
				event.Payload = strings.Replace(event.Payload, `"source_revision":0`, `"source_revision":1`, 1)
			case "wrong-sequence":
				event.Payload = strings.Replace(event.Payload, `"created_sequence":7`, `"created_sequence":8`, 1)
			case "wrong-digest":
				event.Payload = strings.Replace(event.Payload, crypt.Digest(raw), strings.Repeat("a", 64), 1)
			case "wrong-size":
				event.Payload = strings.Replace(event.Payload, `"size":`, `"size":1,"ignored_size":`, 1)
			case "duplicate-manifest":
				event.Payload = strings.Replace(event.Payload, `"manifest":`, `"manifest":{},"manifest":`, 1)
			case "manifest-alias":
				event.Payload = strings.Replace(event.Payload, `"manifest":`, `"Manifest":{},"manifest":`, 1)
			case "missing-digest":
				event.Payload = strings.Replace(event.Payload, `"digest":`, `"omitted":`, 1)
			case "changed-link":
				event.Hash = strings.Repeat("f", 64)
				rehash = false
			case "changed-manifest":
				raw = bytes.Replace(raw, []byte(`"decision_version":1`), []byte(`"decision_version":2`), 1)
			}
			if rehash {
				event.Hash = crypt.Digest([]byte(event.PreviousHash + "\n" + event.Payload))
			}
			got, err := BindGoExportManifest(raw, tenant, repo, id, c, event)
			if scenario == "original" {
				if err != nil || !reflect.DeepEqual(got, m) {
					t.Fatal(err)
				}
			} else if err == nil || got.Profile != "" {
				t.Fatal("detached manifest admitted", scenario, err)
			}
		})
	}
}

func FuzzGoExportManifest(f *testing.F) {
	m, raw, id, event := goExportManifestFixture(f)
	f.Add(raw)
	f.Add([]byte(`{"profile":null}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 64<<10 {
			return
		}
		got, err := ParseGoExportManifest(body)
		if err == nil {
			canonical, e := got.Bytes()
			if e != nil || !bytes.Equal(canonical, body) {
				t.Fatal("accepted ambiguous manifest")
			}
		} else if got.Profile != "" {
			t.Fatal("partial manifest")
		}
		bound, err := BindGoExportManifest(body, m.Tenant, m.Repository, id, gomodule.Coordinate{Module: m.Module, Version: m.Version}, event)
		if err == nil && (crypt.Digest(body) != crypt.Digest(raw) || bound.Profile != GoExportProfile) {
			t.Fatal("detached bytes attributed")
		}
	})
}
