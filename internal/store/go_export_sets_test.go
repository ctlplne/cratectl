// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/gomodule"
)

// These are metadata-only parser fixtures, not independently verified package
// bytes or journal signatures. Actual native intake/PG cases are separate.
func exportSetManifestFixture(t testing.TB, count int) GoExportSetManifest {
	t.Helper()
	base, _, _, _ := goExportManifestFixture(t)
	m := GoExportSetManifest{Profile: GoExportSetProfile, Tenant: base.Tenant, PreparedAt: base.PreparedAt, ObservedJournal: base.ObservedJournal, PolicyScope: goExportSetPolicyScope}
	for n := 0; n < count; n++ {
		child := base
		child.Version = fmt.Sprintf("v1.0.%d", n)
		child.Artifacts = append([]GoExportArtifact(nil), base.Artifacts...)
		for k := range child.Artifacts {
			a := &child.Artifacts[k]
			var metadata GoModuleMetadata
			if err := json.Unmarshal(a.Metadata, &metadata); err != nil {
				t.Fatal(err)
			}
			metadata.Version = child.Version
			a.Metadata, _ = json.Marshal(metadata)
			a.Path = (gomodule.Coordinate{Module: child.Module, Version: child.Version}).Prefix() + "." + []string{"zip", "mod", "info"}[k]
			a.Lifecycle.Path = a.Path
			m.DeclaredArtifactBytes += a.Size
		}
		m.Entries = append(m.Entries, child)
	}
	return m
}

func TestGoExportSetRequestCountCoordinateAndResourceBounds(t *testing.T) {
	good := GoExportSetRequest{Entries: []GoExportSetEntry{{Repository: "owned", Module: "go.cratectl.invalid/Owned/set", Version: "v1.0.0"}, {Repository: "other", Module: "go.cratectl.invalid/Owned/set", Version: "v1.0.1"}}, LifetimeSeconds: 60, MaxArtifactBytes: 1 << 30}
	for _, scenario := range []string{"original", "empty", "oversize", "duplicate", "duplicate-other-repository", "bad-repo", "bad-module", "bad-version", "negative-epoch", "short-lifetime", "long-lifetime", "zero-budget", "large-budget"} {
		t.Run(scenario, func(t *testing.T) {
			r := good
			r.Entries = append([]GoExportSetEntry(nil), good.Entries...)
			switch scenario {
			case "empty":
				r.Entries = nil
			case "oversize":
				r.Entries = make([]GoExportSetEntry, MaxGoExportSetEntries+1)
			case "duplicate":
				r.Entries[1] = r.Entries[0]
			case "duplicate-other-repository":
				r.Entries[1].Version = r.Entries[0].Version
			case "bad-repo":
				r.Entries[0].Repository = "Other/tenant"
			case "bad-module":
				r.Entries[0].Module = "../escape"
			case "bad-version":
				r.Entries[0].Version = "latest"
			case "negative-epoch":
				r.Entries[0].ExpectedSourceRevision = -1
			case "short-lifetime":
				r.LifetimeSeconds = 59
			case "long-lifetime":
				r.LifetimeSeconds = 3601
			case "zero-budget":
				r.MaxArtifactBytes = 0
			case "large-budget":
				r.MaxArtifactBytes = MaxGoExportSetArtifactBytes + 1
			}
			err := r.Validate()
			if scenario == "original" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid batch admitted", scenario)
			}
			// Invalid cardinality/request must fail before any database access.
			p, err := new(Store).PlanGoExportSet(context.Background(), Identity{Actor: "owned", Role: "admin"}, r)
			if err == nil || len(p.Bytes()) != 0 {
				t.Fatal("invalid batch returned partial preview")
			}
		})
	}
}

func TestGoExportSetManifestRequiresOneCommonCanonicalSnapshot(t *testing.T) {
	for _, scenario := range []string{"original", "null", "empty", "oversized-raw", "duplicate", "alias", "unknown", "no-newline", "trailing", "null-entries", "empty-entries", "extra-entries", "wrong-profile", "wrong-tenant", "wrong-anchor", "wrong-time", "duplicate-coordinate", "changed-member", "claimed-admission", "claimed-authority", "claimed-closure", "wrong-total", "over-budget"} {
		t.Run(scenario, func(t *testing.T) {
			m := exportSetManifestFixture(t, 2)
			raw, err := m.Bytes()
			if err != nil {
				t.Fatal("owned canonical fixture", err)
			}
			switch scenario {
			case "null":
				raw = []byte("null\n")
			case "empty":
				raw = nil
			case "oversized-raw":
				raw = bytes.Repeat([]byte("x"), MaxGoExportSetManifest+1)
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"profile":`), []byte(`"profile":"ignored","profile":`), 1)
			case "alias":
				raw = bytes.Replace(raw, []byte(`"profile":`), []byte(`"Profile":`), 1)
			case "unknown":
				raw = bytes.Replace(raw, []byte(`"profile":`), []byte(`"unknown":true,"profile":`), 1)
			case "no-newline":
				raw = bytes.TrimSuffix(raw, []byte("\n"))
			case "trailing":
				raw = append(raw, []byte("{}\n")...)
			case "null-entries":
				m.Entries = nil
				raw, _ = json.Marshal(m)
				raw = append(raw, '\n')
			case "empty-entries":
				m.Entries = []GoExportManifest{}
				raw, _ = json.Marshal(m)
				raw = append(raw, '\n')
			case "extra-entries":
				// Count is checked while decoding, before allocating a typed257th root.
				prefix := []byte(`{"profile":"` + GoExportSetProfile + `","entries":[`)
				one, _ := m.Entries[0].Bytes()
				one = bytes.TrimSpace(one)
				members := make([][]byte, MaxGoExportSetEntries+1)
				for n := range members {
					members[n] = one
				}
				raw = append(prefix, bytes.Join(members, []byte(","))...)
				raw = append(raw, []byte("]}\n")...)
			default:
				switch scenario {
				case "wrong-profile":
					m.Profile = "other"
				case "wrong-tenant":
					m.Entries[1].Tenant = "other-team"
				case "wrong-anchor":
					m.Entries[1].ObservedJournal.Sequence = 1
					m.Entries[1].ObservedJournal.Hash = strings.Repeat("a", 64)
				case "wrong-time":
					m.Entries[1].PreparedAt = m.PreparedAt.Add(1)
				case "duplicate-coordinate":
					m.Entries[1] = m.Entries[0]
				case "changed-member":
					m.Entries[1].Artifacts[0].Decision = "denied"
				case "claimed-admission":
					m.CurrentRegistryAdmission = true
				case "claimed-authority":
					m.ChecksumAuthority = true
				case "claimed-closure":
					m.DependencyClosure = true
				case "wrong-total":
					m.DeclaredArtifactBytes++
				case "over-budget":
					m.DeclaredArtifactBytes = MaxGoExportSetArtifactBytes + 1
				}
				raw, _ = json.Marshal(m)
				raw = append(raw, '\n')
			}
			got, err := ParseGoExportSetManifest(raw)
			if scenario == "original" {
				if err != nil || !reflect.DeepEqual(got, m) {
					t.Fatal("common canonical snapshot changed", err)
				}
				return
			}
			if err == nil || got.Profile != "" || len(got.Entries) != 0 {
				t.Fatal("invalid batch exposed partial members", scenario, err)
			}
		})
	}
}

func TestGoExportSetExactMaximumAndPlanCopies(t *testing.T) {
	m := exportSetManifestFixture(t, MaxGoExportSetEntries)
	raw, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseGoExportSetManifest(raw)
	if err != nil || len(got.Entries) != MaxGoExportSetEntries {
		t.Fatal("maximum count rejected", err)
	}
	p := GoExportSetPlan{manifest: m, raw: bytes.Clone(raw)}
	copied := p.Bytes()
	copied[0] ^= 1
	objects := p.Objects()
	if len(objects) != 3*MaxGoExportSetEntries {
		t.Fatal("lost selected object")
	}
	objects[0].Digest = "changed"
	if !bytes.Equal(p.Bytes(), raw) || p.Objects()[0].Digest == "changed" || p.Object().Size != int64(len(raw)) {
		t.Fatal("caller modified immutable plan")
	}
}

func FuzzGoExportSetCanonicalManifest(f *testing.F) {
	m := exportSetManifestFixture(f, 2)
	raw, err := m.Bytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte("null\n"))
	f.Add([]byte(`{"entries":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := ParseGoExportSetManifest(raw)
		if err != nil {
			if m.Profile != "" || len(m.Entries) != 0 {
				t.Fatal("partial manifest after failure")
			}
			return
		}
		canonical, err := m.Bytes()
		if err != nil || !bytes.Equal(canonical, raw) || len(m.Entries) > MaxGoExportSetEntries || m.CurrentRegistryAdmission || m.ChecksumAuthority || m.DependencyClosure {
			t.Fatal("invalid or trusting canonical manifest")
		}
	})
}

func TestGoExportSetMemberPlansRetainCommonIdentityWithoutLendingMutableBytes(t *testing.T) {
	m := exportSetManifestFixture(t, 2)
	raw, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	request := GoExportSetRequest{LifetimeSeconds: 60, MaxArtifactBytes: MaxGoExportSetArtifactBytes}
	for _, e := range m.Entries {
		request.Entries = append(request.Entries, GoExportSetEntry{Repository: e.Repository, Module: e.Module, Version: e.Version, ExpectedSourceRevision: e.SourceRevision})
	}
	p := GoExportSetPlan{tenant: m.Tenant, actor: "owned", request: request, manifest: m, raw: raw}
	members, err := p.Members()
	if err != nil || len(members) != 2 {
		t.Fatal("member decomposition", err)
	}
	for n, member := range members {
		child, err := ParseGoExportManifest(member.Bytes())
		if err != nil || child.ObservedJournal != m.ObservedJournal || !child.PreparedAt.Equal(m.PreparedAt) || member.Coordinate().Version != request.Entries[n].Version || member.tenant != p.tenant || member.actor != p.actor {
			t.Fatal("member lost original common snapshot", err)
		}
	}
	members[0].manifest.Artifacts[0].Metadata[0] ^= 1
	members[0].raw[0] ^= 1
	again, err := p.Members()
	if err != nil || !bytes.Equal(p.Bytes(), raw) || !bytes.Equal(again[0].manifest.Artifacts[0].Metadata, m.Entries[0].Artifacts[0].Metadata) {
		t.Fatal("member lent immutable common storage", err)
	}
	original := goExportSetFingerprint(request)
	for _, scenario := range []string{"order", "revision", "budget", "lifetime"} {
		r := request
		r.Entries = append([]GoExportSetEntry(nil), request.Entries...)
		switch scenario {
		case "order":
			r.Entries[0], r.Entries[1] = r.Entries[1], r.Entries[0]
		case "revision":
			r.Entries[1].ExpectedSourceRevision++
		case "budget":
			r.MaxArtifactBytes--
		case "lifetime":
			r.LifetimeSeconds++
		}
		if goExportSetFingerprint(r) == original {
			t.Fatal("idempotency omitted caller intent", scenario)
		}
	}
}
