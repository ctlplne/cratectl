// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

const GoExportSetProfile = "cratectl.go.hosted.export-set.v1"
const MaxGoExportSetEntries = 256
const MaxGoExportSetRequest = 256 << 10
const MaxGoExportSetManifest = 8 << 20
const MaxGoExportSetArtifactBytes int64 = 64 << 30
const goExportSetPolicyScope = "historical explicitly selected source decisions; not dependency closure or destination admission"

var ErrGoExportSetInput = errors.New("invalid bounded hosted Go export selection")
var ErrGoExportSetChanged = errors.New("hosted Go export selection source changed")
var ErrGoExportSetBudget = errors.New("hosted Go export selection exceeds its byte budget")

type GoExportSetEntry struct {
	Repository             string `json:"repository"`
	Module                 string `json:"module"`
	Version                string `json:"version"`
	ExpectedSourceRevision int64  `json:"expected_source_revision"`
}
type GoExportSetRequest struct {
	Entries          []GoExportSetEntry `json:"entries"`
	LifetimeSeconds  int                `json:"lifetime_seconds"`
	MaxArtifactBytes int64              `json:"max_artifact_bytes"`
}

func (r GoExportSetRequest) Validate() error {
	if len(r.Entries) < 1 || len(r.Entries) > MaxGoExportSetEntries || r.LifetimeSeconds < 60 || r.LifetimeSeconds > 3600 || r.MaxArtifactBytes < 1 || r.MaxArtifactBytes > MaxGoExportSetArtifactBytes {
		return ErrGoExportSetInput
	}
	seen := make(map[gomodule.Coordinate]bool, len(r.Entries))
	for _, entry := range r.Entries {
		c, err := gomodule.Canonical(entry.Module, entry.Version)
		if err != nil || !Name.MatchString(entry.Repository) || entry.ExpectedSourceRevision < 0 || seen[c] {
			return ErrGoExportSetInput
		}
		seen[c] = true
	}
	return nil
}

// A preview is unsigned. A shared database observation is not physical-byte
// verification, a durable export session, dependency closure or admission.
type GoExportSetManifest struct {
	Profile                  string              `json:"profile"`
	Tenant                   string              `json:"tenant"`
	PreparedAt               time.Time           `json:"prepared_at"`
	ObservedJournal          crypt.JournalAnchor `json:"observed_journal"`
	Entries                  []GoExportManifest  `json:"entries"`
	DeclaredArtifactBytes    int64               `json:"declared_artifact_bytes"`
	PolicyScope              string              `json:"policy_scope"`
	CurrentRegistryAdmission bool                `json:"current_registry_admission"`
	ChecksumAuthority        bool                `json:"checksum_authority_verified"`
	DependencyClosure        bool                `json:"dependency_closure"`
}

func (m GoExportSetManifest) validate() error {
	if m.Profile != GoExportSetProfile || !Name.MatchString(m.Tenant) || m.PreparedAt.IsZero() || !m.ObservedJournal.Valid() || m.ObservedJournal.Tenant != m.Tenant || len(m.Entries) < 1 || len(m.Entries) > MaxGoExportSetEntries || m.PolicyScope != goExportSetPolicyScope || m.CurrentRegistryAdmission || m.ChecksumAuthority || m.DependencyClosure {
		return ErrGoExportSetInput
	}
	seen := make(map[gomodule.Coordinate]bool, len(m.Entries))
	var total int64
	for _, entry := range m.Entries {
		c := gomodule.Coordinate{Module: entry.Module, Version: entry.Version}
		raw, err := entry.Bytes()
		if err != nil || len(raw) > MaxGoExportManifest || entry.Tenant != m.Tenant || !entry.PreparedAt.Equal(m.PreparedAt) || entry.ObservedJournal != m.ObservedJournal || seen[c] {
			return ErrGoExportSetInput
		}
		seen[c] = true
		for _, a := range entry.Artifacts {
			if a.Size > MaxGoExportSetArtifactBytes-total {
				return ErrGoExportSetBudget
			}
			total += a.Size
		}
	}
	if total != m.DeclaredArtifactBytes {
		return ErrGoExportSetInput
	}
	return nil
}

func (m GoExportSetManifest) Bytes() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw)+1 > MaxGoExportSetManifest {
		return nil, ErrGoExportSetBudget
	}
	return append(raw, '\n'), nil
}

func ParseGoExportSetManifest(raw []byte) (GoExportSetManifest, error) {
	// Bound cardinality before allocating typed roots. Decoding the entire8MiB
	// array into structs first would allow millions of empty objects to allocate
	// hundreds of MiB before the member limit was checked.
	var m GoExportSetManifest
	if len(raw) < 1 || len(raw) > MaxGoExportSetManifest {
		return m, ErrGoExportSetInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return GoExportSetManifest{}, ErrGoExportSetInput
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return GoExportSetManifest{}, ErrGoExportSetInput
		}
		seen[name] = true
		if name == "entries" {
			token, err = d.Token()
			if err != nil || token != json.Delim('[') {
				return GoExportSetManifest{}, ErrGoExportSetInput
			}
			for d.More() {
				if len(m.Entries) >= MaxGoExportSetEntries {
					return GoExportSetManifest{}, ErrGoExportSetInput
				}
				var member json.RawMessage
				if d.Decode(&member) != nil || len(member)+1 > MaxGoExportManifest {
					return GoExportSetManifest{}, ErrGoExportSetInput
				}
				child, err := ParseGoExportManifest(append(member, '\n'))
				if err != nil {
					return GoExportSetManifest{}, ErrGoExportSetInput
				}
				m.Entries = append(m.Entries, child)
			}
			token, err = d.Token()
			if err != nil || token != json.Delim(']') {
				return GoExportSetManifest{}, ErrGoExportSetInput
			}
			continue
		}
		var target any
		switch name {
		case "profile":
			target = &m.Profile
		case "tenant":
			target = &m.Tenant
		case "prepared_at":
			target = &m.PreparedAt
		case "observed_journal":
			target = &m.ObservedJournal
		case "declared_artifact_bytes":
			target = &m.DeclaredArtifactBytes
		case "policy_scope":
			target = &m.PolicyScope
		case "current_registry_admission":
			target = &m.CurrentRegistryAdmission
		case "checksum_authority_verified":
			target = &m.ChecksumAuthority
		case "dependency_closure":
			target = &m.DependencyClosure
		default:
			return GoExportSetManifest{}, ErrGoExportSetInput
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || len(value) > 4096 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, target) != nil {
			return GoExportSetManifest{}, ErrGoExportSetInput
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(seen) != 10 {
		return GoExportSetManifest{}, ErrGoExportSetInput
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return GoExportSetManifest{}, ErrGoExportSetInput
	}
	canonical, err := m.Bytes()
	if err != nil {
		return GoExportSetManifest{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return GoExportSetManifest{}, ErrGoExportSetInput
	}
	return m, nil
}

type GoExportSetPlan struct {
	tenant, actor string
	request       GoExportSetRequest
	manifest      GoExportSetManifest
	raw           []byte
}

func (p GoExportSetPlan) Bytes() []byte { return bytes.Clone(p.raw) }
func (p GoExportSetPlan) Object() blob.Object {
	return blob.Object{Digest: crypt.Digest(p.raw), Size: int64(len(p.raw))}
}
func (p GoExportSetPlan) Objects() []blob.Object {
	var out []blob.Object
	for _, entry := range p.manifest.Entries {
		for _, a := range entry.Artifacts {
			out = append(out, blob.Object{Digest: a.Digest, Size: a.Size})
		}
	}
	return out
}

// All roots use this one caller-owned transaction, clock observation and journal
// head. Calling PlanGoExport separately for each root would mix snapshots.
func planGoExportSetInTx(ctx context.Context, tx pgx.Tx, i Identity, r GoExportSetRequest) (GoExportSetPlan, error) {
	if r.Validate() != nil {
		return GoExportSetPlan{}, ErrGoExportSetInput
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return GoExportSetPlan{}, err
	}
	anchor := crypt.JournalAnchor{Tenant: i.Tenant}
	err := tx.QueryRow(ctx, `SELECT sequence,hash FROM cratectl.events ORDER BY sequence DESC LIMIT 1`).Scan(&anchor.Sequence, &anchor.Hash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return GoExportSetPlan{}, err
	}
	m := GoExportSetManifest{Profile: GoExportSetProfile, Tenant: i.Tenant, PreparedAt: now.UTC(), ObservedJournal: anchor, PolicyScope: goExportSetPolicyScope}
	var metadataBytes int
	for _, entry := range r.Entries {
		if err := ctx.Err(); err != nil {
			return GoExportSetPlan{}, err
		}
		one := GoExportRequest{Repository: entry.Repository, Module: entry.Module, Version: entry.Version, ExpectedSourceRevision: entry.ExpectedSourceRevision, LifetimeSeconds: r.LifetimeSeconds}
		member, err := goExportManifestInTx(ctx, tx, i, one, m.PreparedAt, anchor)
		if errors.Is(err, ErrSourceChanged) {
			return GoExportSetPlan{}, ErrGoExportSetChanged
		}
		if errors.Is(err, ErrGoExportInput) {
			return GoExportSetPlan{}, ErrGoExportSetInput
		}
		if err != nil {
			return GoExportSetPlan{}, err
		}
		raw, err := member.Bytes()
		if err != nil {
			return GoExportSetPlan{}, err
		}
		metadataBytes += len(raw)
		if metadataBytes > MaxGoExportSetManifest {
			return GoExportSetPlan{}, ErrGoExportSetBudget
		}
		for _, a := range member.Artifacts {
			if a.Size > r.MaxArtifactBytes-m.DeclaredArtifactBytes {
				return GoExportSetPlan{}, ErrGoExportSetBudget
			}
			m.DeclaredArtifactBytes += a.Size
		}
		m.Entries = append(m.Entries, member)
	}
	raw, err := m.Bytes()
	if err != nil {
		return GoExportSetPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return GoExportSetPlan{}, err
	}
	r.Entries = append([]GoExportSetEntry(nil), r.Entries...)
	return GoExportSetPlan{tenant: i.Tenant, actor: i.Actor, request: r, manifest: m, raw: raw}, nil
}

// Metadata-only planning. It opens no object, stages nothing and creates no
// reference/event/session/receipt/job. The existing Tx read path enforces tenant
// RLS, current identity at admission and one repeatable-read/read-only snapshot.
func (s *Store) PlanGoExportSet(ctx context.Context, i Identity, r GoExportSetRequest) (GoExportSetPlan, error) {
	if len(r.Entries) < 1 || len(r.Entries) > MaxGoExportSetEntries {
		return GoExportSetPlan{}, ErrGoExportSetInput
	}
	r.Entries = append([]GoExportSetEntry(nil), r.Entries...)
	if r.Validate() != nil || i.Actor == "" || len(i.Actor) > 256 || !utf8.ValidString(i.Actor) || strings.ContainsFunc(i.Actor, unicode.IsControl) {
		return GoExportSetPlan{}, ErrGoExportSetInput
	}
	if i.Role != "admin" {
		return GoExportSetPlan{}, ErrDenied
	}
	// Bound the complete metadata transaction, not just each SQL statement.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var plan GoExportSetPlan
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error { var err error; plan, err = planGoExportSetInTx(ctx, tx, i, r); return err })
	if err != nil {
		return GoExportSetPlan{}, err
	}
	return plan, nil
}
