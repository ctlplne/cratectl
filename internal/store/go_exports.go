// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

type GoExportRequest struct {
	Repository             string `json:"repository"`
	Module                 string `json:"module"`
	Version                string `json:"version"`
	ExpectedSourceRevision int64  `json:"expected_source_revision"`
	LifetimeSeconds        int    `json:"lifetime_seconds"`
}

func (r GoExportRequest) Validate() error {
	_, err := gomodule.Canonical(r.Module, r.Version)
	if err != nil || !Name.MatchString(r.Repository) || r.ExpectedSourceRevision < 0 || r.LifetimeSeconds < 60 || r.LifetimeSeconds > 3600 {
		return ErrGoExportInput
	}
	return nil
}

func exportMutationKey(key string) bool {
	return key != "" && len(key) <= 200 && utf8.ValidString(key) && !strings.ContainsFunc(key, unicode.IsControl)
}

func ValidGoExportID(id string) bool { return uploadDigest.MatchString(id) }
func goExportFingerprint(r GoExportRequest) string {
	raw, _ := json.Marshal(r)
	return crypt.Digest(append([]byte("go.export.create\x00"), raw...))
}

type GoExportPlan struct {
	tenant, actor string
	request       GoExportRequest
	manifest      GoExportManifest
	raw           []byte
}

func (p GoExportPlan) Bytes() []byte { return bytes.Clone(p.raw) }
func (p GoExportPlan) Object() blob.Object {
	return blob.Object{Digest: crypt.Digest(p.raw), Size: int64(len(p.raw))}
}
func (p GoExportPlan) Coordinate() gomodule.Coordinate {
	return gomodule.Coordinate{Module: p.request.Module, Version: p.request.Version}
}
func (p GoExportPlan) Objects() [3]blob.Object {
	var out [3]blob.Object
	if len(p.manifest.Artifacts) == 3 {
		for n, a := range p.manifest.Artifacts {
			out[n] = blob.Object{Digest: a.Digest, Size: a.Size}
		}
	}
	return out
}

type GoExportSession struct {
	ID                  string      `json:"id"`
	Repository          string      `json:"repository"`
	SourceRevision      int64       `json:"source_revision"`
	Module              string      `json:"module"`
	Version             string      `json:"version"`
	Actor               string      `json:"actor"`
	Manifest            blob.Object `json:"manifest"`
	State               string      `json:"state"`
	Generation          int64       `json:"generation"`
	CreatedSequence     int64       `json:"created_sequence"`
	ChangeSequence      int64       `json:"change_sequence"`
	CreatedAt           time.Time   `json:"created_at"`
	ChangedAt           time.Time   `json:"changed_at"`
	ExpiresAt           time.Time   `json:"expires_at"`
	MaxExpiresAt        time.Time   `json:"max_expires_at"`
	ServerTime          time.Time   `json:"server_time"`
	DeliveryVerified    bool        `json:"delivery_verified"`
	PayloadPinsRetained bool        `json:"payload_pins_retained"`
	ManifestRetained    bool        `json:"manifest_retained"`
}

const goExportColumns = `id,repository,source_revision,module,version,left(actor,257),manifest_digest,manifest_size,state,generation,created_sequence,change_sequence,created_at,changed_at,expires_at,max_expires_at,clock_timestamp()`

func scanGoExport(row pgx.Row) (GoExportSession, error) {
	var s GoExportSession
	err := row.Scan(&s.ID, &s.Repository, &s.SourceRevision, &s.Module, &s.Version, &s.Actor, &s.Manifest.Digest, &s.Manifest.Size, &s.State, &s.Generation, &s.CreatedSequence, &s.ChangeSequence, &s.CreatedAt, &s.ChangedAt, &s.ExpiresAt, &s.MaxExpiresAt, &s.ServerTime)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	if err != nil {
		return s, err
	}
	if !uploadDigest.MatchString(s.ID) || !uploadDigest.MatchString(s.Manifest.Digest) || s.Manifest.Size < 1 || s.Manifest.Size > MaxGoExportManifest || len(s.Actor) > 256 || s.Generation < 1 {
		return GoExportSession{}, ErrGoExportChanged
	}
	s.ManifestRetained = true
	s.PayloadPinsRetained = s.State == "open" || s.State == "acknowledged"
	if s.PayloadPinsRetained && !s.ExpiresAt.After(s.ServerTime) {
		s.State = "expired_unreconciled"
	}
	return s, nil
}

func goExportAdmin(ctx context.Context, tx pgx.Tx, i Identity, repo string, active bool) (Repository, error) {
	if i.Role != "admin" {
		return Repository{}, ErrDenied
	}
	if active {
		return repositoryInTx(ctx, tx, i, repo, "read")
	}
	return repositoryRecordInTx(ctx, tx, i, repo, "read")
}

func goHostedExportArtifacts(ctx context.Context, tx pgx.Tx, r Repository, c gomodule.Coordinate) ([]GoExportArtifact, error) {
	if r.Format != "go" || r.Mode != "hosted" {
		return nil, ErrGoExportInput
	}
	b := repositoryReadBudget(r)
	b.sqlMetadataBytes = MaxGoModuleMetadata
	out := make([]GoExportArtifact, 0, 3)
	as := make([]Artifact, 0, 3)
	for _, kind := range []string{"zip", "mod", "info"} {
		a, err := readArtifact(ctx, tx, r.Name, c.Prefix()+"."+kind, r.RequireReview, b)
		if err != nil {
			return nil, err
		}
		var decision int64
		if err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT version FROM cratectl.content_decisions WHERE repository=$1 AND digest=$2),0)`, r.Name, a.Digest).Scan(&decision); err != nil {
			return nil, err
		}
		life, err := artifactStateInTx(ctx, tx, r.Name, a.Path)
		if err != nil {
			return nil, err
		}
		a.Created = a.Created.UTC()
		if life.ChangedAt != nil {
			v := life.ChangedAt.UTC()
			life.ChangedAt = &v
		}
		if life.HoldUntil != nil {
			v := life.HoldUntil.UTC()
			life.HoldUntil = &v
		}
		out = append(out, GoExportArtifact{a.Path, a.Digest, a.Size, a.MediaType, bytes.Clone(a.Metadata), a.Created, a.SourceRevision, a.Decision, decision, life})
		as = append(as, a)
	}
	if _, err := validateGoModuleBundle(as); err != nil {
		return nil, err
	}
	return out, nil
}

func goExportManifestInTx(ctx context.Context, tx pgx.Tx, i Identity, r GoExportRequest, prepared time.Time, anchor crypt.JournalAnchor) (GoExportManifest, error) {
	repo, err := goExportAdmin(ctx, tx, i, r.Repository, true)
	if err != nil {
		return GoExportManifest{}, err
	}
	if repo.SourceRevision != r.ExpectedSourceRevision {
		return GoExportManifest{}, ErrSourceChanged
	}
	c := gomodule.Coordinate{Module: r.Module, Version: r.Version}
	as, err := goHostedExportArtifacts(ctx, tx, repo, c)
	if err != nil {
		return GoExportManifest{}, err
	}
	m := GoExportManifest{Profile: GoExportProfile, Tenant: i.Tenant, Repository: r.Repository, Module: r.Module, Version: r.Version, SourceRevision: repo.SourceRevision, RequireReview: repo.RequireReview, Access: repo.Access, PreparedAt: prepared.UTC(), ObservedJournal: anchor, Artifacts: as, PolicyScope: "historical source decisions; not destination admission"}
	if err := m.validate(); err != nil {
		return GoExportManifest{}, err
	}
	return m, nil
}

func (s *Store) PlanGoExport(ctx context.Context, i Identity, r GoExportRequest) (GoExportPlan, error) {
	if r.Validate() != nil || i.Actor == "" || len(i.Actor) > 256 || !utf8.ValidString(i.Actor) || strings.ContainsFunc(i.Actor, unicode.IsControl) {
		return GoExportPlan{}, ErrGoExportInput
	}
	var out GoExportPlan
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		a := crypt.JournalAnchor{Tenant: i.Tenant}
		err := tx.QueryRow(ctx, `SELECT sequence,hash FROM cratectl.events ORDER BY sequence DESC LIMIT 1`).Scan(&a.Sequence, &a.Hash)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		m, err := goExportManifestInTx(ctx, tx, i, r, now, a)
		if err != nil {
			return err
		}
		raw, err := m.Bytes()
		if err != nil {
			return err
		}
		out = GoExportPlan{i.Tenant, i.Actor, r, m, raw}
		return nil
	})
	if err != nil {
		return GoExportPlan{}, err
	}
	return out, nil
}

func (s *Store) ReplayGoExport(ctx context.Context, i Identity, r GoExportRequest, key string) (Result, bool, error) {
	if r.Validate() != nil || !exportMutationKey(key) {
		return Result{}, false, ErrGoExportInput
	}
	return s.replayMutationChecked(ctx, i, key, goExportFingerprint(r), func(tx pgx.Tx) error { _, err := goExportAdmin(ctx, tx, i, r.Repository, false); return err })
}

// Bytes must already be durably staged by the caller. Under the same tenant
// fence as publication, revalidate the complete original policy/byte snapshot,
// then commit its pins, journal, idempotency receipt and job intent together.
func (s *Store) CommitGoExport(ctx context.Context, i Identity, p GoExportPlan, staged blob.Object, key string, activeLimit int) (Result, error) {
	if p.request.Validate() != nil || p.tenant != i.Tenant || p.actor != i.Actor || !exportMutationKey(key) || activeLimit < 1 || activeLimit > 1000000 || len(p.raw) == 0 || len(p.raw) > MaxGoExportManifest || staged != p.Object() {
		return Result{}, ErrGoExportInput
	}
	authorize := func(tx pgx.Tx) error { _, err := goExportAdmin(ctx, tx, i, p.request.Repository, false); return err }
	return s.mutateIntentChecked(ctx, i, key, goExportFingerprint(p.request), "go.export.created", true, authorize, func(tx pgx.Tx) (any, int, error) {
		m, err := goExportManifestInTx(ctx, tx, i, p.request, p.manifest.PreparedAt, p.manifest.ObservedJournal)
		if err != nil {
			return nil, 0, err
		}
		raw, err := m.Bytes()
		if err != nil || !bytes.Equal(raw, p.raw) {
			return nil, 0, ErrGoExportChanged
		}
		var now time.Time
		var count int
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp(),(SELECT count(*) FROM (SELECT 1 FROM cratectl.artifact_exports WHERE state IN ('open','acknowledged') LIMIT $1)x)`, activeLimit).Scan(&now, &count); err != nil {
			return nil, 0, err
		}
		if now.Before(m.PreparedAt) || now.Sub(m.PreparedAt) > 5*time.Minute {
			return nil, 0, ErrGoExportChanged
		}
		if count >= activeLimit {
			return nil, 0, ErrGoExportLimit
		}
		seq, err := nextEventSequence(ctx, tx, i)
		if err != nil {
			return nil, 0, err
		}
		id := crypt.Digest([]byte("go.export\x00" + i.Tenant + "\x00" + i.Actor + "\x00" + key))
		expires, maxExpires := now.Add(time.Duration(p.request.LifetimeSeconds)*time.Second), now.Add(24*time.Hour)
		_, err = tx.Exec(ctx, `INSERT INTO cratectl.artifact_exports(tenant,id,repository,source_revision,module,version,actor,manifest_digest,manifest_size,state,generation,created_sequence,change_sequence,created_at,changed_at,expires_at,max_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'open',1,$10,$10,$11,$11,$12,$13)`, i.Tenant, id, m.Repository, m.SourceRevision, m.Module, m.Version, i.Actor, staged.Digest, staged.Size, seq, now, expires, maxExpires)
		if err != nil {
			return nil, 0, err
		}
		for n, a := range m.Artifacts {
			if _, err = tx.Exec(ctx, `INSERT INTO cratectl.artifact_export_items(tenant,export_id,ordinal,path,digest,size)VALUES($1,$2,$3,$4,$5,$6)`, i.Tenant, id, n, a.Path, a.Digest, a.Size); err != nil {
				return nil, 0, err
			}
		}
		session, err := scanGoExport(tx.QueryRow(ctx, `SELECT `+goExportColumns+` FROM cratectl.artifact_exports WHERE id=$1`, id))
		return session, 201, err
	})
}

func goExportSessionInTx(ctx context.Context, tx pgx.Tx, i Identity, id string) (GoExportSession, error) {
	if i.Role != "admin" {
		return GoExportSession{}, ErrDenied
	}
	if !uploadDigest.MatchString(id) {
		return GoExportSession{}, ErrGoExportInput
	}
	v, err := scanGoExport(tx.QueryRow(ctx, `SELECT `+goExportColumns+` FROM cratectl.artifact_exports WHERE id=$1`, id))
	if err != nil {
		return GoExportSession{}, err
	}
	if _, err := goExportAdmin(ctx, tx, i, v.Repository, false); err != nil {
		return GoExportSession{}, err
	}
	return v, nil
}
func (s *Store) GoExport(ctx context.Context, i Identity, id string) (GoExportSession, error) {
	if !ValidGoExportID(id) {
		return GoExportSession{}, ErrGoExportInput
	}
	var v GoExportSession
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error { var err error; v, err = goExportSessionInTx(ctx, tx, i, id); return err })
	if err != nil {
		return GoExportSession{}, err
	}
	if v.State == "expired_unreconciled" {
		// Expiry is a durable fenced transition before pins can be released.
		// Queue failure retains them. A wall-clock mark alone is never GC intent.
		r := GoExportChange{Action: "expire", ExpectedGeneration: v.Generation, ManifestSHA256: v.Manifest.Digest}
		_, err = s.ChangeGoExport(ctx, i, id, r, "go-export-expire:"+id+":"+fmt.Sprint(v.Generation))
		if err != nil {
			return GoExportSession{}, err
		}
		err = s.Tx(ctx, i, false, func(tx pgx.Tx) error { var err error; v, err = goExportSessionInTx(ctx, tx, i, id); return err })
		if err != nil {
			return GoExportSession{}, err
		}
	}
	return v, nil
}

func (s *Store) GoExports(ctx context.Context, i Identity, after int64, limit int) ([]GoExportSession, bool, error) {
	out := []GoExportSession{}
	if i.Role != "admin" {
		return out, false, ErrDenied
	}
	if after < 0 || limit < 1 || limit > 100 {
		return out, false, ErrGoExportInput
	}
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+goExportColumns+` FROM cratectl.artifact_exports WHERE created_sequence>$1 ORDER BY created_sequence LIMIT $2`, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanGoExport(rows)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

type GoExportReadback struct {
	Session GoExportSession
	Object  blob.Object
	Kind    string
}

func checkGoExportCurrent(ctx context.Context, tx pgx.Tx, i Identity, v GoExportSession, generation int64) ([]GoExportArtifact, error) {
	if generation < 1 || v.Generation != generation {
		return nil, ErrGoExportChanged
	}
	if v.State != "open" && v.State != "acknowledged" {
		return nil, ErrGoExportExpired
	}
	r, err := goExportAdmin(ctx, tx, i, v.Repository, true)
	if err != nil {
		return nil, err
	}
	if r.SourceRevision != v.SourceRevision {
		return nil, ErrSourceChanged
	}
	as, err := goHostedExportArtifacts(ctx, tx, r, gomodule.Coordinate{Module: v.Module, Version: v.Version})
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT ordinal,path,digest,size FROM cratectl.artifact_export_items WHERE export_id=$1 ORDER BY ordinal LIMIT 4`, v.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var ordinal int
		var p, d string
		var size int64
		if err := rows.Scan(&ordinal, &p, &d, &size); err != nil {
			return nil, err
		}
		if n >= 3 || ordinal != n || p != as[n].Path || d != as[n].Digest || size != as[n].Size {
			return nil, ErrGoExportChanged
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if n != 3 {
		return nil, ErrGoExportChanged
	}
	return as, nil
}
func (s *Store) GoExportObject(ctx context.Context, i Identity, id string, generation int64, kind string) (GoExportReadback, error) {
	var out GoExportReadback
	if kind != "manifest" && kind != "zip" && kind != "mod" && kind != "info" {
		return out, ErrGoExportInput
	}
	if _, err := s.GoExport(ctx, i, id); err != nil {
		return out, err
	}
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		v, err := goExportSessionInTx(ctx, tx, i, id)
		if err != nil {
			return err
		}
		as, err := checkGoExportCurrent(ctx, tx, i, v, generation)
		if err != nil {
			return err
		}
		object := v.Manifest
		for n, k := range []string{"zip", "mod", "info"} {
			if k == kind {
				object = blob.Object{Digest: as[n].Digest, Size: as[n].Size}
			}
		}
		out = GoExportReadback{v, object, kind}
		return nil
	})
	if err != nil {
		return GoExportReadback{}, err
	}
	return out, nil
}

type GoExportChange struct {
	Action             string `json:"action"`
	ExpectedGeneration int64  `json:"expected_generation"`
	LifetimeSeconds    int    `json:"lifetime_seconds"`
	ManifestSHA256     string `json:"manifest_sha256"`
}

func (r GoExportChange) Validate() error {
	if r.ExpectedGeneration < 1 || !uploadDigest.MatchString(r.ManifestSHA256) || r.Action != "renew" && r.Action != "acknowledge" && r.Action != "cancel" && r.Action != "expire" || r.Action == "renew" && (r.LifetimeSeconds < 60 || r.LifetimeSeconds > 3600) || r.Action != "renew" && r.LifetimeSeconds != 0 {
		return ErrGoExportInput
	}
	return nil
}
func (s *Store) ChangeGoExport(ctx context.Context, i Identity, id string, r GoExportChange, key string) (Result, error) {
	if !uploadDigest.MatchString(id) || r.Validate() != nil || !exportMutationKey(key) {
		return Result{}, ErrGoExportInput
	}
	raw, _ := json.Marshal(r)
	fp := crypt.Digest(append([]byte("go.export.change\x00"+id+"\x00"), raw...))
	authorize := func(tx pgx.Tx) error { _, err := goExportSessionInTx(ctx, tx, i, id); return err }
	return s.mutateIntentChecked(ctx, i, key, fp, "go.export.changed", true, authorize, func(tx pgx.Tx) (any, int, error) {
		v, err := goExportSessionInTx(ctx, tx, i, id)
		if err != nil {
			return nil, 0, err
		}
		if v.Generation != r.ExpectedGeneration || v.Manifest.Digest != r.ManifestSHA256 {
			return nil, 0, ErrGoExportChanged
		}
		if v.Generation == int64(^uint64(0)>>1) {
			return nil, 0, ErrGoExportChanged
		}
		state, expires := v.State, v.ExpiresAt
		if r.Action == "cancel" {
			state = "cancelled"
		} else if r.Action == "expire" {
			if v.State != "expired_unreconciled" {
				return nil, 0, ErrGoExportChanged
			}
			state = "expired"
		} else {
			if _, err := checkGoExportCurrent(ctx, tx, i, v, v.Generation); err != nil {
				return nil, 0, err
			}
			if r.Action == "acknowledge" {
				state = "acknowledged"
			} else {
				next := v.ServerTime.Add(time.Duration(r.LifetimeSeconds) * time.Second)
				if next.After(v.MaxExpiresAt) {
					next = v.MaxExpiresAt
				}
				if next.After(expires) {
					expires = next
				}
			}
		}
		seq, err := nextEventSequence(ctx, tx, i)
		if err != nil {
			return nil, 0, err
		}
		_, err = tx.Exec(ctx, `UPDATE cratectl.artifact_exports SET state=$1,generation=generation+1,expires_at=$2,change_sequence=$3,changed_at=clock_timestamp() WHERE id=$4`, state, expires, seq, id)
		if err != nil {
			return nil, 0, err
		}
		current, err := scanGoExport(tx.QueryRow(ctx, `SELECT `+goExportColumns+` FROM cratectl.artifact_exports WHERE id=$1`, id))
		return current, 200, err
	})
}
