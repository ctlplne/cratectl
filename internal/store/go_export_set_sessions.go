// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

// Immutable identities and renewable control state share one parent, never a
// sequence of independently committed per-version sessions.
type GoExportSetSession struct {
	ID                  string      `json:"id"`
	Actor               string      `json:"actor"`
	Manifest            blob.Object `json:"manifest"`
	RootCount           int         `json:"root_count"`
	ArtifactBytes       int64       `json:"artifact_bytes"`
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

const goExportSetColumns = `id,left(actor,257),manifest_digest,manifest_size,root_count,artifact_bytes,state,generation,created_sequence,change_sequence,created_at,changed_at,expires_at,max_expires_at,clock_timestamp()`

func scanGoExportSet(row pgx.Row) (GoExportSetSession, error) {
	var v GoExportSetSession
	err := row.Scan(&v.ID, &v.Actor, &v.Manifest.Digest, &v.Manifest.Size, &v.RootCount, &v.ArtifactBytes, &v.State, &v.Generation, &v.CreatedSequence, &v.ChangeSequence, &v.CreatedAt, &v.ChangedAt, &v.ExpiresAt, &v.MaxExpiresAt, &v.ServerTime)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if !ValidGoExportID(v.ID) || !uploadDigest.MatchString(v.Manifest.Digest) || v.Manifest.Size < 1 || v.Manifest.Size > MaxGoExportSetManifest || len(v.Actor) > 256 || v.RootCount < 1 || v.RootCount > MaxGoExportSetEntries || v.ArtifactBytes < 0 || v.ArtifactBytes > MaxGoExportSetArtifactBytes || v.Generation < 1 {
		return GoExportSetSession{}, ErrGoExportSetChanged
	}
	v.ManifestRetained = true
	v.PayloadPinsRetained = v.State == "open" || v.State == "acknowledged"
	if v.PayloadPinsRetained && !v.ExpiresAt.After(v.ServerTime) {
		v.State = "expired_unreconciled"
	}
	return v, nil
}
func goExportSetFingerprint(r GoExportSetRequest) string {
	raw, _ := json.Marshal(r)
	return crypt.Digest(append([]byte("go.export-set.create\x00"), raw...))
}
func authorizeGoExportSetRequest(ctx context.Context, tx pgx.Tx, i Identity, r GoExportSetRequest) error {
	if i.Role != "admin" {
		return ErrDenied
	}
	seen := map[string]bool{}
	for _, e := range r.Entries {
		if seen[e.Repository] {
			continue
		}
		seen[e.Repository] = true
		if _, err := goExportAdmin(ctx, tx, i, e.Repository, false); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) ReplayGoExportSet(ctx context.Context, i Identity, r GoExportSetRequest, key string) (Result, bool, error) {
	if r.Validate() != nil || !exportMutationKey(key) {
		return Result{}, false, ErrGoExportSetInput
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.replayMutationChecked(ctx, i, key, goExportSetFingerprint(r), func(tx pgx.Tx) error { return authorizeGoExportSetRequest(ctx, tx, i, r) })
}

// The caller has verified original package representations and durably synced
// the complete common manifest. Under the tenant publication fence, re-read all
// members and compare every original byte/policy/lifecycle identity before any
// ref, journal, receipt or job can commit. Failure rolls back the whole set.
func (s *Store) CommitGoExportSet(ctx context.Context, i Identity, p GoExportSetPlan, staged blob.Object, key string, activeLimit int) (Result, error) {
	if p.request.Validate() != nil || p.tenant != i.Tenant || p.actor != i.Actor || !exportMutationKey(key) || activeLimit < 1 || activeLimit > 1000000 || len(p.raw) < 1 || len(p.raw) > MaxGoExportSetManifest || staged != p.Object() {
		return Result{}, ErrGoExportSetInput
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	authorize := func(tx pgx.Tx) error { return authorizeGoExportSetRequest(ctx, tx, i, p.request) }
	return s.mutateIntentChecked(ctx, i, key, goExportSetFingerprint(p.request), "go.export-set.created", true, authorize, func(tx pgx.Tx) (any, int, error) {
		current, err := goExportSetManifestInTx(ctx, tx, i, p.request, p.manifest.PreparedAt, p.manifest.ObservedJournal)
		if err != nil {
			return nil, 0, err
		}
		if !bytes.Equal(current.raw, p.raw) {
			return nil, 0, ErrGoExportSetChanged
		}
		var now time.Time
		var count int
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp(),(SELECT count(*) FROM (SELECT 1 FROM cratectl.artifact_exports WHERE state IN ('open','acknowledged') UNION ALL SELECT 1 FROM cratectl.artifact_export_sets WHERE state IN ('open','acknowledged') LIMIT $1)x)`, activeLimit).Scan(&now, &count); err != nil {
			return nil, 0, err
		}
		if now.Before(p.manifest.PreparedAt) || now.Sub(p.manifest.PreparedAt) > 5*time.Minute {
			return nil, 0, ErrGoExportSetChanged
		}
		if count >= activeLimit {
			return nil, 0, ErrGoExportLimit
		}
		seq, err := nextEventSequence(ctx, tx, i)
		if err != nil {
			return nil, 0, err
		}
		id := crypt.Digest([]byte("go.export-set\x00" + i.Tenant + "\x00" + i.Actor + "\x00" + key))
		expires := now.Add(time.Duration(p.request.LifetimeSeconds) * time.Second)
		_, err = tx.Exec(ctx, `INSERT INTO cratectl.artifact_export_sets(tenant,id,actor,manifest_digest,manifest_size,root_count,artifact_bytes,state,generation,created_sequence,change_sequence,created_at,changed_at,expires_at,max_expires_at)VALUES($1,$2,$3,$4,$5,$6,$7,'open',1,$8,$8,$9,$9,$10,$11)`, i.Tenant, id, i.Actor, staged.Digest, staged.Size, len(p.manifest.Entries), p.manifest.DeclaredArtifactBytes, seq, now, expires, now.Add(24*time.Hour))
		if err != nil {
			return nil, 0, err
		}
		for n, e := range p.manifest.Entries {
			if _, err = tx.Exec(ctx, `INSERT INTO cratectl.artifact_export_set_roots(tenant,set_id,ordinal,repository,source_revision,module,version)VALUES($1,$2,$3,$4,$5,$6,$7)`, i.Tenant, id, n, e.Repository, e.SourceRevision, e.Module, e.Version); err != nil {
				return nil, 0, err
			}
			for k, a := range e.Artifacts {
				if _, err = tx.Exec(ctx, `INSERT INTO cratectl.artifact_export_set_items(tenant,set_id,root_ordinal,ordinal,path,digest,size)VALUES($1,$2,$3,$4,$5,$6,$7)`, i.Tenant, id, n, k, a.Path, a.Digest, a.Size); err != nil {
					return nil, 0, err
				}
			}
		}
		v, err := scanGoExportSet(tx.QueryRow(ctx, `SELECT `+goExportSetColumns+` FROM cratectl.artifact_export_sets WHERE id=$1`, id))
		return v, 201, err
	})
}

type goExportSetRoot struct {
	ordinal int
	entry   GoExportSetEntry
}

func goExportSetRoots(ctx context.Context, tx pgx.Tx, v GoExportSetSession) ([]goExportSetRoot, error) {
	rows, err := tx.Query(ctx, `SELECT ordinal,repository,source_revision,module,version FROM cratectl.artifact_export_set_roots WHERE set_id=$1 ORDER BY ordinal LIMIT 257`, v.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]goExportSetRoot, 0, v.RootCount)
	for rows.Next() {
		var r goExportSetRoot
		if err = rows.Scan(&r.ordinal, &r.entry.Repository, &r.entry.ExpectedSourceRevision, &r.entry.Module, &r.entry.Version); err != nil {
			return nil, err
		}
		if r.ordinal != len(out) || len(out) >= v.RootCount {
			return nil, ErrGoExportSetChanged
		}
		out = append(out, r)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(out) != v.RootCount {
		return nil, ErrGoExportSetChanged
	}
	return out, nil
}
func goExportSetSessionInTx(ctx context.Context, tx pgx.Tx, i Identity, id string) (GoExportSetSession, []goExportSetRoot, error) {
	if i.Role != "admin" {
		return GoExportSetSession{}, nil, ErrDenied
	}
	if !ValidGoExportID(id) {
		return GoExportSetSession{}, nil, ErrGoExportSetInput
	}
	v, err := scanGoExportSet(tx.QueryRow(ctx, `SELECT `+goExportSetColumns+` FROM cratectl.artifact_export_sets WHERE id=$1`, id))
	if err != nil {
		return GoExportSetSession{}, nil, err
	}
	roots, err := goExportSetRoots(ctx, tx, v)
	if err != nil {
		return GoExportSetSession{}, nil, err
	}
	r := GoExportSetRequest{}
	for _, root := range roots {
		r.Entries = append(r.Entries, root.entry)
	}
	if err = authorizeGoExportSetRequest(ctx, tx, i, r); err != nil {
		return GoExportSetSession{}, nil, err
	}
	return v, roots, nil
}
func (s *Store) GoExportSet(ctx context.Context, i Identity, id string) (GoExportSetSession, error) {
	if !ValidGoExportID(id) {
		return GoExportSetSession{}, ErrGoExportSetInput
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var v GoExportSetSession
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error { var err error; v, _, err = goExportSetSessionInTx(ctx, tx, i, id); return err })
	if err != nil {
		return GoExportSetSession{}, err
	}
	if v.State == "expired_unreconciled" {
		_, err = s.ChangeGoExportSet(ctx, i, id, GoExportChange{Action: "expire", ExpectedGeneration: v.Generation, ManifestSHA256: v.Manifest.Digest}, "go-export-set-expire:"+id+":"+fmt.Sprint(v.Generation))
		if err != nil {
			return GoExportSetSession{}, err
		}
		err = s.Tx(ctx, i, false, func(tx pgx.Tx) error { var err error; v, _, err = goExportSetSessionInTx(ctx, tx, i, id); return err })
	}
	return v, err
}

// Every delivery/renewal checks the complete set, including a denied late root.
// Historical decisions in the manifest never grant current source access.
func checkGoExportSetCurrent(ctx context.Context, tx pgx.Tx, i Identity, v GoExportSetSession, roots []goExportSetRoot, generation int64) ([][]GoExportArtifact, error) {
	if generation < 1 || v.Generation != generation {
		return nil, ErrGoExportSetChanged
	}
	if v.State != "open" && v.State != "acknowledged" {
		return nil, ErrGoExportExpired
	}
	current := make([][]GoExportArtifact, 0, len(roots))
	var total int64
	for _, root := range roots {
		r, err := goExportAdmin(ctx, tx, i, root.entry.Repository, true)
		if err != nil {
			return nil, err
		}
		if r.SourceRevision != root.entry.ExpectedSourceRevision {
			return nil, ErrGoExportSetChanged
		}
		as, err := goHostedExportArtifacts(ctx, tx, r, gomodule.Coordinate{Module: root.entry.Module, Version: root.entry.Version})
		if err != nil {
			return nil, err
		}
		current = append(current, as)
		for _, a := range as {
			total += a.Size
		}
	}
	if total != v.ArtifactBytes {
		return nil, ErrGoExportSetChanged
	}
	rows, err := tx.Query(ctx, `SELECT root_ordinal,ordinal,path,digest,size FROM cratectl.artifact_export_set_items WHERE set_id=$1 ORDER BY root_ordinal,ordinal LIMIT 769`, v.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var root, k int
		var path, digest string
		var size int64
		if err = rows.Scan(&root, &k, &path, &digest, &size); err != nil {
			return nil, err
		}
		if n >= v.RootCount*3 || root != n/3 || k != n%3 {
			return nil, ErrGoExportSetChanged
		}
		a := current[root][k]
		if a.Path != path || a.Digest != digest || a.Size != size {
			return nil, ErrGoExportSetChanged
		}
		n++
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if n != v.RootCount*3 {
		return nil, ErrGoExportSetChanged
	}
	return current, nil
}
func (s *Store) ChangeGoExportSet(ctx context.Context, i Identity, id string, r GoExportChange, key string) (Result, error) {
	if !ValidGoExportID(id) || r.Validate() != nil || !exportMutationKey(key) {
		return Result{}, ErrGoExportSetInput
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, _ := json.Marshal(r)
	fp := crypt.Digest(append([]byte("go.export-set.change\x00"+id+"\x00"), raw...))
	authorize := func(tx pgx.Tx) error { _, _, err := goExportSetSessionInTx(ctx, tx, i, id); return err }
	return s.mutateIntentChecked(ctx, i, key, fp, "go.export-set.changed", true, authorize, func(tx pgx.Tx) (any, int, error) {
		v, roots, err := goExportSetSessionInTx(ctx, tx, i, id)
		if err != nil {
			return nil, 0, err
		}
		if v.Generation != r.ExpectedGeneration || v.Manifest.Digest != r.ManifestSHA256 || v.Generation == int64(^uint64(0)>>1) || v.State == "cancelled" || v.State == "expired" {
			return nil, 0, ErrGoExportSetChanged
		}
		state, expires := v.State, v.ExpiresAt
		switch r.Action {
		case "cancel":
			state = "cancelled"
		case "expire":
			if state != "expired_unreconciled" {
				return nil, 0, ErrGoExportSetChanged
			}
			state = "expired"
		default:
			if _, err = checkGoExportSetCurrent(ctx, tx, i, v, roots, v.Generation); err != nil {
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
		if _, err = tx.Exec(ctx, `UPDATE cratectl.artifact_export_sets SET state=$1,generation=generation+1,expires_at=$2,change_sequence=$3,changed_at=clock_timestamp() WHERE id=$4`, state, expires, seq, id); err != nil {
			return nil, 0, err
		}
		current, err := scanGoExportSet(tx.QueryRow(ctx, `SELECT `+goExportSetColumns+` FROM cratectl.artifact_export_sets WHERE id=$1`, id))
		return current, 200, err
	})
}

type GoExportSetReadback struct {
	Session GoExportSetSession
	Object  blob.Object
	Root    int
	Kind    string
}

func (s *Store) GoExportSetObject(ctx context.Context, i Identity, id string, generation int64, root int, kind string) (GoExportSetReadback, error) {
	if (kind != "manifest" && kind != "zip" && kind != "mod" && kind != "info") || root < 0 || root >= MaxGoExportSetEntries || kind == "manifest" && root != 0 {
		return GoExportSetReadback{}, ErrGoExportSetInput
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := s.GoExportSet(ctx, i, id); err != nil {
		return GoExportSetReadback{}, err
	}
	var out GoExportSetReadback
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		v, roots, err := goExportSetSessionInTx(ctx, tx, i, id)
		if err != nil {
			return err
		}
		if root >= v.RootCount {
			return ErrGoExportSetInput
		}
		as, err := checkGoExportSetCurrent(ctx, tx, i, v, roots, generation)
		if err != nil {
			return err
		}
		o := v.Manifest
		for k, name := range []string{"zip", "mod", "info"} {
			if kind == name {
				o = blob.Object{Digest: as[root][k].Digest, Size: as[root][k].Size}
			}
		}
		out = GoExportSetReadback{v, o, root, kind}
		return nil
	})
	if err != nil {
		return GoExportSetReadback{}, err
	}
	return out, nil
}
