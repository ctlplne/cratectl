// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

func goRequirementExportFingerprint(r GoRequirementExportRequest) string {
	raw, _ := json.Marshal(r)
	return crypt.Digest(append([]byte("go.requirement-export.create\x00"), raw...))
}

func (s *Store) ReplayGoRequirementExport(ctx context.Context, i Identity, r GoRequirementExportRequest, key string) (Result, bool, error) {
	if r.Validate() != nil || !exportMutationKey(key) {
		return Result{}, false, ErrGoRequirementExport
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.replayMutationChecked(ctx, i, key, goRequirementExportFingerprint(r), func(tx pgx.Tx) error {
		_, err := goExportAdmin(ctx, tx, i, r.Repository, false)
		return err
	})
}

// Every metadata object must have been durably staged and synced by the caller,
// and each selected ZIP/mod/info must have passed original-byte inspection.
// External I/O never runs inside this atomic tenant-fenced mutation.
func (s *Store) CommitGoRequirementExport(ctx context.Context, i Identity, p GoRequirementExportPlan, staged []blob.Object, key string, activeLimit int) (Result, error) {
	if p.request.Validate() != nil || p.tenant != i.Tenant || p.actor != i.Actor || !exportMutationKey(key) || activeLimit < 1 || activeLimit > 1000000 ||
		len(p.sources) < 1 || len(p.sources) != len(p.manifest.Sources) || len(p.raw) < 1 || len(p.raw) > MaxGoRequirementExportManifest {
		return Result{}, ErrGoRequirementExport
	}
	metadata, err := p.Metadata()
	if err != nil || len(staged) != len(metadata) {
		return Result{}, ErrGoRequirementExport
	}
	for n, item := range metadata {
		if staged[n] != item.Object {
			return Result{}, ErrGoRequirementExport
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	authorize := func(tx pgx.Tx) error { _, err := goExportAdmin(ctx, tx, i, p.request.Repository, false); return err }
	return s.mutateIntentChecked(ctx, i, key, goRequirementExportFingerprint(p.request), "go.requirement-export.created", true, authorize, func(tx pgx.Tx) (any, int, error) {
		// Revalidate lower, unselected inputs too. Comparing the full canonical
		// source manifest detects changed decisions/lifecycle even if .mod bytes
		// and a later allowed result are unchanged.
		for _, source := range p.sources {
			current, err := goExportManifestInTx(ctx, tx, i, source.request, source.manifest.PreparedAt, source.manifest.ObservedJournal)
			if err != nil {
				return nil, 0, err
			}
			raw, err := current.Bytes()
			if err != nil || !bytes.Equal(raw, source.raw) {
				return nil, 0, ErrGoExportSetChanged
			}
		}
		selected, err := goExportSetManifestInTx(ctx, tx, i, p.selection.request, p.manifest.Selection.PreparedAt, p.manifest.Selection.ObservedJournal)
		if err != nil {
			return nil, 0, err
		}
		if !bytes.Equal(selected.raw, p.selection.raw) {
			return nil, 0, ErrGoExportSetChanged
		}
		var now time.Time
		var count int
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp(),(SELECT count(*) FROM (SELECT 1 FROM cratectl.artifact_exports WHERE state IN ('open','acknowledged') UNION ALL SELECT 1 FROM cratectl.artifact_export_sets WHERE state IN ('open','acknowledged') LIMIT $1)x)`, activeLimit).Scan(&now, &count); err != nil {
			return nil, 0, err
		}
		if now.Before(p.manifest.Selection.PreparedAt) || now.Sub(p.manifest.Selection.PreparedAt) > 5*time.Minute {
			return nil, 0, ErrGoExportSetChanged
		}
		if count >= activeLimit {
			return nil, 0, ErrGoExportLimit
		}
		seq, err := nextEventSequence(ctx, tx, i)
		if err != nil {
			return nil, 0, err
		}
		id := crypt.Digest([]byte("go.requirement-export\x00" + i.Tenant + "\x00" + i.Actor + "\x00" + key))
		selection := p.selection.Object()
		_, err = tx.Exec(ctx, `INSERT INTO cratectl.artifact_export_sets(tenant,id,actor,manifest_digest,manifest_size,root_count,artifact_bytes,state,generation,created_sequence,change_sequence,created_at,changed_at,expires_at,max_expires_at)VALUES($1,$2,$3,$4,$5,$6,$7,'open',1,$8,$8,$9,$9,$10,$11)`, i.Tenant, id, i.Actor, selection.Digest, selection.Size, len(p.manifest.Selection.Entries), p.manifest.Selection.DeclaredArtifactBytes, seq, now, now.Add(time.Duration(p.request.LifetimeSeconds)*time.Second), now.Add(24*time.Hour))
		if err != nil {
			return nil, 0, err
		}
		for n, e := range p.manifest.Selection.Entries {
			if _, err = tx.Exec(ctx, `INSERT INTO cratectl.artifact_export_set_roots(tenant,set_id,ordinal,repository,source_revision,module,version)VALUES($1,$2,$3,$4,$5,$6,$7)`, i.Tenant, id, n, e.Repository, e.SourceRevision, e.Module, e.Version); err != nil {
				return nil, 0, err
			}
			for k, a := range e.Artifacts {
				if _, err = tx.Exec(ctx, `INSERT INTO cratectl.artifact_export_set_items(tenant,set_id,root_ordinal,ordinal,path,digest,size)VALUES($1,$2,$3,$4,$5,$6,$7)`, i.Tenant, id, n, k, a.Path, a.Digest, a.Size); err != nil {
					return nil, 0, err
				}
			}
		}
		m := p.manifest
		parent := p.Object()
		_, err = tx.Exec(ctx, `INSERT INTO cratectl.artifact_export_set_requirements(tenant,set_id,manifest_digest,manifest_size,main_digest,main_size,proof_digest,proof_size,source_count,prepared_at,observed_sequence,observed_hash)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, i.Tenant, id, parent.Digest, parent.Size, m.MainGoMod.Digest, m.MainGoMod.Size, m.RequirementProof.Digest, m.RequirementProof.Size, len(m.Sources), m.Selection.PreparedAt, m.Selection.ObservedJournal.Sequence, m.Selection.ObservedJournal.Hash)
		if err != nil {
			return nil, 0, err
		}
		for n, source := range m.Sources {
			_, err = tx.Exec(ctx, `INSERT INTO cratectl.artifact_export_set_requirement_sources(tenant,set_id,ordinal,repository,source_revision,module,version,manifest_digest,manifest_size,mod_digest,mod_size)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, i.Tenant, id, n, source.Repository, source.SourceRevision, source.Module, source.Version, source.Manifest.Digest, source.Manifest.Size, source.Mod.Digest, source.Mod.Size)
			if err != nil {
				return nil, 0, err
			}
		}
		v, _, err := goExportSetSessionInTx(ctx, tx, i, id)
		if err != nil {
			return nil, 0, err
		}
		out, _, err := goRequirementSessionInTx(ctx, tx, i, v)
		return out, 201, err
	})
}

// The old parent keeps the <=8 MiB selection identity. Only the distinct graph
// receipt exposes the <=16 MiB parent, preventing a profile/identity substitution.
func goRequirementSessionInTx(ctx context.Context, tx pgx.Tx, i Identity, v GoExportSetSession) (GoRequirementExportSession, time.Time, error) {
	out := GoRequirementExportSession{Profile: GoRequirementExportProfile, GoExportSetSession: v, SelectionManifest: v.Manifest}
	var prepared time.Time
	err := tx.QueryRow(ctx, `SELECT manifest_digest,manifest_size,main_digest,main_size,proof_digest,proof_size,source_count,prepared_at FROM cratectl.artifact_export_set_requirements WHERE set_id=$1`, v.ID).Scan(&out.Manifest.Digest, &out.Manifest.Size, &out.MainGoMod.Digest, &out.MainGoMod.Size, &out.RequirementProof.Digest, &out.RequirementProof.Size, &out.SourceCount, &prepared)
	if errors.Is(err, pgx.ErrNoRows) {
		return GoRequirementExportSession{}, time.Time{}, ErrNotFound
	}
	if err != nil {
		return GoRequirementExportSession{}, time.Time{}, err
	}
	if !uploadDigest.MatchString(out.Manifest.Digest) || out.Manifest.Size < 1 || out.Manifest.Size > MaxGoRequirementExportManifest ||
		!uploadDigest.MatchString(out.MainGoMod.Digest) || out.MainGoMod.Size < 1 || out.MainGoMod.Size > gomodule.MaxGoMod ||
		!uploadDigest.MatchString(out.RequirementProof.Digest) || out.RequirementProof.Size < 1 || out.RequirementProof.Size > gomodule.MaxRequirementProof || out.SourceCount < 1 || out.SourceCount > gomodule.MaxRequirementProofSources ||
		prepared.After(v.CreatedAt) || v.CreatedAt.Sub(prepared) > 5*time.Minute || i.Role != "admin" {
		return GoRequirementExportSession{}, time.Time{}, ErrGoExportSetChanged
	}
	return out, prepared, nil
}

// This guard is shared by every legacy set delivery/renewal/heartbeat as well as
// new graph reads. Load bounded descriptors before issuing nested source queries.
func checkGoRequirementInputsCurrent(ctx context.Context, tx pgx.Tx, i Identity, v GoExportSetSession) error {
	var count int
	var prepared time.Time
	anchor := crypt.JournalAnchor{Tenant: i.Tenant}
	err := tx.QueryRow(ctx, `SELECT source_count,prepared_at,observed_sequence,observed_hash FROM cratectl.artifact_export_set_requirements WHERE set_id=$1`, v.ID).Scan(&count, &prepared, &anchor.Sequence, &anchor.Hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // An original explicit selected-root set has no graph inputs.
	}
	if err != nil {
		return err
	}
	if count < 1 || count > gomodule.MaxRequirementProofSources || prepared.After(v.CreatedAt) || v.CreatedAt.Sub(prepared) > 5*time.Minute {
		return ErrGoExportSetChanged
	}
	rows, err := tx.Query(ctx, `SELECT ordinal,repository,source_revision,module,version,manifest_digest,manifest_size,mod_digest,mod_size FROM cratectl.artifact_export_set_requirement_sources WHERE set_id=$1 ORDER BY ordinal LIMIT 1025`, v.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	sources := make([]GoRequirementExportSource, 0, count)
	for rows.Next() {
		var n int
		var source GoRequirementExportSource
		if err := rows.Scan(&n, &source.Repository, &source.SourceRevision, &source.Module, &source.Version, &source.Manifest.Digest, &source.Manifest.Size, &source.Mod.Digest, &source.Mod.Size); err != nil {
			return err
		}
		if n != len(sources) || len(sources) >= count {
			return ErrGoExportSetChanged
		}
		sources = append(sources, source)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	rows.Close()
	if len(sources) != count {
		return ErrGoExportSetChanged
	}
	for _, source := range sources {
		r := GoExportRequest{Repository: source.Repository, ExpectedSourceRevision: source.SourceRevision, Module: source.Module, Version: source.Version, LifetimeSeconds: 60}
		m, err := goExportManifestInTx(ctx, tx, i, r, prepared, anchor)
		if err != nil {
			return err
		}
		raw, err := m.Bytes()
		if err != nil || source.Manifest != (blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}) || len(m.Artifacts) != 3 || source.Mod != (blob.Object{Digest: m.Artifacts[1].Digest, Size: m.Artifacts[1].Size}) {
			return ErrGoExportSetChanged
		}
	}
	return nil
}

func (s *Store) GoRequirementExport(ctx context.Context, i Identity, id string) (GoRequirementExportSession, error) {
	if _, err := s.GoExportSet(ctx, i, id); err != nil {
		return GoRequirementExportSession{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out GoRequirementExportSession
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		v, _, err := goExportSetSessionInTx(ctx, tx, i, id)
		if err != nil {
			return err
		}
		out, _, err = goRequirementSessionInTx(ctx, tx, i, v)
		return err
	})
	return out, err
}

type GoRequirementExportReadback struct {
	Session GoRequirementExportSession
	Object  blob.Object
	Source  int
	Kind    string
}

func (s *Store) GoRequirementExportObject(ctx context.Context, i Identity, id string, generation int64, source int, kind string) (GoRequirementExportReadback, error) {
	if source < 0 || source >= gomodule.MaxRequirementProofSources ||
		(kind != "manifest" && kind != "selection" && kind != "main" && kind != "proof" && kind != "source-manifest" && kind != "source-mod") ||
		(kind != "source-manifest" && kind != "source-mod" && source != 0) {
		return GoRequirementExportReadback{}, ErrGoRequirementExport
	}
	if _, err := s.GoExportSet(ctx, i, id); err != nil {
		return GoRequirementExportReadback{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out GoRequirementExportReadback
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		v, roots, err := goExportSetSessionInTx(ctx, tx, i, id)
		if err != nil {
			return err
		}
		graph, _, err := goRequirementSessionInTx(ctx, tx, i, v)
		if err != nil {
			return err
		}
		if _, err := checkGoExportSetCurrent(ctx, tx, i, v, roots, generation); err != nil {
			return err
		}
		o := graph.Manifest
		switch kind {
		case "selection":
			o = graph.SelectionManifest
		case "main":
			o = graph.MainGoMod
		case "proof":
			o = graph.RequirementProof
		case "source-manifest", "source-mod":
			if source >= graph.SourceCount {
				return ErrGoRequirementExport
			}
			var manifest, mod blob.Object
			if err := tx.QueryRow(ctx, `SELECT manifest_digest,manifest_size,mod_digest,mod_size FROM cratectl.artifact_export_set_requirement_sources WHERE set_id=$1 AND ordinal=$2`, id, source).Scan(&manifest.Digest, &manifest.Size, &mod.Digest, &mod.Size); err != nil {
				return err
			}
			o = manifest
			if kind == "source-mod" {
				o = mod
			}
		}
		out = GoRequirementExportReadback{Session: graph, Object: o, Source: source, Kind: kind}
		return nil
	})
	if err != nil {
		return GoRequirementExportReadback{}, err
	}
	return out, nil
}
