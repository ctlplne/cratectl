// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"github.com/jackc/pgx/v5"
)

func (s *Store) Inventories(ctx context.Context, i Identity, state, after string, limit int) ([]Job, string, error) {
	return s.jobsByKind(ctx, i, "integrity", state, after, limit, "storage.inventory")
}
func (s *Store) Inventory(ctx context.Context, i Identity, id string) (map[string]any, error) {
	j, e := s.Job(ctx, i, id)
	if e != nil {
		return nil, e
	}
	if j.Kind != "storage.inventory" {
		return nil, ErrNotFound
	}
	p, e := inventoryProgress(j.Target)
	if e != nil {
		return nil, e
	}
	complete := j.State == "succeeded" && p.Phase == "done"
	return map[string]any{"job": j, "enumeration_finished": p.Phase != "enumerate", "supported_layout_accounted": complete && p.LayoutIssues == 0, "all_cas_files_assessed": complete && p.LayoutIssues == 0 && p.CASChecked == p.CASFiles, "cas_integrity_clean": complete && p.LayoutIssues == 0 && p.CASIssues == 0, "reference_snapshot_assessed": complete && p.ReferencesChecked == p.ReferenceSnapshot.Targets, "reference_snapshot_clean": complete && p.ReferenceIssues == 0, "unverified_temporary_and_legacy_files": p.TemporaryFiles + p.LegacyFiles, "safe_to_delete": false, "security_approval": false, "consistency": "Live ordered filesystem walk plus immutable reference snapshot. Concurrent entries behind a completed cursor may require the next run. Reference counts and file identities are observations, not a deletion authorization."}, nil
}

type InventoryItem struct {
	ExportReferencesAtWalk  int64  `json:"export_references_at_walk,omitempty"`
	CurrentExportReferences int64  `json:"current_export_references,omitempty"`
	Ordinal                 int64  `json:"ordinal"`
	Area                    string `json:"area"`
	Bucket                  string `json:"bucket"`
	blob.InventoryEntry
	ArtifactReferencesAtWalk  int64      `json:"artifact_references_at_walk"`
	UploadPartsAtWalk         int64      `json:"upload_parts_at_walk"`
	CurrentArtifactReferences int64      `json:"current_artifact_references"`
	CurrentUploadParts        int64      `json:"current_upload_parts"`
	UploadStateAtWalk         string     `json:"upload_state_at_walk"`
	AcknowledgedBytesAtWalk   int64      `json:"acknowledged_bytes_at_walk"`
	ObservedAt                time.Time  `json:"observed_at"`
	Status                    string     `json:"status"`
	HashObservedAt            *time.Time `json:"hash_observed_at,omitempty"`
	Generation                int64      `json:"generation,omitempty"`
}

func (s *Store) InventoryItems(ctx context.Context, i Identity, id, area string, after int64, limit int) ([]InventoryItem, bool, error) {
	out := []InventoryItem{}
	if i.Role != "admin" {
		return out, false, ErrDenied
	}
	if after < 0 || limit < 1 || limit > 1000 || (area != "" && area != "root" && area != "sha256" && area != "cas" && area != "staged" && area != "uploads") {
		return out, false, ErrConflict
	}
	seq, task, e := ParseJobID(id)
	if e != nil {
		return out, false, e
	}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var j Job
		if e := scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM cratectl.jobs WHERE sequence=$1 AND task=$2 AND kind='storage.inventory'`, seq, task), &j); e != nil {
			return e
		}
		p, e := inventoryProgress(j.Target)
		if e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT e.ordinal,e.area,e.bucket,e.display_name,e.name_b64,e.entry_type,e.size,e.modified_ns,e.file_identity,e.expected_layout,e.digest,e.artifact_references,e.upload_parts,e.export_references,e.upload_state,e.acknowledged_bytes,e.observed_at,COALESCE(o.status,CASE WHEN NOT e.expected_layout THEN CASE WHEN e.entry_type='disappeared' THEN 'disappeared' ELSE 'unsupported' END WHEN e.area='cas' THEN 'pending' WHEN e.area='staged' THEN 'temporary_retained' WHEN e.area='uploads' THEN 'legacy_retained' ELSE 'directory' END),o.observed_at,COALESCE(o.generation,0) FROM cratectl.inventory_entries e LEFT JOIN LATERAL(SELECT status,observed_at,generation FROM cratectl.inventory_observations WHERE sequence=e.sequence AND task=e.task AND pass=$1 AND ordinal=e.ordinal ORDER BY generation DESC LIMIT 1)o ON true WHERE e.sequence=$2 AND e.task=$3 AND e.ordinal>$4 AND ($5='' OR e.area=$5) ORDER BY e.ordinal LIMIT $6`, p.Pass, seq, task, after, area, limit+1)
		if e != nil {
			return e
		}
		digests := []string{}
		for rows.Next() {
			var item InventoryItem
			if e = rows.Scan(&item.Ordinal, &item.Area, &item.Bucket, &item.Name, &item.NameB64, &item.Type, &item.Size, &item.ModifiedNS, &item.FileIdentity, &item.Expected, &item.Digest, &item.ArtifactReferencesAtWalk, &item.UploadPartsAtWalk, &item.ExportReferencesAtWalk, &item.UploadStateAtWalk, &item.AcknowledgedBytesAtWalk, &item.ObservedAt, &item.Status, &item.HashObservedAt, &item.Generation); e != nil {
				rows.Close()
				return e
			}
			out = append(out, item)
			if item.Digest != "" {
				digests = append(digests, item.Digest)
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		refs, e := currentDigestReferences(ctx, tx, digests)
		if e != nil {
			return e
		}
		for n := range out {
			r := refs[out[n].Digest]
			out[n].CurrentArtifactReferences, out[n].CurrentUploadParts, out[n].CurrentExportReferences = r.Artifacts, r.Parts, r.Exports
		}
		return nil
	})
	if errors.Is(e, pgx.ErrNoRows) {
		e = ErrNotFound
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, e
}
func (s *Store) InventoryReferences(ctx context.Context, i Identity, id string, after int64, limit int) ([]SweepItem, bool, error) {
	return s.referenceSnapshotItems(ctx, i, id, after, limit, "storage.inventory")
}

type InventoryObservation struct {
	Ordinal    int64     `json:"ordinal"`
	Generation int64     `json:"generation"`
	Pass       int64     `json:"pass"`
	Digest     string    `json:"digest"`
	Size       int64     `json:"size"`
	Status     string    `json:"status"`
	Worker     string    `json:"worker"`
	Engine     string    `json:"engine"`
	ObservedAt time.Time `json:"observed_at"`
}

func (s *Store) InventoryObservations(ctx context.Context, i Identity, id string, after int64, limit int) ([]InventoryObservation, bool, error) {
	out := []InventoryObservation{}
	if i.Role != "admin" {
		return out, false, ErrDenied
	}
	if after < 0 || limit < 1 || limit > 1000 {
		return out, false, ErrConflict
	}
	seq, task, e := ParseJobID(id)
	if e != nil {
		return out, false, e
	}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.jobs WHERE sequence=$1 AND task=$2 AND kind='storage.inventory')`, seq, task).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return ErrNotFound
		}
		rows, e := tx.Query(ctx, `SELECT o.ordinal,o.generation,o.pass,e.digest,e.size,o.status,o.worker,o.engine,o.observed_at FROM cratectl.inventory_observations o JOIN cratectl.inventory_entries e USING(tenant,sequence,task,ordinal) WHERE o.sequence=$1 AND o.task=$2 AND o.generation>$3 ORDER BY o.generation LIMIT $4`, seq, task, after, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var item InventoryObservation
			if e = rows.Scan(&item.Ordinal, &item.Generation, &item.Pass, &item.Digest, &item.Size, &item.Status, &item.Worker, &item.Engine, &item.ObservedAt); e != nil {
				return e
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, e
}
