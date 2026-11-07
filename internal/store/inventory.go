// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var ErrInventoryEntries = errors.New("inventory total entry budget exceeded")

type InventoryRequest struct {
	PageSize int `json:"page_size"`
}
type InventoryLimits struct {
	MaxEntries       int `json:"max_entries"`
	DirectoryEntries int `json:"directory_entries"`
}

func (l InventoryLimits) Validate(page int) error {
	if page < 1 || page > 1000 || l.MaxEntries < 1 || l.MaxEntries > 2147483646 || l.DirectoryEntries < page || l.DirectoryEntries > 2147483646 {
		return ErrConflict
	}
	return nil
}

type InventoryProgress struct {
	InventoryRequest
	InventoryLimits
	RootIdentity           string        `json:"root_identity"`
	ReferenceSnapshot      SweepProgress `json:"reference_snapshot"`
	Phase                  string        `json:"phase"`
	Area                   string        `json:"area"`
	Bucket                 string        `json:"bucket,omitempty"`
	AfterBucket            string        `json:"after_bucket,omitempty"`
	AfterName              string        `json:"after_name_b64,omitempty"`
	Entries                int64         `json:"entries"`
	Files                  int64         `json:"files"`
	CASFiles               int64         `json:"cas_files"`
	UnreferencedCASAtWalk  int64         `json:"unreferenced_cas_at_walk"`
	TemporaryFiles         int64         `json:"temporary_files"`
	LegacyFiles            int64         `json:"legacy_files"`
	LayoutIssues           int64         `json:"layout_issues"`
	LogicalFileBytes       string        `json:"logical_file_bytes"`
	Pages                  int64         `json:"pages"`
	DirectoryEntriesRead   int64         `json:"directory_entries_read"`
	HashAfterOrdinal       int64         `json:"hash_after_ordinal"`
	CASChecked             int64         `json:"cas_checked"`
	CASVerified            int64         `json:"cas_verified"`
	CASIssues              int64         `json:"cas_issues"`
	ReferencesAfterOrdinal int64         `json:"references_after_ordinal"`
	ReferencesChecked      int64         `json:"references_checked"`
	ReferencesVerified     int64         `json:"references_verified"`
	ReferenceIssues        int64         `json:"reference_issues"`
	Pass                   int64         `json:"pass"`
}

func (p InventoryProgress) Validate() error {
	n, ok := new(big.Int).SetString(p.LogicalFileBytes, 10)
	if p.InventoryLimits.Validate(p.PageSize) != nil || !uploadDigest.MatchString(p.RootIdentity) || p.ReferenceSnapshot.Validate() != nil || !ok || n.Sign() < 0 || n.String() != p.LogicalFileBytes || p.Pass < 1 {
		return ErrConflict
	}
	switch p.Phase {
	case "enumerate", "hash", "references", "done":
	default:
		return ErrConflict
	}
	if !blob.ValidInventoryArea(p.Area, p.Bucket) && !(p.Area == "cas" && p.Bucket == "") {
		return ErrConflict
	}
	if len(p.AfterName) > 344 || len(p.AfterBucket) > 2 || p.Entries < 0 || p.Entries > int64(p.MaxEntries) || p.CASFiles < 0 || p.CASFiles > p.Entries || p.CASChecked < 0 || p.CASChecked > p.CASFiles || p.CASVerified < 0 || p.CASVerified > p.CASChecked || p.CASIssues < 0 || p.CASIssues > p.CASChecked || p.CASVerified+p.CASIssues != p.CASChecked || p.ReferencesChecked < 0 || p.ReferencesChecked > p.ReferenceSnapshot.Targets || p.ReferencesAfterOrdinal != p.ReferencesChecked || p.ReferencesVerified < 0 || p.ReferencesVerified > p.ReferencesChecked || p.ReferenceIssues < 0 || p.ReferenceIssues > p.ReferencesChecked || p.ReferencesVerified+p.ReferenceIssues != p.ReferencesChecked {
		return ErrConflict
	}
	return nil
}
func inventoryProgress(raw []byte) (InventoryProgress, error) {
	var p InventoryProgress
	if len(raw) > 16384 || json.Unmarshal(raw, &p) != nil || p.Validate() != nil {
		return p, ErrConflict
	}
	return p, nil
}
func loadInventory(ctx context.Context, tx pgx.Tx, j Job) (InventoryProgress, error) {
	if j.Kind != "storage.inventory" || j.Queue != "integrity" {
		return InventoryProgress{}, ErrConflict
	}
	var raw []byte
	if e := tx.QueryRow(ctx, `SELECT payload FROM cratectl.jobs WHERE sequence=$1 AND task=$2 AND kind='storage.inventory'`, j.Sequence, j.Task).Scan(&raw); e != nil {
		return InventoryProgress{}, e
	}
	return inventoryProgress(raw)
}
func (s *Store) StartInventory(ctx context.Context, i Identity, key, fingerprint, rootIdentity string, r InventoryRequest, l InventoryLimits, referenceBudget int) (Result, error) {
	if i.Role != "admin" {
		return Result{}, ErrDenied
	}
	if l.Validate(r.PageSize) != nil || !uploadDigest.MatchString(rootIdentity) || referenceBudget < 1 || referenceBudget > 2147483646 {
		return Result{}, ErrConflict
	}
	token, e := crypt.Token()
	if e != nil {
		return Result{}, e
	}
	task := "inventory-" + crypt.Digest([]byte(token))
	return s.mutateIntent(ctx, i, key, fingerprint, "storage.inventory.requested", false, func(tx pgx.Tx) (any, int, error) {
		policy, e := queuePolicy(ctx, tx, i.Tenant, "integrity")
		if e != nil {
			return nil, 0, e
		}
		if e = queueRoom(ctx, tx, policy, 1); e != nil {
			return nil, 0, e
		}
		sequence, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return nil, 0, e
		}
		refs, e := snapshotBindings(ctx, tx, i, sequence, task, SweepRequest{}, referenceBudget)
		if e != nil {
			return nil, 0, e
		}
		p := InventoryProgress{InventoryRequest: r, InventoryLimits: l, RootIdentity: rootIdentity, ReferenceSnapshot: refs, Phase: "enumerate", Area: "root", LogicalFileBytes: "0", Pass: 1}
		raw, e := json.Marshal(p)
		if e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.jobs(tenant,sequence,task,queue,kind,payload) VALUES($1,$2,$3,'integrity','storage.inventory',$4)`, i.Tenant, sequence, task, raw); e != nil {
			return nil, 0, e
		}
		return map[string]any{"job": (Job{Sequence: sequence, Task: task}).ID(), "progress": p, "safe_to_delete": false, "security_approval": false}, 202, nil
	})
}

type InventoryStep struct {
	Kind              string
	Progress          InventoryProgress
	Area, Bucket      string
	ExpectedDirectory bool
	Ordinal           int64
	Entry             blob.InventoryEntry
	Reference         SweepItem
}

const inventoryEntryColumns = `ordinal,area,bucket,display_name,name_b64,entry_type,size,modified_ns,file_identity,expected_layout,digest`

func scanInventoryEntry(row pgx.Row, step *InventoryStep) error {
	return row.Scan(&step.Ordinal, &step.Area, &step.Bucket, &step.Entry.Name, &step.Entry.NameB64, &step.Entry.Type, &step.Entry.Size, &step.Entry.ModifiedNS, &step.Entry.FileIdentity, &step.Entry.Expected, &step.Entry.Digest)
}
func prepareInventoryStep(ctx context.Context, tx pgx.Tx, j Job, p InventoryProgress) (InventoryStep, error) {
	step := InventoryStep{Progress: p, Area: p.Area, Bucket: p.Bucket}
	switch p.Phase {
	case "enumerate":
		step.Kind = "page"
		if p.Area == "cas" && p.Bucket == "" {
			e := tx.QueryRow(ctx, `SELECT bucket FROM cratectl.inventory_entries WHERE sequence=$1 AND task=$2 AND area='sha256' AND expected_layout AND bucket>$3 ORDER BY bucket LIMIT 1`, j.Sequence, j.Task, p.AfterBucket).Scan(&step.Bucket)
			if errors.Is(e, pgx.ErrNoRows) {
				step.Kind = "enumeration_end_cas"
				return step, nil
			}
			if e != nil {
				return step, e
			}
		}
		if step.Area == "cas" {
			step.ExpectedDirectory = true
		} else if step.Area != "root" {
			name := base64.RawURLEncoding.EncodeToString([]byte(step.Area))
			if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.inventory_entries WHERE sequence=$1 AND task=$2 AND area='root' AND name_b64=$3 AND expected_layout)`, j.Sequence, j.Task, name).Scan(&step.ExpectedDirectory); e != nil {
				return step, e
			}
		}
	case "hash":
		step.Kind = "hash"
		e := scanInventoryEntry(tx.QueryRow(ctx, `SELECT `+inventoryEntryColumns+` FROM cratectl.inventory_entries WHERE sequence=$1 AND task=$2 AND area='cas' AND expected_layout AND ordinal>$3 ORDER BY ordinal LIMIT 1`, j.Sequence, j.Task, p.HashAfterOrdinal), &step)
		if errors.Is(e, pgx.ErrNoRows) {
			step.Kind = "hash_end"
			return step, nil
		}
		if e != nil {
			return step, e
		}
	case "references":
		step.Kind = "reference"
		if p.ReferencesChecked == p.ReferenceSnapshot.Targets {
			step.Kind = "references_end"
			return step, nil
		}
		if e := scanSweepItem(tx.QueryRow(ctx, `SELECT `+sweepItemColumns+` FROM cratectl.sweep_items WHERE sequence=$1 AND task=$2 AND ordinal=$3`, j.Sequence, j.Task, p.ReferencesAfterOrdinal+1), &step.Reference); e != nil {
			return step, e
		}
	case "done":
		step.Kind = "done"
	}
	return step, nil
}
func (s *Store) PrepareInventoryStep(ctx context.Context, i WorkerIdentity, j Job) (InventoryStep, error) {
	var step InventoryStep
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		if state == "cancel_requested" {
			return ErrJobCancelled
		}
		p, e := loadInventory(ctx, tx, j)
		if e != nil {
			return e
		}
		step, e = prepareInventoryStep(ctx, tx, j, p)
		return e
	})
	return step, e
}
func (s *Store) applyInventory(ctx context.Context, i WorkerIdentity, j Job, kind string, apply func(pgx.Tx, *InventoryProgress, InventoryStep) error) (string, error) {
	outcome := ""
	e := s.workerTx(ctx, i, func(tx pgx.Tx) error {
		state, e := leasedJob(ctx, tx, j)
		if e != nil {
			return e
		}
		p, e := loadInventory(ctx, tx, j)
		if e != nil {
			return e
		}
		outcome = "cancelled"
		if state != "cancel_requested" {
			step, e := prepareInventoryStep(ctx, tx, j, p)
			if e != nil {
				return e
			}
			if step.Kind != kind {
				return ErrConflict
			}
			if e = apply(tx, &p, step); e != nil {
				return e
			}
			if e = p.Validate(); e != nil {
				return e
			}
			outcome = "pending"
			if p.Phase == "done" {
				outcome = "succeeded"
			}
		}
		raw, e := json.Marshal(p)
		if e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE cratectl.jobs SET payload=$1,state=$2,cycle_attempts=CASE WHEN $2='pending' THEN 0 ELSE cycle_attempts END,available_at=clock_timestamp(),lease_token='',lease_until='epoch',updated_at=clock_timestamp(),finished_at=CASE WHEN $2='pending' THEN NULL ELSE clock_timestamp() END WHERE sequence=$3 AND task=$4 AND generation=$5 AND lease_token=$6 AND lease_until>clock_timestamp()`, raw, outcome, j.Sequence, j.Task, j.Generation, j.Token)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrJobLeaseLost
		}
		return appendEventIntent(ctx, tx, Identity{Tenant: i.Tenant, Actor: i.Actor, Role: "worker"}, "storage.inventory."+outcome, map[string]any{"job": j.ID(), "generation": j.Generation, "step": kind, "progress": p, "safe_to_delete": false, "security_approval": false}, false)
	})
	return outcome, e
}

type digestReferences struct{ Artifacts, Parts, Exports int64 }

func currentDigestReferences(ctx context.Context, tx pgx.Tx, digests []string) (map[string]digestReferences, error) {
	out := map[string]digestReferences{}
	if len(digests) == 0 {
		return out, nil
	}
	rows, e := tx.Query(ctx, `SELECT digest,sum(a)::bigint,sum(p)::bigint,sum(e)::bigint FROM (
 SELECT digest,count(*) a,0::bigint p,0::bigint e FROM cratectl.artifacts WHERE digest=ANY($1::text[]) GROUP BY digest
 UNION ALL SELECT digest,0::bigint,count(*),0::bigint FROM cratectl.upload_parts WHERE digest=ANY($1::text[]) GROUP BY digest
 UNION ALL SELECT manifest_digest,0::bigint,0::bigint,count(*) FROM cratectl.artifact_exports WHERE manifest_digest=ANY($1::text[]) GROUP BY manifest_digest
 UNION ALL SELECT x.digest,0::bigint,0::bigint,count(*) FROM cratectl.artifact_export_items x JOIN cratectl.artifact_exports s ON (s.tenant,s.id)=(x.tenant,x.export_id) WHERE x.digest=ANY($1::text[]) AND s.state IN ('open','acknowledged') GROUP BY x.digest
 UNION ALL SELECT manifest_digest,0::bigint,0::bigint,count(*) FROM cratectl.artifact_export_sets WHERE manifest_digest=ANY($1::text[]) GROUP BY manifest_digest
 UNION ALL SELECT manifest_digest,0::bigint,0::bigint,count(*) FROM cratectl.artifact_export_set_requirements WHERE manifest_digest=ANY($1::text[]) GROUP BY manifest_digest
 UNION ALL SELECT main_digest,0::bigint,0::bigint,count(*) FROM cratectl.artifact_export_set_requirements WHERE main_digest=ANY($1::text[]) GROUP BY main_digest
 UNION ALL SELECT proof_digest,0::bigint,0::bigint,count(*) FROM cratectl.artifact_export_set_requirements WHERE proof_digest=ANY($1::text[]) GROUP BY proof_digest
 UNION ALL SELECT manifest_digest,0::bigint,0::bigint,count(*) FROM cratectl.artifact_export_set_requirement_sources WHERE manifest_digest=ANY($1::text[]) GROUP BY manifest_digest
 UNION ALL SELECT mod_digest,0::bigint,0::bigint,count(*) FROM cratectl.artifact_export_set_requirement_sources WHERE mod_digest=ANY($1::text[]) GROUP BY mod_digest
 UNION ALL SELECT x.digest,0::bigint,0::bigint,count(*) FROM cratectl.artifact_export_set_items x JOIN cratectl.artifact_export_sets s ON (s.tenant,s.id)=(x.tenant,x.set_id) WHERE x.digest=ANY($1::text[]) AND s.state IN ('open','acknowledged') GROUP BY x.digest
 )r GROUP BY digest`, digests)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var digest string
		var r digestReferences
		if e = rows.Scan(&digest, &r.Artifacts, &r.Parts, &r.Exports); e != nil {
			return out, e
		}
		out[digest] = r
	}
	return out, rows.Err()
}
func (s *Store) FinishInventoryPage(ctx context.Context, i WorkerIdentity, j Job, page blob.InventoryPage) (string, error) {
	return s.applyInventory(ctx, i, j, "page", func(tx pgx.Tx, p *InventoryProgress, step InventoryStep) error {
		if page.Area != step.Area || page.Bucket != step.Bucket || len(page.Entries) > p.PageSize || page.Scanned < 0 || page.Scanned > p.DirectoryEntries || page.More && len(page.Entries) == 0 {
			return ErrConflict
		}
		if p.Entries+int64(len(page.Entries)) > int64(p.MaxEntries) {
			return ErrInventoryEntries
		}
		digests := []string{}
		for _, entry := range page.Entries {
			if entry.Digest != "" {
				digests = append(digests, entry.Digest)
			}
		}
		refs, e := currentDigestReferences(ctx, tx, digests)
		if e != nil {
			return e
		}
		previous, e := base64.RawURLEncoding.DecodeString(p.AfterName)
		if e != nil {
			return ErrConflict
		}
		total, _ := new(big.Int).SetString(p.LogicalFileBytes, 10)
		for _, entry := range page.Entries {
			name, e := base64.RawURLEncoding.DecodeString(entry.NameB64)
			if e != nil || len(name) == 0 || len(name) > 255 || string(name) <= string(previous) || strings.ContainsAny(string(name), "/\x00") || len(entry.Name) > 1024 || entry.Size < 0 {
				return ErrConflict
			}
			previous = name
			if entry.Digest != "" && !uploadDigest.MatchString(entry.Digest) {
				return ErrConflict
			}
			bucket := page.Bucket
			if page.Area == "sha256" && entry.Expected {
				bucket = string(name)
			}
			r := refs[entry.Digest]
			uploadState := ""
			var acknowledged int64
			if page.Area == "uploads" && uploadIdentifier.MatchString(string(name)) {
				e = tx.QueryRow(ctx, `SELECT CASE WHEN state='active' AND expires_at<=clock_timestamp() THEN 'expired_unreconciled' ELSE state END,offset_bytes FROM cratectl.uploads WHERE id=$1`, string(name)).Scan(&uploadState, &acknowledged)
				if e != nil && !errors.Is(e, pgx.ErrNoRows) {
					return e
				}
			}
			p.Entries++
			if _, e = tx.Exec(ctx, `INSERT INTO cratectl.inventory_entries(tenant,sequence,task,ordinal,area,bucket,name_b64,display_name,entry_type,size,modified_ns,file_identity,expected_layout,digest,artifact_references,upload_parts,upload_state,acknowledged_bytes,export_references) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`, i.Tenant, j.Sequence, j.Task, p.Entries, page.Area, bucket, entry.NameB64, entry.Name, entry.Type, entry.Size, entry.ModifiedNS, entry.FileIdentity, entry.Expected, entry.Digest, r.Artifacts, r.Parts, uploadState, acknowledged, r.Exports); e != nil {
				return e
			}
			if !entry.Expected {
				p.LayoutIssues++
			}
			if entry.Type == "file" {
				p.Files++
				total.Add(total, big.NewInt(entry.Size))
				if page.Area == "staged" {
					p.TemporaryFiles++
				}
				if page.Area == "uploads" {
					p.LegacyFiles++
				}
			}
			if page.Area == "cas" && entry.Expected {
				p.CASFiles++
				if r.Artifacts+r.Parts+r.Exports == 0 {
					p.UnreferencedCASAtWalk++
				}
			}
		}
		p.LogicalFileBytes = total.String()
		p.Pages++
		p.DirectoryEntriesRead += int64(page.Scanned)
		if page.Unsupported || page.Missing && step.ExpectedDirectory {
			p.LayoutIssues++
		}
		if page.More {
			p.AfterName = page.Entries[len(page.Entries)-1].NameB64
			p.Bucket = step.Bucket
			return nil
		}
		p.AfterName = ""
		p.Bucket = ""
		switch page.Area {
		case "root":
			p.Area = "sha256"
		case "sha256":
			p.Area = "cas"
		case "cas":
			p.AfterBucket = step.Bucket
		case "staged":
			p.Area = "uploads"
		case "uploads":
			p.Phase = "hash"
		}
		return nil
	})
}
func (s *Store) FinishInventoryTransition(ctx context.Context, i WorkerIdentity, j Job, kind string) (string, error) {
	return s.applyInventory(ctx, i, j, kind, func(tx pgx.Tx, p *InventoryProgress, step InventoryStep) error {
		switch kind {
		case "enumeration_end_cas":
			p.Area = "staged"
			p.AfterName = ""
			p.Bucket = ""
		case "hash_end":
			p.Phase = "references"
		case "references_end", "done":
			p.Phase = "done"
		default:
			return ErrConflict
		}
		return nil
	})
}
func (s *Store) FinishInventoryHash(ctx context.Context, i WorkerIdentity, j Job, item InventoryStep, status string) (string, error) {
	switch status {
	case "verified", "missing", "corrupt", "io_error", "limit", "timeout", "changed", "unsupported":
	default:
		return "", ErrConflict
	}
	return s.applyInventory(ctx, i, j, "hash", func(tx pgx.Tx, p *InventoryProgress, step InventoryStep) error {
		if item.Ordinal != step.Ordinal || item.Entry.Digest != step.Entry.Digest || item.Entry.FileIdentity != step.Entry.FileIdentity {
			return ErrConflict
		}
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.inventory_observations(tenant,sequence,task,ordinal,generation,pass,status,worker) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, i.Tenant, j.Sequence, j.Task, step.Ordinal, j.Generation, p.Pass, status, j.Worker); e != nil {
			return e
		}
		p.HashAfterOrdinal = step.Ordinal
		p.CASChecked++
		if status == "verified" {
			p.CASVerified++
		} else {
			p.CASIssues++
		}
		return nil
	})
}
func (s *Store) FinishInventoryReference(ctx context.Context, i WorkerIdentity, j Job, item SweepItem, status string) (string, error) {
	switch status {
	case "verified", "missing", "corrupt", "io_error", "limit", "timeout":
	default:
		return "", ErrConflict
	}
	return s.applyInventory(ctx, i, j, "reference", func(tx pgx.Tx, p *InventoryProgress, step InventoryStep) error {
		target := step.Reference
		if item.Ordinal != target.Ordinal || item.Digest != target.Digest || item.Size != target.Size || item.Repository != target.Repository {
			return ErrConflict
		}
		if target.ReferenceConflict && status == "verified" {
			status = "inconsistent"
		}
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.integrity_observations(tenant,sequence,task,generation,repository,digest,size,status,worker,ordinal,pass) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, i.Tenant, j.Sequence, j.Task, j.Generation, target.Repository, target.Digest, target.Size, status, j.Worker, target.Ordinal, p.Pass); e != nil {
			return e
		}
		p.ReferencesAfterOrdinal = target.Ordinal
		p.ReferencesChecked++
		if status == "verified" {
			p.ReferencesVerified++
		} else {
			p.ReferenceIssues++
		}
		return nil
	})
}
func resetCompletedInventory(j *Job) ([]byte, error) {
	p, e := inventoryProgress(j.Target)
	if e != nil {
		return nil, e
	}
	if p.Pass == int64(^uint64(0)>>1) {
		return nil, ErrConflict
	}
	p.Pass++
	p.Phase = "hash"
	p.HashAfterOrdinal, p.CASChecked, p.CASVerified, p.CASIssues = 0, 0, 0, 0
	p.ReferencesAfterOrdinal, p.ReferencesChecked, p.ReferencesVerified, p.ReferenceIssues = 0, 0, 0, 0
	return json.Marshal(p)
}
