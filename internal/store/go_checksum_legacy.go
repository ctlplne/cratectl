// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var ErrGoChecksumLegacyReview = errors.New("retained unattributed checksum incidents require an explicit external trust review")
var ErrGoChecksumLegacyInput = errors.New("invalid checksum incident review input")
var ErrGoChecksumLegacyChanged = errors.New("checksum incident or reviewed authority changed; inspect and preview again")

const MaxGoChecksumLegacyEvent = 64 << 10

// Bounded keyset pages under the exclusive schema transaction. The temporary
// owner-only source policy is still present; runtime FORCE flags never change.
// Hashing stays in internal/crypto rather than a database extension. Refuse a
// damaged original link instead of recording a success-shaped migration.
func validateLegacyChecksumMigration(ctx context.Context, tx pgx.Tx) error {
	var tenant string
	var sequence int64
	seen := 0
	for {
		rows, err := tx.Query(ctx, `SELECT tenant,sequence,CASE WHEN octet_length(payload)<=$3 THEN payload ELSE NULL END,previous_hash,hash FROM cratectl.events WHERE (tenant,sequence)>($1::text,$2::bigint) AND payload::jsonb->>'kind'='proxy.retrieval.failed' AND payload::jsonb#>>'{data,failure}'='upstream_checksum_fork' ORDER BY tenant,sequence LIMIT 64`, tenant, sequence, MaxGoChecksumLegacyEvent)
		if err != nil {
			return err
		}
		n := 0
		for rows.Next() {
			var original Event
			var payload *string
			if err = rows.Scan(&tenant, &original.Sequence, &payload, &original.PreviousHash, &original.Hash); err != nil {
				rows.Close()
				return err
			}
			n++
			seen++
			if payload == nil || seen > 100000 {
				rows.Close()
				return ErrMetadataLimit
			}
			original.Payload = *payload
			if err = validateGoChecksumLegacyEvidence(tenant, GoChecksumLegacyEvidence{Incident: GoChecksumLegacyIncident{Sequence: original.Sequence, EventHash: original.Hash}, OriginalEvent: original}); err != nil {
				rows.Close()
				return err
			}
			sequence = original.Sequence
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if n < 64 {
			return nil
		}
	}
}

type GoChecksumLegacyIncident struct {
	Sequence       int64     `json:"sequence"`
	EventHash      string    `json:"event_hash"`
	CreatedAt      time.Time `json:"created_at"`
	ReviewedForKey bool      `json:"reviewed_for_key"`
}

// The original event remains an unattributed label, not newly signed log proof.
// Its chain/anchor needs independent validation for trusted export attribution.
type GoChecksumLegacyEvidence struct {
	Incident       GoChecksumLegacyIncident `json:"incident"`
	OriginalEvent  Event                    `json:"original_event"`
	Classification string                   `json:"classification"`
}

type GoChecksumLegacyReviewRequest struct {
	DryRun                     bool   `json:"dry_run"`
	AcceptUnattributedHistory  bool   `json:"accept_unattributed_history"`
	IncidentHash               string `json:"incident_hash"`
	ExpectedSourceRevision     int64  `json:"expected_source_revision"`
	KeyDigest                  string `json:"key_digest"`
	ExpectedCheckpointRevision int64  `json:"expected_checkpoint_revision"`
	CheckpointSHA256           string `json:"checkpoint_sha256"`
	ReviewReferenceSHA256      string `json:"review_reference_sha256"`
	Reason                     string `json:"reason"`
}

type GoChecksumLegacyReview struct {
	IncidentSequence      int64     `json:"incident_sequence"`
	IncidentHash          string    `json:"incident_hash"`
	KeyDigest             string    `json:"key_digest"`
	Repository            string    `json:"repository"`
	SourceRevision        int64     `json:"source_revision"`
	CheckpointRevision    int64     `json:"checkpoint_revision"`
	CheckpointSHA256      string    `json:"checkpoint_sha256"`
	ReviewReferenceSHA256 string    `json:"review_reference_sha256"`
	Reason                string    `json:"reason"`
	Actor                 string    `json:"actor"`
	Sequence              int64     `json:"sequence"`
	CreatedAt             time.Time `json:"created_at"`
}

type GoChecksumLegacyReviewPreview struct {
	Incident              GoChecksumLegacyIncident `json:"incident"`
	Repository            string                   `json:"repository"`
	SourceRevision        int64                    `json:"source_revision"`
	KeyDigest             string                   `json:"key_digest"`
	CheckpointRevision    int64                    `json:"checkpoint_revision"`
	CheckpointSHA256      string                   `json:"checkpoint_sha256"`
	ReviewReferenceSHA256 string                   `json:"review_reference_sha256"`
	Reason                string                   `json:"reason"`
	PackageAdmission      bool                     `json:"package_admission"`
}

type GoChecksumLegacyReviewEvidence struct {
	Review           GoChecksumLegacyReview `json:"review"`
	VerifierKey      string                 `json:"verifier_key"`
	Checkpoint       []byte                 `json:"checkpoint"`
	PackageAdmission bool                   `json:"package_admission"`
}

// A retained receipt is historical evidence, even if its source was later
// changed or removed. It never reports that the selected key is usable now.
func (s *Store) GoChecksumLegacyReviewEvidence(ctx context.Context, i Identity, sequence int64, digest string) (GoChecksumLegacyReviewEvidence, error) {
	if sequence <= 0 || !uploadDigest.MatchString(digest) {
		return GoChecksumLegacyReviewEvidence{}, ErrGoChecksumLegacyInput
	}
	var out GoChecksumLegacyReviewEvidence
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		r := &out.Review
		err := tx.QueryRow(ctx, `SELECT event_sequence,incident_hash,key_digest,repository,source_revision,checkpoint_revision,checkpoint,verifier_key,review_reference_sha256,reason,actor,change_sequence,created_at FROM cratectl.go_checksum_legacy_reviews WHERE event_sequence=$1 AND key_digest=$2`, sequence, digest).Scan(&r.IncidentSequence, &r.IncidentHash, &r.KeyDigest, &r.Repository, &r.SourceRevision, &r.CheckpointRevision, &out.Checkpoint, &out.VerifierKey, &r.ReviewReferenceSHA256, &r.Reason, &r.Actor, &r.Sequence, &r.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err == nil {
			r.CheckpointSHA256 = crypt.Digest(out.Checkpoint)
		}
		return err
	})
	if err != nil {
		return GoChecksumLegacyReviewEvidence{}, err
	}
	return out, nil
}

func validateGoChecksumLegacyReview(sequence int64, repo string, r GoChecksumLegacyReviewRequest) error {
	if sequence <= 0 || !Name.MatchString(repo) || r.ExpectedSourceRevision < 0 || r.ExpectedCheckpointRevision < 0 || !uploadDigest.MatchString(r.IncidentHash) || !uploadDigest.MatchString(r.KeyDigest) || !uploadDigest.MatchString(r.CheckpointSHA256) || !uploadDigest.MatchString(r.ReviewReferenceSHA256) || !utf8.ValidString(r.Reason) || strings.TrimSpace(r.Reason) == "" || !validLifecycleReason(r.Reason) || !r.DryRun && !r.AcceptUnattributedHistory {
		return ErrGoChecksumLegacyInput
	}
	return nil
}

func goChecksumLegacyReviewRequired(ctx context.Context, tx pgx.Tx, digest string) (bool, error) {
	var pending bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.go_checksum_legacy_incidents i WHERE NOT EXISTS(SELECT 1 FROM cratectl.go_checksum_legacy_reviews r WHERE r.tenant=i.tenant AND r.event_sequence=i.event_sequence AND r.incident_hash=i.event_hash AND r.key_digest=$1))`, digest).Scan(&pending)
	return pending, err
}

func goChecksumKeyForked(ctx context.Context, tx pgx.Tx, digest string) (bool, error) {
	var blocked bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.go_checksum_forks WHERE key_digest=$1)`, digest).Scan(&blocked)
	return blocked, err
}

// Preserve any new label-only failures as unattributed incidents as well. The
// caller has just appended this exact event in the same tenant write transaction.
func appendGoChecksumLegacyIncident(ctx context.Context, tx pgx.Tx, i Identity, sequence int64) error {
	tag, err := tx.Exec(ctx, `INSERT INTO cratectl.go_checksum_legacy_incidents(tenant,event_sequence,event_hash) SELECT tenant,sequence,hash FROM cratectl.events WHERE tenant=$1 AND sequence=$2`, i.Tenant, sequence)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrGoChecksumLegacyChanged
	}
	return err
}

func (s *Store) GoChecksumLegacyIncidentPage(ctx context.Context, i Identity, after int64, limit int, digest string) ([]GoChecksumLegacyIncident, bool, error) {
	if after < 0 || limit < 1 || limit > 100 || digest != "" && !uploadDigest.MatchString(digest) {
		return nil, false, ErrGoChecksumLegacyInput
	}
	out := []GoChecksumLegacyIncident{}
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		rows, err := tx.Query(ctx, `SELECT i.event_sequence,i.event_hash,i.created_at,EXISTS(SELECT 1 FROM cratectl.go_checksum_legacy_reviews r WHERE r.tenant=i.tenant AND r.event_sequence=i.event_sequence AND r.incident_hash=i.event_hash AND r.key_digest=$3) FROM cratectl.go_checksum_legacy_incidents i WHERE i.event_sequence>$1 ORDER BY i.event_sequence LIMIT $2`, after, limit+1, digest)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v GoChecksumLegacyIncident
			if err := rows.Scan(&v.Sequence, &v.EventHash, &v.CreatedAt, &v.ReviewedForKey); err != nil {
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

func goChecksumLegacyEvidenceInTx(ctx context.Context, tx pgx.Tx, tenant string, sequence int64) (GoChecksumLegacyEvidence, error) {
	var out GoChecksumLegacyEvidence
	var payload *string
	err := tx.QueryRow(ctx, `SELECT i.event_sequence,i.event_hash,i.created_at,CASE WHEN octet_length(e.payload)<=$2 THEN e.payload ELSE NULL END,e.previous_hash,e.hash FROM cratectl.go_checksum_legacy_incidents i JOIN cratectl.events e ON e.tenant=i.tenant AND e.sequence=i.event_sequence WHERE i.event_sequence=$1`, sequence, MaxGoChecksumLegacyEvent).Scan(&out.Incident.Sequence, &out.Incident.EventHash, &out.Incident.CreatedAt, &payload, &out.OriginalEvent.PreviousHash, &out.OriginalEvent.Hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return GoChecksumLegacyEvidence{}, ErrNotFound
	}
	if err != nil {
		return GoChecksumLegacyEvidence{}, err
	}
	if payload == nil {
		return GoChecksumLegacyEvidence{}, ErrMetadataLimit
	}
	out.OriginalEvent.Sequence, out.OriginalEvent.Payload = sequence, *payload
	if err := validateGoChecksumLegacyEvidence(tenant, out); err != nil {
		return GoChecksumLegacyEvidence{}, err
	}
	out.Classification = "unattributed_fork_label"
	return out, nil
}

func validateGoChecksumLegacyEvidence(tenant string, out GoChecksumLegacyEvidence) error {
	if len(out.OriginalEvent.Payload) > MaxGoChecksumLegacyEvent {
		return ErrMetadataLimit
	}
	if !Name.MatchString(tenant) || out.Incident.Sequence <= 0 || out.Incident.Sequence != out.OriginalEvent.Sequence || !uploadDigest.MatchString(out.Incident.EventHash) || out.OriginalEvent.PreviousHash != "" && !uploadDigest.MatchString(out.OriginalEvent.PreviousHash) || out.Incident.EventHash != out.OriginalEvent.Hash || crypt.Digest([]byte(out.OriginalEvent.PreviousHash+"\n"+out.OriginalEvent.Payload)) != out.OriginalEvent.Hash || out.Classification != "" && out.Classification != "unattributed_fork_label" {
		return ErrGoChecksumLegacyChanged
	}
	// Match PostgreSQL's case-sensitive JSON field selection. Go struct decoding
	// alone also accepts case aliases, which cannot establish the retained row's
	// original tenant/sequence binding.
	var envelope, data map[string]json.RawMessage
	var eventTenant, kind, failure string
	var sequence int64
	if json.Unmarshal([]byte(out.OriginalEvent.Payload), &envelope) != nil || json.Unmarshal(envelope["tenant"], &eventTenant) != nil || json.Unmarshal(envelope["sequence"], &sequence) != nil || json.Unmarshal(envelope["kind"], &kind) != nil || json.Unmarshal(envelope["data"], &data) != nil || json.Unmarshal(data["failure"], &failure) != nil || eventTenant != tenant || sequence != out.Incident.Sequence || kind != "proxy.retrieval.failed" || failure != "upstream_checksum_fork" {
		return ErrGoChecksumLegacyChanged
	}
	return nil
}

func (s *Store) GoChecksumLegacyIncidentEvidence(ctx context.Context, i Identity, sequence int64) (GoChecksumLegacyEvidence, error) {
	if sequence <= 0 {
		return GoChecksumLegacyEvidence{}, ErrGoChecksumLegacyInput
	}
	var out GoChecksumLegacyEvidence
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		var err error
		out, err = goChecksumLegacyEvidenceInTx(ctx, tx, i.Tenant, sequence)
		return err
	})
	if err != nil {
		return GoChecksumLegacyEvidence{}, err
	}
	return out, nil
}

func goChecksumLegacyReviewPreview(ctx context.Context, tx pgx.Tx, i Identity, repo string, sequence int64, input GoChecksumLegacyReviewRequest) (GoChecksumLegacyReviewPreview, Repository, GoChecksumCheckpoint, error) {
	var out GoChecksumLegacyReviewPreview
	r, err := repositoryInTx(ctx, tx, i, repo, "read")
	if err != nil {
		return out, Repository{}, GoChecksumCheckpoint{}, err
	}
	if i.Role != "admin" {
		return out, Repository{}, GoChecksumCheckpoint{}, ErrDenied
	}
	if r.SourceRevision != input.ExpectedSourceRevision {
		return out, Repository{}, GoChecksumCheckpoint{}, ErrGoChecksumLegacyChanged
	}
	a := r.Settings.GoChecksumAuthority
	if r.Format != "go" || r.Mode != "proxy" || a == nil || a.Validate() != nil {
		return out, Repository{}, GoChecksumCheckpoint{}, ErrGoModuleUnvalidated
	}
	initial, err := crypt.ParseGoSumDBCheckpoint(a.VerifierKey, a.InitialCheckpoint)
	if err != nil {
		return out, Repository{}, GoChecksumCheckpoint{}, err
	}
	if initial.KeyDigest != input.KeyDigest {
		return out, Repository{}, GoChecksumCheckpoint{}, ErrGoChecksumLegacyChanged
	}
	blocked, err := goChecksumKeyForked(ctx, tx, initial.KeyDigest)
	if err != nil {
		return out, Repository{}, GoChecksumCheckpoint{}, err
	}
	if blocked {
		return out, Repository{}, GoChecksumCheckpoint{}, ErrGoChecksumAuthorityBlocked
	}
	checkpoint, err := currentGoChecksumCheckpoint(ctx, tx, a.VerifierKey, initial.KeyDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		checkpoint = GoChecksumCheckpoint{KeyDigest: initial.KeyDigest, Checkpoint: a.InitialCheckpoint, TreeSize: initial.TreeSize, RootHash: initial.RootHash}
	} else if err != nil {
		return out, Repository{}, GoChecksumCheckpoint{}, err
	}
	if checkpoint.Revision != input.ExpectedCheckpointRevision || crypt.Digest(checkpoint.Checkpoint) != input.CheckpointSHA256 {
		return out, Repository{}, GoChecksumCheckpoint{}, ErrGoChecksumLegacyChanged
	}
	evidence, err := goChecksumLegacyEvidenceInTx(ctx, tx, i.Tenant, sequence)
	if err != nil {
		return out, Repository{}, GoChecksumCheckpoint{}, err
	}
	if evidence.Incident.EventHash != input.IncidentHash {
		return out, Repository{}, GoChecksumCheckpoint{}, ErrGoChecksumLegacyChanged
	}
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.go_checksum_legacy_reviews WHERE event_sequence=$1 AND key_digest=$2)`, sequence, initial.KeyDigest).Scan(&evidence.Incident.ReviewedForKey); err != nil {
		return out, Repository{}, GoChecksumCheckpoint{}, err
	}
	out = GoChecksumLegacyReviewPreview{Incident: evidence.Incident, Repository: repo, SourceRevision: r.SourceRevision, KeyDigest: initial.KeyDigest, CheckpointRevision: checkpoint.Revision, CheckpointSHA256: input.CheckpointSHA256, ReviewReferenceSHA256: input.ReviewReferenceSHA256, Reason: input.Reason}
	return out, r, checkpoint, nil
}

// Administrative external-trust review does not authenticate the missing old
// proof, reset any checkpoint, approve packages or override a true key fork.
func (s *Store) ReviewGoChecksumLegacyIncident(ctx context.Context, i Identity, repo string, sequence int64, key, fingerprint string, input GoChecksumLegacyReviewRequest) (Result, error) {
	if err := validateGoChecksumLegacyReview(sequence, repo, input); err != nil {
		return Result{}, err
	}
	if input.DryRun {
		var out GoChecksumLegacyReviewPreview
		err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
			var err error
			out, _, _, err = goChecksumLegacyReviewPreview(ctx, tx, i, repo, sequence, input)
			return err
		})
		return jsonResult(out, 200, err)
	}
	if len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00") || !uploadDigest.MatchString(fingerprint) {
		return Result{}, ErrGoChecksumLegacyInput
	}
	authorize := func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		_, err := repositoryRecordInTx(ctx, tx, i, repo, "read")
		return err
	}
	return s.mutateIntentChecked(ctx, i, key, fingerprint, "go.checksum.legacy.reviewed", false, authorize, func(tx pgx.Tx) (any, int, error) {
		preview, r, checkpoint, err := goChecksumLegacyReviewPreview(ctx, tx, i, repo, sequence, input)
		if err != nil {
			return nil, 0, err
		}
		if preview.Incident.ReviewedForKey {
			return nil, 0, ErrConflict
		}
		next, err := nextEventSequence(ctx, tx, i)
		if err != nil {
			return nil, 0, err
		}
		out := GoChecksumLegacyReview{IncidentSequence: sequence, IncidentHash: input.IncidentHash, KeyDigest: input.KeyDigest, Repository: repo, SourceRevision: r.SourceRevision, CheckpointRevision: checkpoint.Revision, CheckpointSHA256: input.CheckpointSHA256, ReviewReferenceSHA256: input.ReviewReferenceSHA256, Reason: input.Reason, Actor: i.Actor, Sequence: next}
		err = tx.QueryRow(ctx, `INSERT INTO cratectl.go_checksum_legacy_reviews(tenant,event_sequence,incident_hash,key_digest,repository,source_revision,verifier_key,checkpoint_revision,checkpoint,review_reference_sha256,reason,actor,change_sequence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING created_at`, i.Tenant, sequence, input.IncidentHash, input.KeyDigest, repo, r.SourceRevision, r.Settings.GoChecksumAuthority.VerifierKey, checkpoint.Revision, checkpoint.Checkpoint, input.ReviewReferenceSHA256, input.Reason, i.Actor, next).Scan(&out.CreatedAt)
		if err != nil {
			return nil, 0, err
		}
		return struct {
			Review           GoChecksumLegacyReview `json:"review"`
			PackageAdmission bool                   `json:"package_admission"`
		}{Review: out}, 200, nil
	})
}
