// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var ErrRetentionInput = errors.New("invalid retention request")
var ErrRetentionChanged = errors.New("retention policy or approved plan changed")
var ErrRetentionBudget = errors.New("retention plan exceeds configured budget")
var ErrRetentionAuthorization = errors.New("retention requester authority changed")

type RetentionSettings struct {
	MinAgeSeconds int64  `json:"min_age_seconds"`
	KeepLast      int    `json:"keep_last"`
	ProtectTagged bool   `json:"protect_tagged"`
	Enabled       bool   `json:"enabled"`
	Reason        string `json:"reason"`
}

func (s RetentionSettings) Validate() error {
	if s.MinAgeSeconds < 60 || s.MinAgeSeconds > 315360000 || s.KeepLast < 0 || s.KeepLast > 1000000 || !validLifecycleReason(s.Reason) || !utf8.ValidString(s.Reason) || strings.TrimSpace(s.Reason) == "" {
		return ErrRetentionInput
	}
	return nil
}

type RetentionPolicy struct {
	RetentionSettings
	Repository   string    `json:"repository"`
	Name         string    `json:"name"`
	Revision     int64     `json:"revision"`
	Actor        string    `json:"actor"`
	ConfiguredAt time.Time `json:"configured_at"`
}
type RetentionPolicyRequest struct {
	RetentionSettings
	ExpectedRevision int64 `json:"expected_revision"`
	DryRun           bool  `json:"dry_run"`
}

func retentionRepository(ctx context.Context, tx pgx.Tx, i Identity, repo string) (Repository, error) {
	if _, e := retentionRepositoryRecord(ctx, tx, i, repo); e != nil {
		return Repository{}, e
	}
	return repositoryInTx(ctx, tx, i, repo, "write")
}
func retentionRepositoryRecord(ctx context.Context, tx pgx.Tx, i Identity, repo string) (Repository, error) {
	if i.Role != "admin" {
		return Repository{}, ErrDenied
	}
	r, e := repositoryRecordInTx(ctx, tx, i, repo, "write")
	if e != nil {
		return r, e
	}
	if r.Format != "oci" || r.Mode == "group" {
		return r, ErrRetentionInput
	}
	return r, nil
}
func retentionPolicy(ctx context.Context, tx pgx.Tx, repo, name string) (RetentionPolicy, error) {
	var out RetentionPolicy
	var revision int64
	var raw []byte
	e := tx.QueryRow(ctx, `SELECT revision,configuration FROM cratectl.retention_policies WHERE repository=$1 AND name=$2`, repo, name).Scan(&revision, &raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if e != nil {
		return out, e
	}
	if len(raw) > 16384 || json.Unmarshal(raw, &out) != nil || out.Repository != repo || out.Name != name || out.Revision != revision || out.RetentionSettings.Validate() != nil {
		return out, ErrRetentionInput
	}
	return out, nil
}
func (s *Store) RetentionPolicy(ctx context.Context, i Identity, repo, name string) (RetentionPolicy, error) {
	var out RetentionPolicy
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, e := retentionRepositoryRecord(ctx, tx, i, repo); e != nil {
			return e
		}
		var e error
		out, e = retentionPolicy(ctx, tx, repo, name)
		return e
	})
	return out, e
}
func (s *Store) SetRetentionPolicy(ctx context.Context, i Identity, repo, name, key, fp string, r RetentionPolicyRequest) (Result, error) {
	if !Name.MatchString(name) || r.ExpectedRevision < 0 || r.ExpectedRevision == math.MaxInt64 || r.RetentionSettings.Validate() != nil {
		return Result{}, ErrRetentionInput
	}
	prepare := func(tx pgx.Tx) (RetentionPolicy, error) {
		out := RetentionPolicy{RetentionSettings: r.RetentionSettings, Repository: repo, Name: name, Revision: r.ExpectedRevision + 1, Actor: i.Actor}
		if _, e := retentionRepository(ctx, tx, i, repo); e != nil {
			return out, e
		}
		old, e := retentionPolicy(ctx, tx, repo, name)
		if e != nil && !errors.Is(e, ErrNotFound) {
			return out, e
		}
		if old.Revision != r.ExpectedRevision {
			return out, ErrRetentionChanged
		}
		e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&out.ConfiguredAt)
		return out, e
	}
	if r.DryRun {
		var out RetentionPolicy
		e := s.Tx(ctx, i, false, func(tx pgx.Tx) error { var e error; out, e = prepare(tx); return e })
		return jsonResult(out, 200, e)
	}
	return s.mutateIntentChecked(ctx, i, key, fp, "repository.retention.configured", true, func(tx pgx.Tx) error { _, e := retentionRepository(ctx, tx, i, repo); return e }, func(tx pgx.Tx) (any, int, error) {
		out, e := prepare(tx)
		if e != nil {
			return nil, 0, e
		}
		raw, e := json.Marshal(out)
		if e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.retention_policies(tenant,repository,name,revision,configuration)VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant,repository,name)DO UPDATE SET revision=excluded.revision,configuration=excluded.configuration`, i.Tenant, repo, name, out.Revision, raw); e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.retention_revisions(tenant,repository,name,revision,configuration)VALUES($1,$2,$3,$4,$5)`, i.Tenant, repo, name, out.Revision, raw); e != nil {
			return nil, 0, e
		}
		return out, 200, nil
	})
}

type RetentionRequest struct {
	ExpectedRevision int64      `json:"expected_revision"`
	EvaluatedAt      *time.Time `json:"evaluated_at,omitempty"`
	PreviewDigest    string     `json:"preview_digest,omitempty"`
	Reason           string     `json:"reason"`
	DryRun           bool       `json:"dry_run"`
}
type RetentionItem struct {
	Ordinal           int64     `json:"ordinal"`
	Path              string    `json:"path"`
	Digest            string    `json:"digest"`
	Size              int64     `json:"size"`
	CreatedAt         time.Time `json:"created_at"`
	LifecycleRevision int64     `json:"lifecycle_revision"`
	Status            string    `json:"status"`
	Tags              []string  `json:"tags"`
	StrongParents     []string  `json:"strong_parents"`
}
type RetentionPlan struct {
	Policy         RetentionPolicy `json:"policy"`
	SourceRevision int64           `json:"source_revision"`
	EvaluatedAt    time.Time       `json:"evaluated_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	Reason         string          `json:"reason"`
	Targets        int             `json:"targets"`
	Eligible       int             `json:"eligible"`
	Items          []RetentionItem `json:"items,omitempty"`
	Digest         string          `json:"preview_digest"`
	BytesReclaimed int64           `json:"bytes_reclaimed"`
}

func retentionStatus(policy RetentionPolicy, state ArtifactStatePreview, created time.Time, rank int64, validated bool, evaluated time.Time) string {
	switch {
	case state.Current.Deleted:
		return "already_retired"
	case state.Current.Held:
		return "held"
	case !validated:
		return "unvalidated"
	case len(state.StrongParents) > 0:
		return "referenced"
	case policy.ProtectTagged && len(state.Tags) > 0:
		return "tagged"
	case rank <= int64(policy.KeepLast):
		return "newest"
	case created.After(evaluated.Add(-time.Duration(policy.MinAgeSeconds) * time.Second)):
		return "young"
	default:
		return "eligible"
	}
}
func retentionPreview(ctx context.Context, tx pgx.Tx, i Identity, repo, name string, r RetentionRequest, budget int) (RetentionPlan, error) {
	out := RetentionPlan{Items: []RetentionItem{}, Reason: r.Reason}
	if budget < 1 || budget > 10000 || r.ExpectedRevision < 1 || !validLifecycleReason(r.Reason) || !utf8.ValidString(r.Reason) || strings.TrimSpace(r.Reason) == "" {
		return out, ErrRetentionInput
	}
	record, e := retentionRepository(ctx, tx, i, repo)
	if e != nil {
		return out, e
	}
	out.SourceRevision = record.SourceRevision
	out.Policy, e = retentionPolicy(ctx, tx, repo, name)
	if e != nil {
		return out, e
	}
	if out.Policy.Revision != r.ExpectedRevision || !out.Policy.Enabled {
		return out, ErrRetentionChanged
	}
	var now time.Time
	if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return out, e
	}
	out.EvaluatedAt = now.UTC()
	if r.EvaluatedAt != nil {
		out.EvaluatedAt = r.EvaluatedAt.UTC()
	}
	out.ExpiresAt = out.EvaluatedAt.Add(5 * time.Minute)
	if out.EvaluatedAt.After(now) || !out.ExpiresAt.After(now) {
		return out, ErrRetentionChanged
	}
	rows, e := tx.Query(ctx, `SELECT a.path,a.digest,a.size,a.created_at,COALESCE((a.metadata->>'oci_validated')='true',false),row_number() OVER(PARTITION BY left(a.path,length(a.path)-length('/manifests/sha256:')-64) ORDER BY a.created_at DESC,a.path DESC) FROM cratectl.artifacts a WHERE a.repository=$1 AND right(a.path,length('/manifests/sha256:')+64)='/manifests/sha256:'||a.digest AND length(a.path)>length('/manifests/sha256:')+64 AND NOT EXISTS(SELECT 1 FROM cratectl.artifact_lifecycle l WHERE(l.tenant,l.repository,l.path)=(a.tenant,a.repository,a.path)AND l.deleted) ORDER BY a.path LIMIT $2`, repo, budget+1)
	if e != nil {
		return out, e
	}
	type candidate struct {
		item      RetentionItem
		validated bool
		rank      int64
	}
	candidates := []candidate{}
	for rows.Next() {
		var c candidate
		if e = rows.Scan(&c.item.Path, &c.item.Digest, &c.item.Size, &c.item.CreatedAt, &c.validated, &c.rank); e != nil {
			rows.Close()
			return out, e
		}
		candidates = append(candidates, c)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	if len(candidates) > budget {
		return out, ErrRetentionBudget
	}
	bytes := 0
	for n, c := range candidates {
		input := ArtifactStateRequest{Action: "hold", Path: c.item.Path, Digest: c.item.Digest, Reason: r.Reason}
		state, e := artifactStateInTx(ctx, tx, repo, c.item.Path)
		if e != nil {
			return out, e
		}
		input.ExpectedRevision = state.Revision
		preview, e := artifactStatePreview(ctx, tx, i, repo, input, 128)
		if e != nil {
			return out, e
		}
		item := c.item
		item.Ordinal = int64(n + 1)
		item.LifecycleRevision = state.Revision
		item.Tags = preview.Tags
		item.StrongParents = preview.StrongParents
		item.Status = retentionStatus(out.Policy, preview, item.CreatedAt, c.rank, c.validated, out.EvaluatedAt)
		raw, e := json.Marshal(item)
		if e != nil {
			return out, e
		}
		bytes += len(raw)
		if len(raw) > 16384 || bytes > 8<<20 {
			return out, ErrRetentionBudget
		}
		if item.Status == "eligible" {
			out.Eligible++
		}
		out.Items = append(out.Items, item)
	}
	out.Targets = len(out.Items)
	raw, e := json.Marshal(out)
	if e != nil {
		return out, e
	}
	out.Digest = crypt.Digest(raw)
	return out, nil
}
func (s *Store) StartRetention(ctx context.Context, i Identity, repo, name, key, fp string, r RetentionRequest, budget int) (Result, error) {
	if !Name.MatchString(name) {
		return Result{}, ErrRetentionInput
	}
	if r.DryRun {
		var out RetentionPlan
		e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
			var e error
			out, e = retentionPreview(ctx, tx, i, repo, name, r, budget)
			return e
		})
		return jsonResult(out, 200, e)
	}
	if r.EvaluatedAt == nil || !uploadDigest.MatchString(r.PreviewDigest) || i.CredentialHash == "" {
		return Result{}, ErrRetentionInput
	}
	return s.mutateIntentChecked(ctx, i, key, fp, "repository.retention.requested", true, func(tx pgx.Tx) error { _, e := retentionRepository(ctx, tx, i, repo); return e }, func(tx pgx.Tx) (any, int, error) {
		out, e := retentionPreview(ctx, tx, i, repo, name, r, budget)
		if e != nil {
			return nil, 0, e
		}
		if out.Digest != r.PreviewDigest {
			return nil, 0, ErrRetentionChanged
		}
		policy, e := queuePolicy(ctx, tx, i.Tenant, "maintenance")
		if e != nil {
			return nil, 0, e
		}
		if e = queueRoom(ctx, tx, policy, 1); e != nil {
			return nil, 0, e
		}
		seq, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return nil, 0, e
		}
		task := "retention-" + crypt.Digest([]byte(i.Actor+"\x00"+key+"\x00"+fp))
		id := (Job{Sequence: seq, Task: task}).ID()
		summary := out
		summary.Items = nil
		raw, e := json.Marshal(summary)
		if e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.jobs(tenant,sequence,task,queue,kind,payload)VALUES($1,$2,$3,'maintenance','repository.retention',$4)`, i.Tenant, seq, task, raw); e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.retention_runs(tenant,sequence,task,repository,name,revision,plan,requester_actor,requester_hash)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, i.Tenant, seq, task, repo, name, out.Policy.Revision, raw, i.Actor, i.CredentialHash); e != nil {
			return nil, 0, e
		}
		for _, item := range out.Items {
			raw, e := json.Marshal(item)
			if e != nil {
				return nil, 0, e
			}
			if _, e = tx.Exec(ctx, `INSERT INTO cratectl.retention_items(tenant,sequence,task,ordinal,target)VALUES($1,$2,$3,$4,$5)`, i.Tenant, seq, task, item.Ordinal, raw); e != nil {
				return nil, 0, e
			}
		}
		return map[string]any{"job": id, "plan": summary, "bytes_reclaimed": 0}, 202, nil
	})
}
