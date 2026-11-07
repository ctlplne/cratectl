// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrSourceChanged = errors.New("repository source configuration changed")
var ErrSourceRevalidation = errors.Join(ErrSourceChanged, errors.New("304 response has no body bound to the current source revision"))
var ErrConfigurationRevision = errors.New("repository configuration revision changed")
var ErrConfigurationInput = errors.New("invalid repository configuration request")

type ConfigurationRequest struct {
	ExpectedRevision int64               `json:"expected_revision"`
	Settings         *RepositorySettings `json:"settings"`
	Reason           string              `json:"reason"`
	DryRun           bool                `json:"dry_run"`
}
type ConfigurationPreview struct {
	Current          Repository         `json:"current"`
	Settings         RepositorySettings `json:"settings"`
	NextRevision     int64              `json:"next_revision"`
	ActiveRetrievals int                `json:"active_retrievals"`
	Groups           []string           `json:"groups"`
	MemberStates     []RepositoryState  `json:"member_states"`
	RefreshRequired  bool               `json:"refresh_required"`
	RetainedBytes    bool               `json:"retained_bytes"`
	DryRun           bool               `json:"dry_run"`
}
type ConfigurationChange struct {
	Revision         int64              `json:"revision"`
	PreviousRevision int64              `json:"previous_revision"`
	PreviousSettings RepositorySettings `json:"previous_settings"`
	Settings         RepositorySettings `json:"settings"`
	Reason           string             `json:"reason"`
	Actor            string             `json:"actor"`
	ChangedAt        time.Time          `json:"changed_at"`
	ChangeSequence   int64              `json:"change_sequence"`
}

func configurationPreview(ctx context.Context, tx pgx.Tx, i Identity, repo string, input ConfigurationRequest, budget int) (ConfigurationPreview, []string, error) {
	out := ConfigurationPreview{Groups: []string{}, MemberStates: []RepositoryState{}, RefreshRequired: true, RetainedBytes: true, DryRun: input.DryRun}
	if i.Role != "admin" {
		return out, nil, ErrDenied
	}
	if input.ExpectedRevision < 0 || input.Settings == nil || !validLifecycleReason(input.Reason) || strings.TrimSpace(input.Reason) == "" || budget < 1 || budget > 1000000 {
		return out, nil, ErrConfigurationInput
	}
	r, e := repositoryRecordInTx(ctx, tx, i, repo, "write")
	if e != nil {
		return out, nil, e
	}
	out.Current = r
	if r.SourceRevision != input.ExpectedRevision {
		return out, nil, ErrConfigurationRevision
	}
	if r.Mode != "proxy" && r.Mode != "group" && !(r.Mode == "hosted" && r.Format == "maven") {
		return out, nil, ErrConfigurationInput
	}
	out.RefreshRequired = r.Mode != "hosted"
	proposed := r
	proposed.SourceRevision = 0
	proposed.Settings = *input.Settings
	if validateRepository(&proposed, r.Format == "go" && r.Mode == "proxy") != nil {
		return out, nil, ErrConfigurationInput
	}
	if r.SourceRevision == int64(1<<63-1) {
		return out, nil, ErrConfigurationRevision
	}
	out.Settings = proposed.Settings
	out.NextRevision = r.SourceRevision + 1
	for _, name := range proposed.Settings.Members {
		member, e := repositoryRecordInTx(ctx, tx, i, name, "read")
		if e != nil {
			return out, nil, e
		}
		if member.Format != r.Format || member.Mode == "group" {
			return out, nil, ErrConfigurationInput
		}
		state, e := repositoryStateInTx(ctx, tx, name)
		if e != nil {
			return out, nil, e
		}
		out.MemberStates = append(out.MemberStates, state)
	}
	bytes := 8 << 20
	query := func(sql string) ([]string, error) {
		rows, e := tx.Query(ctx, sql, repo, budget+1)
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		values := []string{}
		for rows.Next() {
			var v string
			if e = rows.Scan(&v); e != nil {
				return nil, e
			}
			if len(values) >= budget || len(v) > 2048 || len(v) > bytes {
				return nil, ErrMetadataLimit
			}
			bytes -= len(v)
			values = append(values, v)
		}
		return values, rows.Err()
	}
	paths, e := query(`SELECT path FROM cratectl.retrievals WHERE repository=$1 AND state='fetching' ORDER BY path LIMIT $2`)
	if e != nil {
		return out, nil, e
	}
	out.ActiveRetrievals = len(paths)
	out.Groups, e = query(`SELECT name FROM cratectl.repositories WHERE mode='group' AND settings->'members' ? $1 ORDER BY name LIMIT $2`)
	return out, paths, e
}
func (s *Store) Configuration(ctx context.Context, i Identity, repo string) (Repository, error) {
	var r Repository
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		var e error
		r, e = repositoryRecordInTx(ctx, tx, i, repo, "read")
		return e
	})
	return r, e
}
func (s *Store) ConfigurationHistory(ctx context.Context, i Identity, repo string, after int64, limit int) ([]ConfigurationChange, error) {
	out := []ConfigurationChange{}
	if after < 0 || limit < 1 || limit > 1000 {
		return out, ErrConfigurationInput
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		if _, e := repositoryRecordInTx(ctx, tx, i, repo, "read"); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT revision,previous_revision,previous_settings,settings,reason,actor,changed_at,change_sequence FROM cratectl.repository_configurations WHERE repository=$1 AND revision>$2 ORDER BY revision LIMIT $3`, repo, after, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		remaining := 8 << 20
		for rows.Next() {
			var v ConfigurationChange
			var before, next []byte
			if e = rows.Scan(&v.Revision, &v.PreviousRevision, &before, &next, &v.Reason, &v.Actor, &v.ChangedAt, &v.ChangeSequence); e != nil {
				return e
			}
			remaining -= len(before) + len(next)
			if remaining < 0 {
				return ErrMetadataLimit
			}
			if json.Unmarshal(before, &v.PreviousSettings) != nil || json.Unmarshal(next, &v.Settings) != nil {
				return ErrConflict
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, e
}
func (s *Store) ChangeConfiguration(ctx context.Context, i Identity, repo, key, fp string, input ConfigurationRequest, budget int) (Result, error) {
	if input.DryRun {
		var out ConfigurationPreview
		e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
			var e error
			out, _, e = configurationPreview(ctx, tx, i, repo, input, budget)
			return e
		})
		return jsonResult(out, 200, e)
	}
	return s.mutateIntentChecked(ctx, i, key, fp, "repository.configuration.changed", true, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		_, e := repositoryRecordInTx(ctx, tx, i, repo, "write")
		return e
	}, func(tx pgx.Tx) (any, int, error) {
		out, paths, e := configurationPreview(ctx, tx, i, repo, input, budget)
		if e != nil {
			return nil, 0, e
		}
		sequence, e := nextEventSequence(ctx, tx, i)
		if e != nil {
			return nil, 0, e
		}
		before, e := json.Marshal(out.Current.Settings)
		if e != nil {
			return nil, 0, e
		}
		settings, e := json.Marshal(out.Settings)
		if e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.repository_configurations(tenant,repository,revision,previous_revision,previous_settings,settings,reason,actor,change_sequence)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, i.Tenant, repo, out.NextRevision, out.Current.SourceRevision, before, settings, input.Reason, i.Actor, sequence); e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `UPDATE cratectl.repositories SET settings=$1,source_revision=$2 WHERE name=$3`, settings, out.NextRevision, repo); e != nil {
			return nil, 0, e
		}
		if _, e = tx.Exec(ctx, `UPDATE cratectl.retrievals SET generation=generation+1,state='failed',lease_until='epoch',fresh_until='epoch',stale_until='epoch',last_error='source_configuration_changed',changed_at=clock_timestamp(),change_sequence=$3 WHERE repository=$1 AND path=ANY($2::text[])`, repo, paths, sequence); e != nil {
			return nil, 0, e
		}
		out.Current, e = repositoryRecordInTx(ctx, tx, i, repo, "read")
		return out, 200, e
	})
}

func repositoryReadBudget(r Repository) *graphBudget {
	b := newGraphBudget()
	if r.Mode == "proxy" {
		b.sourceRevision = &r.SourceRevision
	}
	return b
}

// SourceSnapshot binds a resolved artifact to the source and group settings
// that selected it. Admission checks it alongside grants and artifact policy
// in the same read transaction, rather than across separate snapshots.
type SourceSnapshot struct {
	Repository string
	Revision   int64
	Groups     map[string]int64
}

func checkSourceSnapshot(ctx context.Context, tx pgx.Tx, i Identity, source Repository, snapshot SourceSnapshot) (bool, error) {
	review := source.RequireReview
	if snapshot.Repository != source.Name || snapshot.Revision != source.SourceRevision || len(snapshot.Groups) > 32 {
		return review, ErrSourceChanged
	}
	for name, revision := range snapshot.Groups {
		group, e := repositoryInTx(ctx, tx, i, name, "read")
		if e != nil {
			return review, e
		}
		if group.Mode != "group" || group.Format != source.Format || group.SourceRevision != revision {
			return review, ErrSourceChanged
		}
		member := false
		for _, name := range group.Settings.Members {
			if name == source.Name {
				member = true
				break
			}
		}
		if !member {
			return review, ErrSourceChanged
		}
		review = review || group.RequireReview
	}
	return review, nil
}
