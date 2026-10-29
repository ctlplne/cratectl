// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"encoding/json"
	"errors"
	"path"

	"github.com/jackc/pgx/v5"
)

type MavenMember struct {
	Repository      Repository
	Catalog         *Artifact
	Artifacts       []Artifact
	CacheGeneration int64
	CacheState      string
}
type MavenView struct {
	Group   Repository
	Members []MavenMember
}

var ErrMavenSourceChanged = errors.New("Maven catalog does not belong to the current source authority")

func mavenChecksumReceipt(repo, p, algorithm, sum string) (string, string) {
	fingerprint := "maven-metadata-checksum:" + repo + "\n" + p + "\n" + algorithm + "\n" + sum
	return "maven-metadata-" + crypt.Digest([]byte(fingerprint)), fingerprint
}
func insertMavenChecksumReceipts(ctx context.Context, tx pgx.Tx, i Identity, repo string, a Artifact, sums map[string]string) error {
	response, e := json.Marshal(map[string]any{"repository": repo, "path": a.Path, "digest": a.Digest, "size": a.Size})
	if e != nil {
		return e
	}
	for algorithm, sum := range sums {
		key, fingerprint := mavenChecksumReceipt(repo, a.Path, algorithm, sum)
		if _, e = tx.Exec(ctx, `INSERT INTO cratectl.mutations(tenant,actor,key,fingerprint,response,status)VALUES($1,$2,$3,$4,$5,201)ON CONFLICT(tenant,actor,key)DO NOTHING`, i.Tenant, i.Actor, key, fingerprint, response); e != nil {
			return e
		}
	}
	return nil
}

// Native publisher receipts share the original reference/event/job transaction.
// They validate accepted historical bytes without changing today's checksum.
func (s *Store) ReplaceMavenMetadata(ctx context.Context, i Identity, repo string, a Artifact, sums map[string]string) error {
	return s.replaceMetadata(ctx, i, repo, a, sums)
}
func (s *Store) MavenChecksumReceipt(ctx context.Context, i Identity, repo, p, algorithm, sum string) error {
	return s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "write")
		if e != nil {
			return e
		}
		if r.Format != "maven" || r.Mode != "hosted" || !i.CanWrite() {
			return ErrDenied
		}
		key, fingerprint := mavenChecksumReceipt(repo, p, algorithm, sum)
		var found bool
		e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.mutations WHERE actor=$1 AND key=$2 AND fingerprint=$3 AND status=201)`, i.Actor, key, fingerprint).Scan(&found)
		if e != nil {
			return e
		}
		if !found {
			return ErrNotFound
		}
		return nil
	})
}

func (s *Store) MavenCatalogArtifact(ctx context.Context, i Identity, repo, p string) (Artifact, error) {
	var a Artifact
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != "maven" || path.Base(p) != "maven-metadata.xml" {
			return ErrConflict
		}
		a, e = readArtifact(ctx, tx, repo, p, false, newGraphBudget())
		return e
	})
	return a, e
}

// MavenMetadataView rereads every consulted grant and current digest decision
// in one snapshot. Blocked references are retained to prevent group fallthrough.
func (s *Store) MavenMetadataView(ctx context.Context, i Identity, repo, p string, maxRecords int, maxBytes int64) (MavenView, error) {
	var view MavenView
	if maxRecords < 1 || maxBytes < 1 {
		return view, ErrMetadataLimit
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		group, members, e := nativeRepositories(ctx, tx, i, repo, path.Dir(p), "maven")
		if e != nil {
			return e
		}
		view.Group = group
		remaining, bytes := maxRecords, maxBytes
		for _, r := range members {
			member := MavenMember{Repository: r, Artifacts: []Artifact{}}
			rows, e := tx.Query(ctx, `SELECT a.repository,a.path,a.digest,a.size,a.media_type,CASE WHEN a.path=$4 THEN a.metadata ELSE '{}'::jsonb END,COALESCE(d.decision,a.decision),a.created_at FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND starts_with(a.path,$2) ORDER BY a.path LIMIT $3`, r.Name, path.Dir(p)+"/", remaining+1, p)
			if e != nil {
				return e
			}
			for rows.Next() {
				var a Artifact
				if e = scanArtifact(rows, &a); e != nil {
					rows.Close()
					return e
				}
				remaining--
				bytes -= int64(len(a.Path) + len(a.Digest) + len(a.MediaType) + len(a.Metadata) + 128)
				if remaining < 0 || bytes < 0 {
					rows.Close()
					return ErrMetadataLimit
				}
				if a.Path == p {
					if a.Size > maxBytes {
						rows.Close()
						return ErrMetadataLimit
					}
					if a.Decision == "denied" {
						rows.Close()
						return ErrDenied
					}
					copy := a
					member.Catalog = &copy
				} else {
					member.Artifacts = append(member.Artifacts, a)
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			if r.Mode == "proxy" {
				if member.Catalog != nil {
					var binding struct {
						Authority string `json:"source_authority"`
						Path      string `json:"source_path"`
					}
					if json.Unmarshal(member.Catalog.Metadata, &binding) != nil || r.Settings.Upstream == nil || binding.Authority != r.Settings.Upstream.URL || binding.Path != p {
						return ErrMavenSourceChanged
					}
				}
				var retrieval Retrieval
				e = scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, r.Name, p), &retrieval)
				if errors.Is(e, pgx.ErrNoRows) {
					return ErrNotFound
				}
				if e != nil {
					return e
				}
				member.CacheGeneration = retrieval.Generation
				member.CacheState = retrieval.State
				switch retrieval.State {
				case "negative":
					member.Catalog = nil
					member.Artifacts = nil
				case "fetching":
					return ErrBusy
				case "failed":
					if !retrieval.StalePermitted() {
						return ErrBusy
					}
				case "ready":
				default:
					return ErrBusy
				}
			}
			view.Members = append(view.Members, member)
		}
		return nil
	})
	return view, e
}
