// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

const PythonCatalogMedia = "application/vnd.cratectl.python-catalog+json"

var ErrPythonUnvalidated = errors.New("Python archive metadata has not been validated")

type PythonFile struct {
	Name           string  `json:"name"`
	Filename       string  `json:"filename"`
	Version        string  `json:"version"`
	RequiresPython string  `json:"requires_python,omitempty"`
	Yanked         *string `json:"yanked,omitempty"`
	CoreAvailable  bool    `json:"core_available"`
	CoreIntegrity  string  `json:"core_integrity,omitempty"`
	CoreMetadata   string  `json:"core_metadata,omitempty"`
	CoreSHA256     string  `json:"core_sha256,omitempty"`
	Validated      bool    `json:"archive_validated"`
	Integrity      string  `json:"integrity,omitempty"`
	Size           *int64  `json:"size,omitempty"`
	SourceKey      string  `json:"source_key,omitempty"`
	SourceURL      string  `json:"source_url,omitempty"`
}

// PythonProjects is the authorized local inventory, including cached catalogs.
// It does not claim to enumerate an upstream service's entire project corpus.
func (s *Store) PythonProjects(ctx context.Context, i Identity, repo string, limit int, maxBytes int64) ([]string, error) {
	var names []string
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		_, members, e := nativeRepositories(ctx, tx, i, repo, "", "pypi")
		if e != nil {
			return e
		}
		seen := map[string]bool{}
		for _, r := range members {
			rows, e := tx.Query(ctx, `SELECT DISTINCT metadata->>'name' FROM cratectl.artifacts WHERE repository=$1 AND metadata->>'name' IS NOT NULL ORDER BY 1 LIMIT $2`, r.Name, limit+1)
			if e != nil {
				return e
			}
			for rows.Next() {
				var name string
				if e = rows.Scan(&name); e != nil {
					rows.Close()
					return e
				}
				seen[name] = true
				if len(seen) > limit {
					rows.Close()
					return ErrMetadataLimit
				}
			}
			rows.Close()
			if e = rows.Err(); e != nil {
				return e
			}
		}
		for name := range seen {
			view, e := pythonViewInTx(ctx, tx, i, repo, name, limit, maxBytes)
			if e != nil {
				return e
			}
			visible := false
			first := map[string]bool{}
			for _, member := range view {
				for _, file := range member.Files {
					if first[file.File.Filename] {
						continue
					}
					first[file.File.Filename] = true
					if !file.Blocked {
						visible = true
					}
				}
			}
			if visible {
				names = append(names, name)
			}
		}
		return nil
	})
	return names, e
}

type PythonCatalog struct {
	Name  string            `json:"name"`
	Files map[string]string `json:"files"`
}

func PythonCatalogPath(name string) string { return "pypi-catalog/" + name }
func PythonBlobPath(name, key, filename string) string {
	return "pypi-packages/" + name + "/" + key + "/" + filename
}

func (s *Store) PublishPython(ctx context.Context, i Identity, repo string, a Artifact) error {
	var metadata PythonFile
	if json.Unmarshal(a.Metadata, &metadata) != nil || !metadata.Validated || metadata.Filename != a.Path {
		return ErrConflict
	}
	_, e := s.MutateRepository(ctx, i, repo, "", "", "python.distribution.published", func(tx pgx.Tx) (any, int, error) {
		r, e := repositoryInTx(ctx, tx, i, repo, "write")
		if e != nil {
			return nil, 0, e
		}
		if r.Format != "pypi" {
			return nil, 0, ErrConflict
		}
		if e = InsertArtifacts(ctx, tx, i, repo, []Artifact{a}); e != nil {
			return nil, 0, e
		}
		// A same-byte replay may safely enrich pre-validation development records.
		_, e = tx.Exec(ctx, `UPDATE cratectl.artifacts SET metadata=$1 WHERE repository=$2 AND path=$3 AND digest=$4`, a.Metadata, repo, a.Path, a.Digest)
		if e != nil {
			return nil, 0, e
		}
		var stored Artifact
		e = scanArtifact(tx.QueryRow(ctx, `SELECT `+artifactColumns+` FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND a.path=$2`, repo, a.Path), &stored)
		return stored, 200, e
	})
	return e
}
func SetPythonYank(ctx context.Context, tx pgx.Tx, i Identity, repo, filename string, yanked bool, reason string) (any, error) {
	if i.Role != "admin" || len(reason) > 4096 {
		return nil, ErrDenied
	}
	r, e := repositoryInTx(ctx, tx, i, repo, "write")
	if e != nil {
		return nil, e
	}
	if r.Format != "pypi" || r.Mode != "hosted" {
		return nil, ErrConflict
	}
	var exists bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=$2)`, repo, filename).Scan(&exists); e != nil {
		return nil, e
	}
	if !exists {
		return nil, ErrNotFound
	}
	var revision int64
	e = tx.QueryRow(ctx, `INSERT INTO cratectl.python_yanks(tenant,repository,filename,yanked,reason) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant,repository,filename) DO UPDATE SET yanked=excluded.yanked,reason=excluded.reason,revision=cratectl.python_yanks.revision+1,updated_at=now() RETURNING revision`, i.Tenant, repo, filename, yanked, reason).Scan(&revision)
	return map[string]any{"repository": repo, "filename": filename, "yanked": yanked, "reason": reason, "revision": revision}, e
}

type PythonFileView struct {
	File                         PythonFile
	Path, Key, Digest, Integrity string
	Size                         int64
	Blocked                      bool
}
type PythonMember struct {
	Repository Repository
	Files      []PythonFileView
}

func (s *Store) PythonView(ctx context.Context, i Identity, repo, name string, maxFiles int, maxBytes int64) ([]PythonMember, error) {
	var out []PythonMember
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var e error
		out, e = pythonViewInTx(ctx, tx, i, repo, name, maxFiles, maxBytes)
		return e
	})
	return out, e
}
func pythonViewInTx(ctx context.Context, tx pgx.Tx, i Identity, repo, name string, maxFiles int, maxBytes int64) ([]PythonMember, error) {
	var out []PythonMember
	if maxFiles <= 0 || maxBytes <= 0 {
		return nil, ErrMetadataLimit
	}
	e := func() error {
		group, members, e := nativeRepositories(ctx, tx, i, repo, name, "pypi")
		if e != nil {
			return e
		}
		remaining, count := maxBytes, 0
		for _, r := range members {
			member := PythonMember{Repository: r}
			cached := map[string]Artifact{}
			denied := map[string]bool{}
			columns := `a.repository,a.path,a.digest,a.size,a.media_type,a.metadata-'core_metadata',COALESCE(d.decision,a.decision),a.created_at`
			rows, e := tx.Query(ctx, `SELECT `+columns+` FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND a.metadata->>'name'=$2 AND a.media_type<>$3 ORDER BY a.path LIMIT $4`, r.Name, name, PythonCatalogMedia, maxFiles+1)
			if e != nil {
				return e
			}
			for rows.Next() {
				var a Artifact
				if e = scanArtifact(rows, &a); e != nil {
					rows.Close()
					return e
				}
				remaining -= int64(len(a.Metadata))
				if len(cached) >= maxFiles || remaining < 0 {
					rows.Close()
					return ErrMetadataLimit
				}
				cached[a.Path] = a
				var file PythonFile
				if json.Unmarshal(a.Metadata, &file) != nil {
					rows.Close()
					return ErrConflict
				}
				if a.Decision == "denied" && file.Integrity != "" {
					denied[file.Integrity] = true
				}
				if r.Mode == "hosted" {
					member.Files = append(member.Files, PythonFileView{File: file, Path: a.Path, Digest: a.Digest, Size: a.Size, Blocked: !file.Validated || a.Decision == "denied" || ((r.RequireReview || group.RequireReview) && a.Decision != "allowed")})
				}
			}
			rows.Close()
			if e = rows.Err(); e != nil {
				return e
			}
			if r.Mode == "hosted" {
				paths := []string{}
				for _, f := range member.Files {
					paths = append(paths, f.Path)
				}
				yanks, e := tx.Query(ctx, `SELECT filename,yanked,reason FROM cratectl.python_yanks WHERE repository=$1 AND filename=ANY($2::text[]) LIMIT $3`, r.Name, paths, maxFiles+1)
				if e != nil {
					return e
				}
				values := map[string]*string{}
				for yanks.Next() {
					var filename, reason string
					var yanked bool
					if e = yanks.Scan(&filename, &yanked, &reason); e != nil {
						yanks.Close()
						return e
					}
					if yanked {
						copy := reason
						values[filename] = &copy
					}
				}
				yanks.Close()
				if e = yanks.Err(); e != nil {
					return e
				}
				for n := range member.Files {
					member.Files[n].File.Yanked = values[member.Files[n].Path]
				}
			} else {
				var state Retrieval
				e = scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, r.Name, PythonCatalogPath(name)), &state)
				if errors.Is(e, pgx.ErrNoRows) || (e == nil && state.State == "negative") {
					out = append(out, member)
					continue
				}
				if e != nil {
					return e
				}
				if state.State == "failed" && !state.StalePermitted() {
					return ErrBusy
				}
				a, e := nativeCatalogArtifact(ctx, tx, i, r.Name, name, "pypi", PythonCatalogMedia)
				if e != nil {
					return e
				}
				remaining -= int64(len(a.Metadata))
				if remaining < 0 {
					return ErrMetadataLimit
				}
				var catalog PythonCatalog
				if json.Unmarshal(a.Metadata, &catalog) != nil || catalog.Name != name || len(catalog.Files) > maxFiles {
					return ErrMetadataLimit
				}
				keys := []string{}
				for _, key := range catalog.Files {
					keys = append(keys, key)
				}
				sources, e := tx.Query(ctx, `SELECT key,format,package,coordinate,version,url,integrity,metadata FROM cratectl.native_sources WHERE repository=$1 AND format='pypi' AND key=ANY($2::text[]) LIMIT $3`, r.Name, keys, maxFiles+1)
				if e != nil {
					return e
				}
				for sources.Next() {
					var source NativeSource
					if e = sources.Scan(&source.Key, &source.Format, &source.Name, &source.Coordinate, &source.Version, &source.URL, &source.Integrity, &source.Metadata); e != nil {
						sources.Close()
						return e
					}
					if source.Name != name || catalog.Files[source.Coordinate] != source.Key {
						sources.Close()
						return ErrConflict
					}
					remaining -= int64(len(source.Metadata))
					if remaining < 0 {
						sources.Close()
						return ErrMetadataLimit
					}
					var file PythonFile
					if json.Unmarshal(source.Metadata, &file) != nil || file.Filename != source.Coordinate {
						sources.Close()
						return ErrConflict
					}
					v := PythonFileView{File: file, Key: source.Key, Path: PythonBlobPath(name, source.Key, file.Filename), Integrity: source.Integrity, Size: -1}
					decision := "unassessed"
					if denied[source.Integrity] {
						decision = "denied"
					}
					if a, ok := cached[v.Path]; ok {
						var actual PythonFile
						if json.Unmarshal(a.Metadata, &actual) != nil {
							sources.Close()
							return ErrConflict
						}
						actual.Yanked = file.Yanked
						v.File = actual
						v.Size = a.Size
						v.Digest = a.Digest
						decision = a.Decision
					}
					v.Blocked = decision == "denied" || ((r.RequireReview || group.RequireReview) && (!v.File.Validated || decision != "allowed"))
					member.Files = append(member.Files, v)
				}
				sources.Close()
				if e = sources.Err(); e != nil {
					return e
				}
				if len(member.Files) != len(catalog.Files) {
					return ErrConflict
				}
				paths := []string{}
				for _, f := range member.Files {
					paths = append(paths, f.Path)
				}
				bad, e := tx.Query(ctx, `SELECT path FROM cratectl.retrievals WHERE repository=$1 AND path=ANY($2::text[]) AND ((state='negative' AND fresh_until>clock_timestamp()) OR (state='failed' AND last_error IN ('upstream_integrity_failure','upstream_python_metadata_mismatch','upstream_archive_invalid','upstream_authority_failure'))) LIMIT $3`, r.Name, paths, maxFiles+1)
				if e != nil {
					return e
				}
				blocked := map[string]bool{}
				for bad.Next() {
					var p string
					if e = bad.Scan(&p); e != nil {
						bad.Close()
						return e
					}
					blocked[p] = true
				}
				bad.Close()
				if e = bad.Err(); e != nil {
					return e
				}
				for n := range member.Files {
					if blocked[member.Files[n].Path] {
						member.Files[n].Blocked = true
					}
				}
			}
			count += len(member.Files)
			if count > maxFiles {
				return ErrMetadataLimit
			}
			out = append(out, member)
		}
		return nil
	}()
	return out, e
}
