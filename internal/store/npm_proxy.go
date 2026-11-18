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

const NPMCatalogMedia = "application/vnd.cratectl.npm-catalog+json"

func NPMCatalogPath(name string) string   { return "npm-catalog/" + name }
func NPMBlobPath(name, key string) string { return name + "/-/cratectl/" + key + ".tgz" }

type NPMSource struct {
	Key       string          `json:"key"`
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Tarball   string          `json:"tarball"`
	Integrity string          `json:"integrity"`
	Package   json.RawMessage `json:"package"`
}
type NPMCatalog struct {
	Name     string            `json:"name"`
	Versions map[string]string `json:"versions"`
	Tags     map[string]string `json:"dist-tags"`
}

func npmCatalogArtifact(ctx context.Context, tx pgx.Tx, i Identity, repo, name string) (Artifact, error) {
	return nativeCatalogArtifact(ctx, tx, i, repo, name, "npm", NPMCatalogMedia)
}

// Catalog discovery is not package approval. Require-review is applied to each
// package version, rather than treating the catalog itself as a package tarball.
func (s *Store) NPMCatalogArtifact(ctx context.Context, i Identity, repo, name string) (Artifact, error) {
	var a Artifact
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error { var e error; a, e = npmCatalogArtifact(ctx, tx, i, repo, name); return e })
	return a, e
}
func (s *Store) NPMSource(ctx context.Context, i Identity, repo, key string, expected ...int64) (NPMSource, error) {
	source, e := s.NativeSource(ctx, i, repo, key, "npm", expected...)
	return NPMSource{Key: source.Key, Name: source.Name, Version: source.Version, Tarball: source.URL, Integrity: source.Integrity, Package: source.Metadata}, e
}

// MembersForPath applies longest-prefix namespace ownership before fallback or
// metadata union. For npm the caller passes name+"/", covering the exact package.
func MembersForPath(r Repository, p string) []string {
	if r.Mode != "group" {
		return []string{r.Name}
	}
	longest, owner := "", ""
	for prefix, member := range r.Settings.NamespaceOwners {
		if strings.HasPrefix(p, prefix) && len(prefix) > len(longest) {
			longest, owner = prefix, member
		}
	}
	if owner != "" {
		return []string{owner}
	}
	return r.Settings.Members
}
func npmRepositories(ctx context.Context, tx pgx.Tx, i Identity, repo, name string) (Repository, []Repository, error) {
	return nativeRepositories(ctx, tx, i, repo, name, "npm")
}
func (s *Store) NPMRepositories(ctx context.Context, i Identity, repo, name string) ([]Repository, error) {
	var out []Repository
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		_, members, e := npmRepositories(ctx, tx, i, repo, name)
		out = members
		return e
	})
	return out, e
}

type NPMVersion struct {
	Version string
	Path    string
	Key     string
	Package json.RawMessage
	Blocked bool
	created time.Time
}
type NPMMember struct {
	Repository Repository
	Versions   []NPMVersion
	Tags       map[string]string
}

type NPMSelected struct {
	Version NPMVersion
	Source  Repository
}

// MergeNPMMembers preserves the first version and tag authority even when the
// selected coordinate is currently blocked.
func MergeNPMMembers(members []NPMMember) (map[string]NPMSelected, map[string]string) {
	versions := map[string]NPMSelected{}
	tags := map[string]string{}
	seenTags := map[string]bool{}
	for _, member := range members {
		for _, version := range member.Versions {
			if _, seen := versions[version.Version]; !seen {
				versions[version.Version] = NPMSelected{Version: version, Source: member.Repository}
			}
		}
		for tag, version := range member.Tags {
			if seenTags[tag] {
				continue
			}
			seenTags[tag] = true
			if v, ok := versions[version]; ok && v.Source.Name == member.Repository.Name && !v.Version.Blocked {
				tags[tag] = version
			}
		}
	}
	return versions, tags
}

// NPMView rereads grants, group policy, source catalogs and digest decisions in
// one snapshot after network cache fills. Blocked version coordinates remain in
// the result so a lower-priority source cannot replace a denied collision.
func (s *Store) NPMView(ctx context.Context, i Identity, repo, name string, maxVersions, maxTags int, maxBytes int64) ([]NPMMember, error) {
	var out []NPMMember
	if maxVersions <= 0 || maxTags <= 0 || maxBytes <= 0 {
		return nil, ErrMetadataLimit
	}
	budget := npmViewBudget{versions: maxVersions, tags: maxTags, bytes: maxBytes}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var e error
		out, e = npmViewInTx(ctx, tx, i, repo, name, &budget, false)
		return e
	})
	return out, e
}

type npmViewBudget struct {
	versions int
	tags     int
	bytes    int64
}

func npmViewInTx(ctx context.Context, tx pgx.Tx, i Identity, repo, name string, budget *npmViewBudget, cachedSearch bool) ([]NPMMember, error) {
	var out []NPMMember
	maxVersions, maxTags := budget.versions, budget.tags
	group, members, e := npmRepositories(ctx, tx, i, repo, name)
	if e != nil {
		if cachedSearch && (errors.Is(e, ErrDenied) || errors.Is(e, ErrNotFound) ||
			errors.Is(e, ErrRepositorySuspended) || errors.Is(e, ErrRepositoryRemoved)) {
			return out, errNPMSearchCatalog
		}
		return out, e
	}
	var known map[string]Retrieval
	if cachedSearch {
		known, e = npmSearchCatalogs(ctx, tx, members, name)
		if e != nil {
			return out, e
		}
	}
	remaining := budget.bytes
	count := 0
	for _, r := range members {
		member := NPMMember{Repository: r, Tags: map[string]string{}}
		rows, e := tx.Query(ctx, `SELECT `+artifactColumns+`,COALESCE(nl.deleted,false) FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+` WHERE a.repository=$1 AND starts_with(a.path,$2) AND ($4::boolean OR a.source_revision=$5) ORDER BY a.path LIMIT $3`, r.Name, name+"/-/", maxVersions+1, r.Mode != "proxy", r.SourceRevision)
		if e != nil {
			return out, e
		}
		cached := map[string]Artifact{}
		integrityDecisions := map[string]string{}
		for rows.Next() {
			var a Artifact
			if e = scanNativeArtifact(rows, &a); e != nil {
				rows.Close()
				return out, e
			}
			remaining -= int64(len(a.Metadata))
			if len(cached) >= maxVersions || remaining < 0 {
				rows.Close()
				return out, ErrMetadataLimit
			}
			cached[a.Path] = a
			var m struct {
				Integrity string          `json:"integrity"`
				Version   string          `json:"version"`
				Package   json.RawMessage `json:"package"`
			}
			if json.Unmarshal(a.Metadata, &m) != nil {
				rows.Close()
				return out, ErrConflict
			}
			if m.Integrity != "" && (a.Decision == "denied" || integrityDecisions[m.Integrity] == "") {
				integrityDecisions[m.Integrity] = a.Decision
			}
			if r.Mode == "hosted" {
				member.Versions = append(member.Versions, NPMVersion{Version: m.Version, Path: a.Path, Package: m.Package, created: a.Created, Blocked: a.Deleted || a.Decision == "denied" || ((r.RequireReview || group.RequireReview) && a.Decision != "allowed")})
			}
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return out, e
		}
		if r.Mode == "hosted" {
			tags, e := tx.Query(ctx, `SELECT tag,version FROM cratectl.npm_tags WHERE repository=$1 AND package=$2 AND NOT deleted ORDER BY tag LIMIT $3`, r.Name, name, maxTags+1)
			if e != nil {
				return out, e
			}
			for tags.Next() {
				var tag, version string
				if e = tags.Scan(&tag, &version); e != nil {
					tags.Close()
					return out, e
				}
				member.Tags[tag] = version
				if len(member.Tags) > maxTags {
					tags.Close()
					return out, ErrMetadataLimit
				}
			}
			tags.Close()
			if e = tags.Err(); e != nil {
				return out, e
			}
		} else {
			state := known[r.Name]
			if !cachedSearch {
				state, e = npmCatalogRetrieval(ctx, tx, r.Name, name)
			}
			if errors.Is(e, pgx.ErrNoRows) || (e == nil && state.State == "negative") {
				out = append(out, member)
				continue
			}
			if e != nil {
				return out, e
			}
			if state.State == "failed" && !state.StalePermitted() {
				return out, ErrBusy
			}
			a, e := npmCatalogArtifact(ctx, tx, i, r.Name, name)
			if e != nil {
				return out, e
			}
			remaining -= int64(len(a.Metadata))
			if remaining < 0 {
				return out, ErrMetadataLimit
			}
			var catalog NPMCatalog
			if json.Unmarshal(a.Metadata, &catalog) != nil || catalog.Name != name || len(catalog.Versions) > maxVersions || len(catalog.Tags) > maxTags {
				return out, ErrMetadataLimit
			}
			keys := make([]string, 0, len(catalog.Versions))
			for _, key := range catalog.Versions {
				keys = append(keys, key)
			}
			sources, e := tx.Query(ctx, `SELECT key,package,version,url,integrity,metadata FROM cratectl.native_sources WHERE format='npm' AND repository=$1 AND key=ANY($2::text[]) AND source_revision=$4 LIMIT $3`, r.Name, keys, maxVersions+1, r.SourceRevision)
			if e != nil {
				return out, e
			}
			for sources.Next() {
				var source NPMSource
				if e = sources.Scan(&source.Key, &source.Name, &source.Version, &source.Tarball, &source.Integrity, &source.Package); e != nil {
					sources.Close()
					return out, e
				}
				if source.Name != name || catalog.Versions[source.Version] != source.Key {
					sources.Close()
					return out, ErrConflict
				}
				remaining -= int64(len(source.Package))
				if remaining < 0 {
					sources.Close()
					return out, ErrMetadataLimit
				}
				v := NPMVersion{Version: source.Version, Key: source.Key, Path: NPMBlobPath(name, source.Key), Package: source.Package}
				// A known denial may block aliases before retrieval. Approval
				// requires this descriptor's archive/metadata binding to have
				// been validated, even if another URL has the same SRI set.
				decision := "unassessed"
				if integrityDecisions[source.Integrity] == "denied" {
					decision = "denied"
				}
				if a, ok := cached[v.Path]; ok {
					decision = a.Decision
					v.created = a.Created
					v.Blocked = a.Deleted
					var m struct {
						Package json.RawMessage `json:"package"`
					}
					if json.Unmarshal(a.Metadata, &m) != nil {
						sources.Close()
						return out, ErrConflict
					}
					v.Package = m.Package
				}
				v.Blocked = v.Blocked || decision == "denied" || ((r.RequireReview || group.RequireReview) && decision != "allowed")
				if cachedSearch && v.created.IsZero() {
					v.Blocked = true
				}
				member.Versions = append(member.Versions, v)
			}
			sources.Close()
			if e = sources.Err(); e != nil {
				return out, e
			}
			if len(member.Versions) != len(catalog.Versions) {
				return out, ErrConflict
			}
			member.Tags = catalog.Tags
			// A source already observed to contain invalid bytes or a forged
			// package graph must not be advertised again as a usable version.
			paths := make([]string, 0, len(member.Versions))
			for _, v := range member.Versions {
				paths = append(paths, v.Path)
			}
			failed, e := tx.Query(ctx, `SELECT path FROM cratectl.retrievals WHERE repository=$1 AND path=ANY($2::text[]) AND ((state='negative' AND fresh_until>clock_timestamp()) OR (state='failed' AND last_error IN ('upstream_integrity_failure','upstream_package_metadata_mismatch','upstream_authority_failure'))) LIMIT $3`, r.Name, paths, maxVersions+1)
			if e != nil {
				return out, e
			}
			blocked := map[string]bool{}
			for failed.Next() {
				var p string
				if e = failed.Scan(&p); e != nil {
					failed.Close()
					return out, e
				}
				blocked[p] = true
			}
			failed.Close()
			if e = failed.Err(); e != nil {
				return out, e
			}
			for n := range member.Versions {
				if blocked[member.Versions[n].Path] {
					member.Versions[n].Blocked = true
				}
			}
		}
		count += len(member.Versions)
		if count > maxVersions {
			return out, ErrMetadataLimit
		}
		out = append(out, member)
	}
	budget.versions -= count
	budget.bytes = remaining
	return out, nil
}

func npmCatalogRetrieval(ctx context.Context, tx pgx.Tx, repo, name string) (Retrieval, error) {
	var state Retrieval
	err := scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, repo, NPMCatalogPath(name)), &state)
	return state, err
}

// Search may use current catalog data or a current negative result. A missing
// or expired catalog cannot establish that a lower group member may answer.
func npmSearchCatalogs(ctx context.Context, tx pgx.Tx, members []Repository, name string) (map[string]Retrieval, error) {
	known := map[string]Retrieval{}
	for _, member := range members {
		if member.Mode != "proxy" {
			continue
		}
		state, err := npmCatalogRetrieval(ctx, tx, member.Name, name)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errNPMSearchCatalog
		}
		if err != nil {
			return nil, err
		}
		current := (state.State == "ready" || state.State == "negative") && state.Fresh()
		stale := state.State == "failed" && member.Settings.Cache.StaleSeconds > 0 && state.StalePermitted()
		if state.SourceRevision != member.SourceRevision || (!current && !stale) {
			return nil, errNPMSearchCatalog
		}
		known[member.Name] = state
	}
	return known, nil
}
