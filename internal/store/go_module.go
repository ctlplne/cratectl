// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"unicode"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

var ErrGoModuleUnvalidated = errors.New("Go module representations lack a complete validated bundle")

const GoModuleProfile = "go-module-bundle-v1"
const MaxGoModuleMetadata = 4096

var goMedia = map[string]string{"zip": "application/zip", "mod": "text/plain; charset=utf-8", "info": "application/json"}

type GoModuleMetadata struct {
	Profile string            `json:"go_module_profile"`
	Module  string            `json:"module"`
	Version string            `json:"version"`
	Digests map[string]string `json:"representations_sha256"`
}

func ValidateGoModuleArtifact(a Artifact) (GoModuleMetadata, error) {
	var m GoModuleMetadata
	if len(a.Metadata) > MaxGoModuleMetadata || json.Unmarshal(a.Metadata, &m) != nil || m.Profile != GoModuleProfile || len(m.Digests) != 3 {
		return m, ErrGoModuleUnvalidated
	}
	request, e := gomodule.ParseRequest(a.Path)
	if e != nil || request.Version == "" || request.Module != m.Module || request.Version != m.Version || a.MediaType != goMedia[request.Operation] || a.Digest != m.Digests[request.Operation] {
		return m, ErrGoModuleUnvalidated
	}
	for _, kind := range []string{"zip", "mod", "info"} {
		digest := m.Digests[kind]
		if len(digest) != 64 || strings.ToLower(digest) != digest {
			return m, ErrGoModuleUnvalidated
		}
		if _, e := hex.DecodeString(digest); e != nil {
			return m, ErrGoModuleUnvalidated
		}
	}
	return m, nil
}

func validateGoModuleBundle(as []Artifact) (GoModuleMetadata, error) {
	if len(as) != 3 {
		return GoModuleMetadata{}, ErrGoModuleUnvalidated
	}
	var bundle GoModuleMetadata
	seen := map[string]bool{}
	for _, a := range as {
		m, e := ValidateGoModuleArtifact(a)
		if e != nil {
			return m, e
		}
		if bundle.Profile == "" {
			bundle = m
		} else if m.Module != bundle.Module || m.Version != bundle.Version || !maps.Equal(m.Digests, bundle.Digests) {
			return m, ErrGoModuleUnvalidated
		}
		if seen[a.Path] {
			return m, ErrGoModuleUnvalidated
		}
		seen[a.Path] = true
	}
	return bundle, nil
}

// PublishGoModule commits the complete immutable version with integrity intents,
// journal and outbox. Every object must already be durably staged and inspected.
func (s *Store) PublishGoModule(ctx context.Context, i Identity, repo string, as []Artifact, key string) (Result, error) {
	m, e := validateGoModuleBundle(as)
	if e != nil {
		return Result{}, e
	}
	if len(key) > 200 || !utf8.ValidString(key) || strings.ContainsFunc(key, unicode.IsControl) {
		return Result{}, ErrConflict
	}
	raw, _ := json.Marshal(m)
	fingerprint := crypt.Digest(append([]byte("go.module.published\x00"+repo+"\x00"), raw...))
	if key == "" {
		key = "go-module:" + crypt.Digest([]byte(repo+"\x00"+m.Module+"\x00"+m.Version))
	}
	authorize := func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "write")
		if e != nil {
			return e
		}
		if r.Format != "go" || r.Mode != "hosted" {
			return ErrConflict
		}
		return nil
	}
	return s.mutateIntentChecked(ctx, i, key, fingerprint, "go.module.published", true, authorize, func(tx pgx.Tx) (any, int, error) {
		if e := InsertArtifacts(ctx, tx, i, repo, as); e != nil {
			return nil, 0, e
		}
		return map[string]any{"repository": repo, "module": m.Module, "version": m.Version, "representations_sha256": m.Digests}, 201, nil
	})
}

// All three representations are one policy unit. A ZIP approval cannot expose
// denied or missing metadata, and a metadata approval cannot expose a denied ZIP.
func checkGoModuleBundle(ctx context.Context, tx pgx.Tx, repo string, a Artifact, review bool, b *graphBudget) error {
	m, e := ValidateGoModuleArtifact(a)
	if e != nil {
		return e
	}
	c := gomodule.Coordinate{Module: m.Module, Version: m.Version}
	as := make([]Artifact, 0, 3)
	for _, kind := range []string{"zip", "mod", "info"} {
		ref, e := readArtifact(ctx, tx, repo, c.Prefix()+"."+kind, review, b)
		if errors.Is(e, ErrNotFound) {
			return ErrGoModuleUnvalidated
		}
		if e != nil {
			return e
		}
		as = append(as, ref)
	}
	_, e = validateGoModuleBundle(as)
	return e
}

// goModuleVersionCandidates retains blocked coordinates so a lower-priority
// source cannot replace a denied, unreviewed or retired first-source version.
func goModuleVersionCandidates(as []Artifact, mod string, review bool) (map[string]bool, error) {
	bundles := map[string][]Artifact{}
	blocked := map[string]bool{}
	for _, a := range as {
		m, e := ValidateGoModuleArtifact(a)
		if e != nil {
			return nil, e
		}
		if m.Module != mod {
			return nil, ErrGoModuleUnvalidated
		}
		bundles[m.Version] = append(bundles[m.Version], a)
		blocked[m.Version] = blocked[m.Version] || a.Deleted || a.Decision == "denied" || review && a.Decision != "allowed"
	}
	candidates := map[string]bool{}
	for version, refs := range bundles {
		if _, e := validateGoModuleBundle(refs); e != nil {
			return nil, e
		}
		candidates[version] = !blocked[version]
	}
	return candidates, nil
}

func mergeGoModuleVersions(selected, candidates map[string]bool) {
	for version, allowed := range candidates {
		if _, exists := selected[version]; !exists {
			selected[version] = allowed
		}
	}
}

type GoModuleVersionView struct {
	Versions []string
	Known    bool
}

func (s *Store) GoModuleVersions(ctx context.Context, i Identity, repo, mod string, limit int, budget int64) ([]string, error) {
	view, e := s.GoModuleView(ctx, i, repo, mod, limit, budget)
	return view.Versions, e
}

// GoModuleView takes one repeatable-read authority/policy snapshot across
// all consulted sources. SQL rows and metadata share one complete-view budget;
// blocked first-source coordinates are retained during ordered group merging.
// Known is kept independently of allowed versions: a policy-hidden module must
// not become a not-found result authorizing a native client's source fallback.
func (s *Store) GoModuleView(ctx context.Context, i Identity, repo, mod string, limit int, budget int64) (GoModuleVersionView, error) {
	escaped, e := module.EscapePath(mod)
	if e != nil || len(mod) > gomodule.MaxModulePath || limit < 1 || limit > 10000 || budget < 1 || budget > 64<<20 {
		return GoModuleVersionView{}, ErrMetadataLimit
	}
	out := GoModuleVersionView{Versions: []string{}}
	e = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		group, members, e := nativeRepositories(ctx, tx, i, repo, escaped, "go")
		if e != nil {
			return e
		}
		if group.Mode != "hosted" && group.Mode != "group" {
			return ErrConflict
		}
		selected := map[string]bool{}
		remaining := limit * 3
		for _, source := range members {
			if source.Mode != "hosted" {
				return ErrConflict
			}
			rows, e := tx.Query(ctx, `SELECT a.repository,left(a.path,2049),left(a.digest,65),a.size,left(a.media_type,257),CASE WHEN octet_length(a.metadata::text)<=$4 THEN a.metadata ELSE NULL END,COALESCE(d.decision,a.decision),a.created_at,a.source_revision,COALESCE(nl.deleted,false) FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+` WHERE a.repository=$1 AND starts_with(a.path,$2) ORDER BY a.path LIMIT $3`, source.Name, escaped+"/@v/", remaining+1, MaxGoModuleMetadata)
			if e != nil {
				return e
			}
			as := []Artifact{}
			for rows.Next() {
				remaining--
				if remaining < 0 {
					rows.Close()
					return ErrMetadataLimit
				}
				var a Artifact
				if e = scanNativeArtifact(rows, &a); e != nil {
					rows.Close()
					return e
				}
				budget -= int64(len(a.Path) + len(a.Metadata) + len(a.MediaType) + 192)
				if budget < 0 {
					rows.Close()
					return ErrMetadataLimit
				}
				as = append(as, a)
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			candidates, e := goModuleVersionCandidates(as, mod, source.RequireReview || group.RequireReview)
			if e != nil {
				return e
			}
			mergeGoModuleVersions(selected, candidates)
		}
		for version, allowed := range selected {
			out.Known = true
			if allowed {
				out.Versions = append(out.Versions, version)
			}
		}
		return nil
	})
	if e != nil {
		return GoModuleVersionView{}, e
	}
	semver.Sort(out.Versions)
	return out, nil
}

// A missing sibling of an existing version is damaged publication state, not a
// not-found result that authorizes a package client's fallback to another source.
func missingGoModuleRepresentation(ctx context.Context, tx pgx.Tx, repo, p string) error {
	request, e := gomodule.ParseRequest(p)
	if e != nil || request.Version == "" {
		return ErrNotFound
	}
	prefix := request.Coordinate.Prefix()
	var exists bool
	e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts WHERE repository=$1 AND path=ANY($2::text[]))`, repo, []string{prefix + ".zip", prefix + ".mod", prefix + ".info"}).Scan(&exists)
	if e != nil {
		return e
	}
	if exists {
		return ErrGoModuleUnvalidated
	}
	return ErrNotFound
}
