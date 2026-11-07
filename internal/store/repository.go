// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

type CacheSettings struct {
	FreshSeconds    int  `json:"fresh_seconds"`
	NegativeSeconds int  `json:"negative_seconds"`
	StaleSeconds    int  `json:"stale_seconds"`
	RequireChecksum bool `json:"require_checksum"`
	AllowNoStore    bool `json:"allow_no_store"`
	AllowLegacyNPM  bool `json:"allow_legacy_npm_shasum"`
}
type RepositorySettings struct {
	Upstream            *upstream.Config     `json:"upstream,omitempty"`
	Cache               CacheSettings        `json:"cache"`
	Members             []string             `json:"members,omitempty"`
	NamespaceOwners     map[string]string    `json:"namespace_owners,omitempty"`
	DownloadSources     []upstream.Config    `json:"download_sources,omitempty"`
	PythonIndexFormat   string               `json:"python_index_format,omitempty"`
	OCITokenEndpoint    *upstream.Config     `json:"oci_token_endpoint,omitempty"`
	OCITokenService     string               `json:"oci_token_service,omitempty"`
	MavenSnapshotPolicy string               `json:"maven_snapshot_policy,omitempty"`
	GoChecksumAuthority *GoChecksumAuthority `json:"go_checksum_authority,omitempty"`
}
type Repository struct {
	SourceRevision int64              `json:"source_revision"`
	Name           string             `json:"name"`
	Format         string             `json:"format"`
	Mode           string             `json:"mode"`
	RequireReview  bool               `json:"require_review"`
	Access         string             `json:"access"`
	Settings       RepositorySettings `json:"settings"`
}

func repositoryInTx(ctx context.Context, tx pgx.Tx, i Identity, name, action string) (Repository, error) {
	r, e := repositoryRecordInTx(ctx, tx, i, name, action)
	if e != nil {
		return r, e
	}
	state, e := repositoryStateInTx(ctx, tx, name)
	if e != nil {
		return r, e
	}
	switch state.State {
	case "suspended":
		return r, ErrRepositorySuspended
	case "removed":
		return r, ErrRepositoryRemoved
	}
	return r, nil
}

// Lifecycle administration authorizes the retained record without admitting an
// inactive repository to ordinary serving or publication.
func repositoryRecordInTx(ctx context.Context, tx pgx.Tx, i Identity, name, action string) (Repository, error) {
	var r Repository
	var settings []byte
	e := tx.QueryRow(ctx, `SELECT name,format,mode,require_review,access,settings,source_revision FROM cratectl.repositories WHERE name=$1`, name).Scan(&r.Name, &r.Format, &r.Mode, &r.RequireReview, &r.Access, &settings, &r.SourceRevision)
	if errors.Is(e, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	if e != nil {
		return r, e
	}
	if json.Unmarshal(settings, &r.Settings) != nil {
		return r, errors.New("invalid durable repository configuration")
	}
	if action == "write" && !i.CanWrite() {
		return r, ErrDenied
	}
	if i.Role == "admin" || r.Access == "tenant" {
		return r, nil
	}
	var read, write bool
	e = tx.QueryRow(ctx, `SELECT can_read,can_write FROM cratectl.repository_grants WHERE repository=$1 AND actor=$2`, name, i.Actor).Scan(&read, &write)
	if errors.Is(e, pgx.ErrNoRows) {
		return r, ErrDenied
	}
	if e != nil {
		return r, e
	}
	if !read || (action == "write" && !write) {
		return r, ErrDenied
	}
	return r, nil
}
func (s *Store) Repository(ctx context.Context, i Identity, name string) (Repository, error) {
	var r Repository
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error { var e error; r, e = repositoryInTx(ctx, tx, i, name, "read"); return e })
	return r, e
}
func (s *Store) AuthorizeWrite(ctx context.Context, i Identity, name string) error {
	return s.Tx(ctx, i, false, func(tx pgx.Tx) error { _, e := repositoryInTx(ctx, tx, i, name, "write"); return e })
}
func ValidateRepository(r *Repository) error {
	return validateRepository(r, false)
}

// Retained Go proxy records need an administrative trust-recovery path while
// new proxy creation and public protocol routing remain unqualified and gated.
// Only configurationPreview may select this path after reading the actual row.
func validateRepository(r *Repository, retainedGoProxy bool) error {
	if r.SourceRevision != 0 {
		return errors.New("source_revision is read-only")
	}
	if r.Settings.PythonIndexFormat != "" && (r.Format != "pypi" || r.Mode != "proxy" || (r.Settings.PythonIndexFormat != "auto" && r.Settings.PythonIndexFormat != "html" && r.Settings.PythonIndexFormat != "json")) {
		return errors.New("Python index format requires a PyPI proxy and auto, html or json")
	}
	if !Name.MatchString(r.Name) {
		return errors.New("invalid name")
	}
	if r.Mode == "" {
		r.Mode = "hosted"
	}
	if r.Access == "" {
		r.Access = "tenant"
	}
	if r.Access != "tenant" && r.Access != "restricted" {
		return errors.New("access must be tenant or restricted")
	}
	if policy := r.Settings.MavenSnapshotPolicy; policy != "" && (r.Format != "maven" || r.Mode != "hosted" || policy != "immutable" && policy != MavenSnapshotRedeployNonunique) {
		return errors.New("Maven snapshot policy requires a hosted Maven repository and immutable or redeploy_nonunique")
	}
	if authority := r.Settings.GoChecksumAuthority; authority != nil {
		if r.Format != "go" || r.Mode != "proxy" {
			return errors.New("Go checksum authority requires a Go proxy")
		}
		if e := authority.Validate(); e != nil {
			return e
		}
	}
	if retainedGoProxy && (r.Format != "go" || r.Mode != "proxy" || r.Settings.GoChecksumAuthority == nil || !r.Settings.Cache.RequireChecksum) {
		return errors.New("retained Go proxy configuration requires explicit checksum authority and checksum enforcement")
	}
	if r.Mode != "hosted" && r.Format != "generic" && r.Format != "maven" && r.Format != "npm" && r.Format != "pypi" && r.Format != "oci" && !(r.Format == "go" && (r.Mode == "group" || r.Mode == "proxy" && retainedGoProxy)) {
		return errors.New("proxy/group native adapters not yet implemented for this format")
	}
	if r.Settings.OCITokenEndpoint != nil {
		if ref := r.Settings.OCITokenEndpoint.CredentialRef; ref != "" && !Name.MatchString(ref) {
			return errors.New("invalid OCI token credential reference")
		}
		if r.Settings.OCITokenEndpoint.AllowSignedQuery || r.Format != "oci" || r.Mode != "proxy" || r.Settings.OCITokenService == "" || len(r.Settings.OCITokenService) > 255 || strings.ContainsAny(r.Settings.OCITokenService, "\r\n\x00") {
			return errors.New("OCI token endpoint requires an OCI proxy and an exact bounded service audience")
		}
		endpoint, e := upstream.New(*r.Settings.OCITokenEndpoint, "")
		if e != nil {
			return e
		}
		endpoint.Close()
	} else if r.Settings.OCITokenService != "" {
		return errors.New("OCI token service requires its approved endpoint")
	}
	switch r.Mode {
	case "hosted":
		if r.Settings.Upstream != nil || len(r.Settings.Members) != 0 || len(r.Settings.DownloadSources) != 0 {
			return errors.New("hosted sources are not permitted")
		}
	case "proxy":
		if r.Settings.Upstream == nil || len(r.Settings.Members) != 0 {
			return errors.New("proxy requires exactly one upstream")
		}
		if ref := r.Settings.Upstream.CredentialRef; ref != "" && !Name.MatchString(ref) {
			return errors.New("invalid credential reference")
		}
		if r.Settings.Upstream.AllowSignedQuery && r.Format != "oci" {
			return errors.New("signed query delivery requires an OCI proxy")
		}
		endpoint, e := upstream.New(*r.Settings.Upstream, "")
		if e != nil {
			return e
		}
		endpoint.Close()
		if len(r.Settings.DownloadSources) > 16 || (len(r.Settings.DownloadSources) > 0 && r.Format != "npm" && r.Format != "pypi" && r.Format != "oci") {
			return errors.New("download sources require npm, PyPI or OCI and at most 16 explicit authorities")
		}
		authorities := map[string]bool{strings.TrimRight(r.Settings.Upstream.URL, "/") + "/": true}
		for _, source := range r.Settings.DownloadSources {
			if source.AllowSignedQuery && r.Format != "oci" {
				return errors.New("signed query delivery requires an OCI proxy")
			}
			key := strings.TrimRight(source.URL, "/") + "/"
			if authorities[key] {
				return errors.New("duplicate download authority/base path")
			}
			authorities[key] = true
			if source.CredentialRef != "" && !Name.MatchString(source.CredentialRef) {
				return errors.New("invalid download credential reference")
			}
			e, e2 := upstream.New(source, "")
			if e2 != nil {
				return e2
			}
			e.Close()
		}
		c := r.Settings.Cache
		if c.FreshSeconds < 0 || c.FreshSeconds > 86400 || c.NegativeSeconds < 0 || c.NegativeSeconds > 3600 || c.StaleSeconds < 0 || c.StaleSeconds > 604800 {
			return errors.New("cache windows exceed configured safety bounds")
		}
	case "group":
		if r.Settings.Upstream != nil || len(r.Settings.DownloadSources) != 0 || len(r.Settings.Members) == 0 || len(r.Settings.Members) > 32 {
			return errors.New("group needs 1–32 source members")
		}
		seen := map[string]bool{}
		for _, member := range r.Settings.Members {
			if !Name.MatchString(member) || member == r.Name || seen[member] {
				return errors.New("invalid or duplicate group member")
			}
			seen[member] = true
		}
		if len(r.Settings.NamespaceOwners) > 128 {
			return errors.New("too many namespace owners")
		}
		for prefix, owner := range r.Settings.NamespaceOwners {
			if prefix == "" || !upstream.SafePath(strings.TrimSuffix(prefix, "/")) || !strings.HasSuffix(prefix, "/") || !seen[owner] {
				return errors.New("namespace owner must be a member and prefix must end in slash")
			}
			if r.Format == "go" {
				request, e := gomodule.ParseRequest(strings.TrimSuffix(prefix, "/") + "/@v/list")
				if e != nil || request.Operation != "list" {
					return errors.New("Go namespace owners require a canonical escaped module or parent namespace prefix")
				}
			}
		}
	default:
		return errors.New("invalid repository mode")
	}
	return nil
}
func CreateRepository(ctx context.Context, tx pgx.Tx, i Identity, r Repository) error {
	if i.Role != "admin" {
		return ErrDenied
	}
	if e := ValidateRepository(&r); e != nil {
		return e
	}
	for _, member := range r.Settings.Members {
		source, e := repositoryInTx(ctx, tx, i, member, "read")
		if e != nil {
			return e
		}
		if source.Format != r.Format || source.Mode == "group" {
			return ErrConflict
		}
	}
	settings, e := json.Marshal(r.Settings)
	if e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `INSERT INTO cratectl.repositories(tenant,name,format,mode,require_review,access,settings) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, i.Tenant, r.Name, r.Format, r.Mode, r.RequireReview, r.Access, settings)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) MutateRepository(ctx context.Context, i Identity, repo, key, fingerprint, kind string, fn func(pgx.Tx) (any, int, error)) (Result, error) {
	return s.Mutate(ctx, i, key, fingerprint, kind, func(tx pgx.Tx) (any, int, error) {
		r, e := repositoryInTx(ctx, tx, i, repo, "write")
		if e != nil {
			return nil, 0, e
		}
		if r.Mode != "hosted" {
			return nil, 0, ErrDenied
		}
		return fn(tx)
	})
}
