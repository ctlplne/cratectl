// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

var errUpstream = errors.New("configured upstream retrieval failed")
var errUpstreamIntegrity = errors.New("configured upstream checksum verification failed")

type resolvedArtifact struct {
	artifact   store.Artifact
	source     store.Repository
	groups     []string
	cache      string
	ociImage   string
	ociRef     string
	admissions []store.OCIAdmission
}

func (s *Server) resolve(ctx context.Context, i store.Identity, repo store.Repository, p string, force bool) (resolvedArtifact, error) {
	if repo.Mode != "hosted" && !upstream.SafePath(p) {
		return resolvedArtifact{}, upstream.ErrPath
	}
	switch repo.Mode {
	case "hosted":
		a, e := s.DB.Artifact(ctx, i, repo.Name, p)
		return resolvedArtifact{artifact: a, source: repo}, e
	case "proxy":
		return s.resolveProxy(ctx, i, repo, p, force)
	case "group":
		members := repo.Settings.Members
		longest := ""
		owner := ""
		for prefix, m := range repo.Settings.NamespaceOwners {
			if strings.HasPrefix(p, prefix) && len(prefix) > len(longest) {
				longest = prefix
				owner = m
			}
		}
		if owner != "" {
			members = []string{owner}
		}
		for _, member := range members {
			source, e := s.DB.Repository(ctx, i, member)
			if e != nil {
				return resolvedArtifact{}, e
			}
			if source.Mode == "group" || source.Format != repo.Format {
				return resolvedArtifact{}, store.ErrConflict
			}
			a, e := s.resolve(ctx, i, source, p, force)
			if errors.Is(e, store.ErrNotFound) {
				continue
			}
			if e != nil {
				return a, e
			}
			if repo.RequireReview && a.artifact.Decision != "allowed" {
				return a, store.ErrDenied
			}
			a.groups = append(a.groups, repo.Name)
			return a, nil
		}
		return resolvedArtifact{}, store.ErrNotFound
	default:
		return resolvedArtifact{}, store.ErrConflict
	}
}
func (s *Server) resolveProxy(ctx context.Context, i store.Identity, repo store.Repository, p string, force bool) (resolvedArtifact, error) {
	result := resolvedArtifact{source: repo}
	waits := 0
	for {
		lease, e := s.DB.Retrieval(ctx, i, repo.Name, p)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			return result, e
		}
		if e == nil && lease.State != "fetching" && lease.Fresh() && !force {
			switch lease.State {
			case "ready":
				result.cache = "hit"
				result.artifact, e = s.proxyArtifact(ctx, i, repo, p)
				return result, e
			case "negative":
				return result, store.ErrNotFound
			case "failed":
				if lease.StalePermitted() {
					if repo.Format == "oci" {
						result.admissions = []store.OCIAdmission{{Repository: repo.Name, Path: p, Generation: lease.Generation, Stale: true}}
					}
					result.cache = "stale"
					result.artifact, e = s.proxyArtifact(ctx, i, repo, p)
					return result, e
				}
				return result, errUpstream
			}
		}
		if e == nil && lease.State == "fetching" && lease.LeaseUntil.After(lease.Now) {
			if waits >= 40 {
				return result, store.ErrBusy
			}
			waits++
			force = false
			timer := time.NewTimer(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return result, ctx.Err()
			case <-timer.C:
				continue
			}
		}
		select {
		case s.fillSlots <- struct{}{}:
		default:
			// Contenders may observe the miss before its owner commits the lease.
			// Recheck boundedly so they can join that fill instead of consuming
			// another slot or failing merely because its SQL transaction waited.
			if waits >= 40 {
				return result, store.ErrBusy
			}
			waits++
			timer := time.NewTimer(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return result, ctx.Err()
			case <-timer.C:
				continue
			}
		}
		token, e := crypt.Token()
		if e != nil {
			<-s.fillSlots
			return result, e
		}
		lease, e = s.DB.AcquireRetrieval(ctx, i, repo.Name, p, token, force, s.TenantProxyLimit)
		if errors.Is(e, store.ErrBusy) {
			<-s.fillSlots
			force = false
			waits++
			if waits >= 40 {
				return result, store.ErrBusy
			}
			timer := time.NewTimer(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return result, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if e != nil {
			<-s.fillSlots
			return result, e
		}
		if !lease.Acquired {
			<-s.fillSlots
			force = false
			continue
		}
		e = s.fillProxy(ctx, i, repo, lease)
		<-s.fillSlots
		if e != nil {
			return result, e
		}
		refreshed, e := s.DB.Retrieval(ctx, i, repo.Name, p)
		if e != nil {
			return result, e
		}
		force = false
		switch refreshed.State {
		case "ready":
			if repo.Format == "oci" {
				result.admissions = []store.OCIAdmission{{Repository: repo.Name, Path: p, Generation: refreshed.Generation}}
			}
			result.cache = "filled"
			if refreshed.LastStatus == 304 {
				result.cache = "revalidated"
			}
			result.artifact, e = s.proxyArtifact(ctx, i, repo, p)
			return result, e
		case "negative":
			return result, store.ErrNotFound
		case "failed":
			if refreshed.StalePermitted() {
				if repo.Format == "oci" {
					result.admissions = []store.OCIAdmission{{Repository: repo.Name, Path: p, Generation: refreshed.Generation, Stale: true}}
				}
				result.cache = "stale"
				result.artifact, e = s.proxyArtifact(ctx, i, repo, p)
				return result, e
			}
			if refreshed.LastError == "upstream_integrity_failure" {
				return result, errUpstreamIntegrity
			}
			return result, errUpstream
		default:
			return result, store.ErrBusy
		}
	}
}
func (s *Server) proxyArtifact(ctx context.Context, i store.Identity, repo store.Repository, p string) (store.Artifact, error) {
	if repo.Format == "oci" {
		if strings.HasPrefix(p, "oci-catalog/") {
			return s.DB.NativeCatalogArtifact(ctx, i, repo.Name, strings.TrimPrefix(p, "oci-catalog/"), "oci", store.OCICatalogMedia)
		}
		image, kind, ref := parseOCIPath(p)
		if kind == "manifests" {
			return s.DB.OCIManifest(ctx, i, repo.Name, image, ref)
		}
	}
	if repo.Format == "pypi" && strings.HasPrefix(p, "pypi-catalog/") {
		return s.DB.NativeCatalogArtifact(ctx, i, repo.Name, strings.TrimPrefix(p, "pypi-catalog/"), "pypi", store.PythonCatalogMedia)
	}
	if repo.Format == "npm" && strings.HasPrefix(p, "npm-catalog/") {
		return s.DB.NPMCatalogArtifact(ctx, i, repo.Name, strings.TrimPrefix(p, "npm-catalog/"))
	}
	return s.DB.Artifact(ctx, i, repo.Name, p)
}
func cachePolicy(h http.Header, repo store.Repository, lease store.Retrieval, status int) (int, int, error) {
	fresh, stale := repo.Settings.Cache.FreshSeconds, repo.Settings.Cache.StaleSeconds
	if status == 304 && h.Get("Cache-Control") == "" && h.Get("Expires") == "" {
		return lease.SourceFresh, lease.SourceStale, nil
	}
	for _, part := range strings.Split(strings.ToLower(h.Get("Cache-Control")), ",") {
		bits := strings.SplitN(strings.TrimSpace(part), "=", 2)
		switch bits[0] {
		case "no-store":
			if !repo.Settings.Cache.AllowNoStore {
				return 0, 0, errors.New("upstream forbids storage")
			}
		case "no-cache":
			fresh = 0
			stale = 0
		case "must-revalidate", "proxy-revalidate":
			stale = 0
		case "max-age", "s-maxage":
			if len(bits) != 2 {
				fresh = 0
				continue
			}
			n, e := strconv.Atoi(strings.Trim(bits[1], `"`))
			if e != nil || n < 0 {
				fresh = 0
				continue
			}
			age, ageErr := strconv.Atoi(h.Get("Age"))
			if h.Get("Age") != "" && (ageErr != nil || age < 0) {
				fresh = 0
				continue
			}
			fresh = min(fresh, max(0, n-max(0, age)))
		}
	}
	if expires, e := http.ParseTime(h.Get("Expires")); e == nil {
		fresh = min(fresh, max(0, int(time.Until(expires).Seconds())))
	}
	if strings.TrimSpace(h.Get("Vary")) == "*" {
		fresh = 0
		stale = 0
	}
	return fresh, stale, nil
}
func (s *Server) fillProxy(parent context.Context, i store.Identity, repo store.Repository, lease store.Retrieval) error {
	if repo.Format == "oci" {
		return s.fillOCIProxy(parent, i, repo, lease)
	}
	if repo.Format == "pypi" {
		return s.fillPythonProxy(parent, i, repo, lease)
	}
	if repo.Format == "npm" {
		return s.fillNPMProxy(parent, i, repo, lease)
	}
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	config := repo.Settings.Upstream
	if config == nil {
		return store.ErrConflict
	}
	credential, e := s.credential(i.Tenant, *config)
	if e != nil {
		return s.DB.CompleteRetrieval(ctx, i, lease, store.RetrievalResult{Failure: "upstream_credential_authority"})
	}
	endpoint, e := upstream.New(*config, credential, s.PrivateUpstreamNetworks...)
	if e != nil {
		return s.DB.CompleteRetrieval(ctx, i, lease, store.RetrievalResult{Failure: "upstream_authority_failure"})
	}

	defer endpoint.Close()
	result := store.RetrievalResult{FreshSeconds: repo.Settings.Cache.NegativeSeconds}
	validators := http.Header{}
	if lease.ETag != "" {
		validators.Set("If-None-Match", lease.ETag)
	}
	if lease.Modified != "" {
		validators.Set("If-Modified-Since", lease.Modified)
	}
	response, e := endpoint.Get(ctx, lease.Path, validators)
	if e != nil {
		result.Failure = "transient_upstream_failure"
		if errors.Is(e, upstream.ErrDestination) || errors.Is(e, upstream.ErrRedirect) || errors.Is(e, upstream.ErrPath) {
			result.Failure = "upstream_authority_failure"
		}
	} else {
		defer response.Body.Close()
		result.Status = response.StatusCode
		switch response.StatusCode {
		case 200, 304:
			fresh, stale, err := cachePolicy(response.Header, repo, lease, response.StatusCode)
			result.FreshSeconds = fresh
			result.StaleSeconds = stale
			if err != nil {
				result.Failure = "upstream_cache_policy_failure"
				break
			}
			if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
				result.Failure = "unexpected_upstream_encoding"
				break
			}
			if len(response.Header.Get("ETag")) > 1024 || len(response.Header.Get("Last-Modified")) > 128 {
				result.Failure = "upstream_header_limit"
				break
			}
			result.ETag = response.Header.Get("ETag")
			result.Modified = response.Header.Get("Last-Modified")
			if response.StatusCode == 304 {
				break
			}
			object, err := s.Blobs.Put(ctx, i.Tenant, response.Body, "", response.ContentLength)
			if err != nil {
				result.Failure = "upstream_transfer_failure"
				break
			}
			result.Object = &object
			verification := "not_applicable"
			if repo.Format == "maven" {
				verification = "checksum_unavailable"
				for _, algorithm := range []string{"sha256", "sha1"} {
					checksum, err := endpoint.Get(ctx, lease.Path+"."+algorithm, nil)
					if err != nil {
						result.Failure = "upstream_checksum_retrieval_failure"
						break
					}
					if checksum.StatusCode == 404 {
						checksum.Body.Close()
						continue
					}
					if checksum.StatusCode != 200 {
						checksum.Body.Close()
						result.Failure = "upstream_checksum_retrieval_failure"
						break
					}
					b, err := io.ReadAll(io.LimitReader(checksum.Body, 1025))
					checksum.Body.Close()
					if err != nil || len(b) > 1024 {
						result.Failure = "upstream_integrity_failure"
						break
					}
					file, err := s.Blobs.OpenVerified(ctx, i.Tenant, object.Digest, object.Size)
					if err != nil {
						result.Failure = "upstream_integrity_failure"
						break
					}
					hash := crypt.CompatibilityHash(algorithm)
					_, err = io.Copy(hash, file)
					file.Close()
					if err != nil || strings.TrimSpace(string(b)) != hex.EncodeToString(hash.Sum(nil)) {
						result.Failure = "upstream_integrity_failure"
						break
					}
					verification = algorithm + "_verified"
					break
				}
				if verification == "checksum_unavailable" && repo.Settings.Cache.RequireChecksum {
					result.Failure = "upstream_checksum_required"
				}
			}
			result.Metadata, _ = json.Marshal(map[string]any{"source_repository": repo.Name, "source_authority": config.URL, "source_path": lease.Path, "upstream_checksum": verification})
		case 404:
			negativeRepo := repo
			negativeRepo.Settings.Cache.FreshSeconds = repo.Settings.Cache.NegativeSeconds
			fresh, _, err := cachePolicy(response.Header, negativeRepo, lease, 404)
			if err != nil {
				fresh = 0
			}
			result.FreshSeconds = fresh
		default:
			result.Failure = "upstream_rejected_request"
			if response.StatusCode >= 500 {
				result.Failure = "transient_upstream_failure"
			}
		}
	}
	if ctx.Err() != nil {
		result.Object = nil
		result.Failure = "retrieval_cancelled"
	}
	completeCtx := ctx
	var done context.CancelFunc
	if ctx.Err() != nil {
		completeCtx, done = context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
		defer done()
	}
	return s.DB.CompleteRetrieval(completeCtx, i, lease, result)
}
func (s *Server) guardResolved(ctx context.Context, i store.Identity, a resolvedArtifact) (store.Artifact, error) {
	var current store.Artifact
	var e error
	if a.ociRef != "" {
		endpoint := a.source.Name
		if len(a.groups) > 0 {
			endpoint = a.groups[0]
		}
		_, kind, _ := parseOCIPath(a.artifact.Path)
		var source store.Repository
		current, source, e = s.DB.OCISelection(ctx, i, endpoint, a.ociImage, kind, a.ociRef, a.admissions...)
		if e != nil {
			return current, e
		}
		if source.Name != a.source.Name || current.Digest != a.artifact.Digest {
			return current, store.ErrConflict
		}
		return current, nil
	} else {
		current, e = s.DB.Artifact(ctx, i, a.source.Name, a.artifact.Path)
	}
	if e != nil {
		return current, e
	}
	if current.Digest != a.artifact.Digest {
		return current, store.ErrConflict
	}
	if a.source.Mode == "proxy" {
		entry, e := s.DB.Retrieval(ctx, i, a.source.Name, a.artifact.Path)
		if e != nil {
			return current, e
		}
		if entry.State == "negative" {
			return current, store.ErrNotFound
		}
		if entry.State == "failed" && !entry.StalePermitted() {
			return current, errUpstream
		}
	}
	for _, name := range a.groups {
		group, e := s.DB.Repository(ctx, i, name)
		if e != nil {
			return current, e
		}
		if group.RequireReview && current.Decision != "allowed" {
			return current, store.ErrDenied
		}
	}
	return current, nil
}

func forceRefresh(r *http.Request) bool {
	value := strings.ToLower(r.Header.Get("Cache-Control"))
	return strings.Contains(value, "no-cache") || strings.Contains(value, "max-age=0")
}
