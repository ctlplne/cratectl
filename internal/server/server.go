// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/consoleui"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
	"github.com/jackc/pgx/v5"
)

type Adapter interface {
	Format() string
	Serve(http.ResponseWriter, *http.Request, store.Identity, store.Repository, string)
}
type adapter struct {
	name  string
	serve func(http.ResponseWriter, *http.Request, store.Identity, store.Repository, string)
}

func (a adapter) Format() string { return a.name }
func (a adapter) Serve(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	a.serve(w, r, i, repo, p)
}

type Server struct {
	DB                           *store.Store
	PaginationKey                *crypt.CursorKey
	ManagementMetadataBytes      int
	Blobs                        *blob.Local
	PublicURL                    string
	UpstreamCredentials          map[string]UpstreamCredential
	PrivateUpstreamNetworks      []string
	TenantProxyLimit             int
	ProxyLease                   time.Duration
	NativeVersionLimit           int
	NativeTagLimit               int
	NativeMetadataBytes          int64
	NPMPublishBytes              int64
	NPMExpandedBytes             int64
	NPMFileLimit                 int
	NPMPackageJSONBytes          int64
	PythonUploadBytes            int64
	PythonExpandedBytes          int64
	PythonFileLimit              int
	PythonMetadataBytes          int64
	OCIGraphBytes                int64
	OCIDeliveryRedirects         int
	OCIDeliveryLimits            upstream.RegistryDeliveryLimits
	OCICatalogPages              int
	OCIPageSize                  int
	OCIDescriptorURLs            int
	OCIDescriptorParents         int
	UploadLimit, UploadPartLimit int
	UploadMetadataBytes          int64
	SweepTargetBudget            int
	InventoryLimits              store.InventoryLimits
	UploadLease, UploadTTL       time.Duration
	fillSlots                    chan struct{}
	slots                        chan struct{}
	adapters                     map[string]Adapter
}

func New(db *store.Store, b *blob.Local, public string) *Server {
	s := &Server{DB: db, Blobs: b, PublicURL: strings.TrimRight(public, "/"), slots: make(chan struct{}, 16), fillSlots: make(chan struct{}, 4), TenantProxyLimit: 32, NativeVersionLimit: 10000, NativeTagLimit: 128, NativeMetadataBytes: 8 << 20, UpstreamCredentials: map[string]UpstreamCredential{}, adapters: map[string]Adapter{}}
	s.ManagementMetadataBytes = 8 << 20
	s.NPMPublishBytes, s.NPMExpandedBytes, s.NPMFileLimit, s.NPMPackageJSONBytes = 24<<20, 64<<20, 10000, 1<<20
	s.PythonUploadBytes, s.PythonExpandedBytes, s.PythonFileLimit, s.PythonMetadataBytes = 64<<20, 256<<20, 10000, 1<<20
	s.OCIGraphBytes = 4 << 30
	s.OCIDeliveryRedirects = 5
	s.OCICatalogPages = 32
	s.OCIPageSize = 1000
	s.OCIDescriptorURLs = 32
	s.OCIDescriptorParents = 64
	s.ProxyLease = 150 * time.Second
	s.SweepTargetBudget = 100000
	s.InventoryLimits = store.InventoryLimits{MaxEntries: 1000000, DirectoryEntries: 1000000}
	s.UploadLimit, s.UploadPartLimit, s.UploadMetadataBytes, s.UploadLease, s.UploadTTL = 32, 4096, 1<<20, 30*time.Second, 30*time.Minute
	s.OCIDeliveryLimits = upstream.DefaultRegistryDeliveryLimits()
	for _, a := range []adapter{{"generic", s.raw}, {"maven", s.raw}, {"npm", s.npm}, {"pypi", s.pypi}, {"oci", s.oci}} {
		s.adapters[a.Format()] = a
	}
	secret, keyError := crypt.Token()
	if keyError == nil {
		s.PaginationKey, _ = crypt.ParseCursorKey(secret)
	}
	return s
}
func ValidPath(p string) bool {
	return p != "" && len(p) <= 2048 && path.Clean(p) == p && !strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "\\\x00\r\n") && p != "." && p != ".." && !strings.HasPrefix(p, "../")
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code, action string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "action": action}})
}
func respondErr(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, store.ErrMatterInput):
		fail(w, 400, "invalid_hold_matter", "Supply a complete bounded matter request or the exact reviewed target manifest and revision.")
	case errors.Is(e, store.ErrMatterChanged):
		fail(w, 409, "hold_matter_changed", "Read the current matter and memberships, then preview again. Existing outcomes stay recorded; a changed or expired review cannot authorize remaining work.")
	case errors.Is(e, store.ErrMatterBudget):
		fail(w, 413, "hold_matter_budget", "The complete target manifest exceeds the configured target or metadata budget. No partial list was admitted.")
	case errors.Is(e, store.ErrMatterAuthorization):
		fail(w, 403, "hold_matter_authorization_changed", "The original requester or distinct approver is no longer authorized. Inspect committed outcomes and create a fresh proposal for remaining references.")
	case errors.Is(e, store.ErrRetentionScheduleChanged):
		fail(w, 409, "retention_schedule_changed", "Read the current schedule revision and inspect earlier outcomes. A paused or replaced schedule stops its remaining targets; retrying an old job cannot replace that approval.")
	case errors.Is(e, store.ErrRetentionInput):
		fail(w, 400, "invalid_retention", "Supply a complete OCI retention policy or an exact approved preview, current expected_revision and nonempty bounded reason.")
	case errors.Is(e, store.ErrRetentionChanged):
		fail(w, 409, "retention_changed", "Read current policy and preview again. Apply its exact digest and evaluation time within five minutes; changed policy, membership or source needs a new preview.")
	case errors.Is(e, store.ErrRetentionBudget):
		fail(w, 413, "retention_budget", "The complete retention plan exceeds the operator target or metadata budget. No partial plan was admitted; inspect repository size and configured limits.")
	case errors.Is(e, store.ErrRetentionAuthorization):
		fail(w, 403, "retention_authorization_changed", "The requesting administrator credential changed or expired. Inspect already committed outcomes and create a newly authorized preview for remaining work.")
	case errors.Is(e, store.ErrSourceChanged):
		fail(w, 503, "source_configuration_changed", "The repository source or group configuration changed. Retry from current package metadata; prior cache bytes, validators and locators cannot be reused across this change.")
	case errors.Is(e, store.ErrConfigurationRevision):
		fail(w, 409, "configuration_changed", "Read current repository configuration, preview its impact, and apply that exact expected_revision with a new idempotency key.")
	case errors.Is(e, store.ErrConfigurationInput):
		fail(w, 400, "invalid_configuration", "Supply complete valid proxy/group settings, a nonnegative expected_revision and a nonempty reason of at most 1024 UTF-8 bytes without controls. Repository name, mode and format are immutable.")
	case errors.Is(e, store.ErrScheduleRevision):
		fail(w, 409, "schedule_changed", "Read the current schedule, preview a replacement at its exact revision, then apply with a new idempotency key.")
	case errors.Is(e, store.ErrScheduleEvidence):
		fail(w, 503, "schedule_evidence_unavailable", "The job progress disagrees with its immutable admission receipt. Stop interpreting this run as verified and inspect the retained database evidence; automatic metadata repair is unavailable.")
	case errors.Is(e, store.ErrScheduleInput):
		fail(w, 400, "invalid_schedule", "Supply expected_revision, interval_seconds 60–31536000, sample_size within the operator target budget, enabled and a nonempty reason of at most 1024 UTF-8 bytes. Use a retained-byte repository or omit repository for tenant scope.")
	case errors.Is(e, store.ErrRepairInput):
		fail(w, 400, "invalid_repair", "Supply an exact retained path/digest, current expected_source_revision, nonempty reason and source provenance of at most 1024 UTF-8 bytes each.")
	case errors.Is(e, store.ErrRepairChanged):
		fail(w, 409, "repair_changed", "Read the retained reference and current source revision, then create a new repair plan; this source or target changed.")
	case errors.Is(e, store.ErrRepairAuthorization):
		fail(w, 403, "repair_authorization_changed", "Use the original still-valid requesting administrator credential for source submission. If it expired or was revoked, create a new authorized plan.")
	case errors.Is(e, store.ErrRepairReferences):
		fail(w, 409, "repair_reference_conflict", "References disagree on the size of these exact bytes. Inspect metadata consistency before repair; no bytes were replaced.")
	case errors.Is(e, store.ErrDeleted):
		fail(w, 404, "artifact_deleted", "This retained reference was deleted. A writer must preview and explicitly restore its verified bytes; cache refresh cannot restore it.")
	case errors.Is(e, store.ErrRepositorySuspended):
		fail(w, 503, "repository_suspended", "Ask a tenant administrator to inspect repository state and explicitly resume it.")
	case errors.Is(e, store.ErrRepositoryRemoved):
		fail(w, 404, "repository_removed", "The repository and its bytes are retained. A tenant administrator can inspect its state and explicitly restore it.")
	case errors.Is(e, store.ErrHeld):
		fail(w, 409, "artifact_held", "Inspect the current hold. An administrator must release it or wait for its recorded expiry before changing deletion state.")
	case errors.Is(e, store.ErrReferenced):
		fail(w, 409, "artifact_referenced", "Preview the active incoming manifest references and retire their parents before deleting this child.")
	case errors.Is(e, store.ErrLifecycleRevision):
		fail(w, 409, "lifecycle_changed", "Read and preview current state, then retry with its exact revision and digest using a new idempotency key.")
	case errors.Is(e, store.ErrSchemaMaintenance):
		w.Header().Set("Retry-After", "1")
		fail(w, 503, "schema_maintenance", "Schema maintenance is draining or changing database transactions. Keep the credential and retry after readiness recovers.")
	case errors.Is(e, store.ErrSchemaIncompatible):
		fail(w, 503, "schema_incompatible", "Use a compatible binary and inspect the owner migration plan and schema safety checks. No operation was accepted.")
	case errors.Is(e, errMavenMetadata):
		fail(w, 502, "maven_metadata_invalid", "Inspect the source Maven XML, path/coordinate binding and snapshot mappings. No partial metadata was returned.")
	case errors.Is(e, store.ErrMavenSourceChanged):
		fail(w, 503, "maven_source_changed", "Expire and revalidate this metadata cache entry against the current configured upstream authority. The previous source catalog was not used.")
	case errors.Is(e, errMavenViewChanged):
		w.Header().Set("Retry-After", "1")
		fail(w, 503, "maven_metadata_changed", "Concurrent references or policy changed this metadata view during three read attempts. Retry after one second.")
	case errors.Is(e, blob.ErrStorageChanged):
		fail(w, 503, "storage_changed", "Inspect the configured storage root and preview a new maintenance operation; observations or repair sources from different storage identities cannot be combined.")
	case errors.Is(e, blob.ErrUnsupported):
		fail(w, 503, "unsupported_storage_entry", "Inspect storage for links, special files or an unsupported layout; no content was accepted or deleted.")
	case errors.Is(e, store.ErrSweepBudget):
		fail(w, 503, "sweep_target_budget", "No snapshot was accepted. Narrow the repository scope or ask the operator to adjust --integrity-sweep-target-budget after checking database capacity.")
	case errors.Is(e, store.ErrUploadBusy):
		w.Header().Set("Retry-After", "1")
		fail(w, 503, "upload_in_progress", "Retry after one second; inspect the current upload offset.")
	case errors.Is(e, store.ErrUploadLeaseLost):
		fail(w, 409, "upload_superseded", "Read the upload status and retry from its acknowledged offset; this operation was not accepted.")
	case errors.Is(e, store.ErrQueueFull):
		w.Header().Set("Retry-After", "5")
		fail(w, 503, "durable_queue_full", "Inspect /api/v1/jobs/queues, start or repair the worker, or adjust the tenant queue capacity; this mutation was rolled back.")
	case errors.Is(e, store.ErrOCIMemberChanged):
		fail(w, 409, "graph_cache_superseded", "A graph member changed during intake. Retry against the current cache state; no partial graph was published.")
	case errors.Is(e, store.ErrOCICacheExpired):
		w.Header().Set("Retry-After", "1")
		fail(w, 503, "graph_cache_expired", "The OCI graph requires current member validation. Retry the repository request.")
	case errors.Is(e, store.ErrOCICache):
		fail(w, 502, "upstream_unavailable", "Inspect the OCI source cache state and repair or revalidate the failed source; group requests cannot bypass its failure.")
	case errors.Is(e, store.ErrOCIUnvalidated):
		fail(w, 409, "oci_manifest_unvalidated", "Re-publish the exact retained manifests through a writer, children before parents, to validate their structure and descriptors; existing digest decisions remain in force.")
	case errors.Is(e, store.ErrPythonUnvalidated):
		fail(w, 409, "python_metadata_unvalidated", "Re-upload the exact retained distribution through a writer to validate its archive identity; do not approve unverified metadata.")
	case errors.Is(e, store.ErrMetadataLimit):
		fail(w, 503, "metadata_budget_exceeded", "Ask the operator to inspect native index or graph size and its metadata budget; no partial result was returned.")
	case errors.Is(e, store.ErrBusy):
		w.Header().Set("Retry-After", "1")
		fail(w, 503, "retrieval_in_progress", "Retry after one second; inspect the proxy cache operation for the path.")
	case errors.Is(e, store.ErrLeaseLost):
		fail(w, 409, "retrieval_superseded", "A newer retrieval or operator revalidation fenced this worker; retry the request.")
	case errors.Is(e, upstream.ErrPath):
		fail(w, 400, "ambiguous_upstream_path", "Use a canonical path without percent escapes, dot segments or URL controls.")
	case errors.Is(e, errUpstreamIntegrity):
		fail(w, 502, "upstream_integrity_failure", "Inspect the configured upstream checksum and quarantine the affected source.")
	case errors.Is(e, errUpstream):
		fail(w, 502, "upstream_unavailable", "Inspect the proxy cache status, configured source, credential reference and network allowlist.")
	case errors.Is(e, store.ErrUnauthenticated):
		w.Header().Set("WWW-Authenticate", `Basic realm="cratectl"`)
		fail(w, 401, "unauthenticated", "Configure an unexpired, unrevoked tenant credential.")
	case errors.Is(e, store.ErrNotFound):
		fail(w, 404, "not_found", "Check the repository and package coordinate.")
	case errors.Is(e, store.ErrDenied):
		fail(w, 403, "policy_denied", "Check repository grants, the exact digest and current policy; group access also requires source access.")
	case errors.Is(e, store.ErrConflict):
		fail(w, 409, "conflict", "Use a new coordinate or idempotency key for different content.")
	case errors.Is(e, blob.ErrLimit):
		fail(w, 413, "object_limit", "Reduce object size or ask the operator to adjust the configured limit.")
	case errors.Is(e, blob.ErrDigest), errors.Is(e, blob.ErrLength):
		fail(w, 400, "upload_mismatch", "Retry with the declared length and digest of the exact uploaded bytes.")
	case errors.Is(e, blob.ErrIntegrity):
		fail(w, 503, "integrity_failure", "Restore the exact digest from a verified source and inspect storage health.")
	default:
		fail(w, 503, "dependency_failure", "Retry; ask the operator to inspect database and object storage health.")
	}
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	if r.URL.Path == "/" || r.URL.Path == "/console" || strings.HasPrefix(r.URL.Path, "/console/") {
		consoleui.Serve(w, r)
		return
	}
	if r.URL.Path == "/health/live" {
		writeJSON(w, 200, map[string]string{"status": "live"})
		return
	}
	if r.URL.Path == "/health/ready" {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if e := s.DB.Ready(ctx); e != nil {
			respondErr(w, e)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ready"})
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" && r.Method != "POST" && r.Method != "PUT" && r.Method != "PATCH" && r.Method != "DELETE" {
		w.Header().Set("Allow", "GET, HEAD, POST, PUT, PATCH, DELETE")
		fail(w, 405, "method_not_allowed", "Use a documented protocol method.")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		fail(w, 503, "transfer_saturated", "Retry after the admission queue has capacity.")
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if _, p, ok := r.BasicAuth(); ok {
		token = p
	}
	i, e := s.DB.Authenticate(r.Context(), token)
	if e != nil {
		if !errors.Is(e, pgx.ErrNoRows) && !errors.Is(e, store.ErrNotFound) && !errors.Is(e, store.ErrUnauthenticated) {
			respondErr(w, e)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="cratectl"`)
		fail(w, 401, "unauthenticated", "Configure an unexpired tenant service token.")
		return
	}
	if r.URL.Path == "/v2/" {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.WriteHeader(200)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/") {
		s.management(w, r, i)
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 3)
	if len(parts) < 2 || !store.Name.MatchString(parts[1]) {
		fail(w, 404, "not_found", "Use the repository client configuration.")
		return
	}
	repo, e := s.DB.Repository(r.Context(), i, parts[1])
	if e != nil {
		respondErr(w, e)
		return
	}
	p := ""
	if len(parts) == 3 {
		p = parts[2]
	}
	prefix := map[string]string{"generic": "r", "maven": "r", "npm": "npm", "pypi": "pypi", "oci": "v2"}[repo.Format]
	a := s.adapters[repo.Format]
	if a == nil || parts[0] != prefix {
		fail(w, 404, "format_mismatch", "Use the native endpoint for this repository format.")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" && !i.CanWrite() {
		fail(w, 403, "forbidden", "A repository writer or administrator token is required.")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		if repo.Mode != "hosted" {
			fail(w, 405, "read_only_repository", "Publish to a hosted source, then consume through the proxy/group endpoint.")
			return
		}
		if e := s.DB.AuthorizeWrite(r.Context(), i, repo.Name); e != nil {
			respondErr(w, e)
			return
		}
	}

	a.Serve(w, r, i, repo, p)
}
func readJSON(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		fail(w, 400, "invalid_json", "Use a valid request within the documented size limit.")
		return false
	}
	var rest any
	if e := d.Decode(&rest); e != io.EOF {
		fail(w, 400, "invalid_json", "Send one JSON object.")
		return false
	}
	return true
}
func (s *Server) management(w http.ResponseWriter, r *http.Request, i store.Identity) {
	p := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	if s.holdMatterManagement(w, r, i, p) {
		return
	}
	if s.holdCaseManagement(w, r, i, p) {
		return
	}
	if s.holdManagement(w, r, i, p) {
		return
	}
	if s.retentionManagement(w, r, i, p) {
		return
	}
	if s.repairManagement(w, r, i, p) {
		return
	}
	if s.configurationManagement(w, r, i, p) {
		return
	}
	if s.lifecycleManagement(w, r, i, p) {
		return
	}
	if p == "session" {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			fail(w, 405, "method_not_allowed", "Read current identity with GET.")
			return
		}
		if e := s.DB.Tx(r.Context(), i, false, func(pgx.Tx) error { return nil }); e != nil {
			respondErr(w, e)
			return
		}
		formats := []string{}
		for _, name := range []string{"generic", "maven", "npm", "pypi", "oci"} {
			if s.adapters[name] != nil {
				formats = append(formats, name)
			}
		}
		writeJSON(w, 200, map[string]any{"tenant": i.Tenant, "actor": i.Actor, "role": i.Role, "public_url": s.PublicURL, "formats": formats})
		return
	}
	if p == "maintenance/storage-inventories" || strings.HasPrefix(p, "maintenance/storage-inventories/") {
		s.inventoryManagement(w, r, i, p)
		return
	}
	if p == "maintenance/integrity-schedules" || strings.HasPrefix(p, "maintenance/integrity-schedules/") {
		s.scheduleManagement(w, r, i, p)
		return
	}
	if p == "maintenance/integrity-sweeps" || strings.HasPrefix(p, "maintenance/integrity-sweeps/") {
		s.sweepManagement(w, r, i, p)
		return
	}
	if p == "jobs" || strings.HasPrefix(p, "jobs/") || p == "activity" || p == "maintenance/reconciliations" {
		s.jobManagement(w, r, i, p)
		return
	}
	if r.Method == "GET" {
		switch {
		case p == "repositories":
			s.managementPage(w, r, i, "")
		case p == "audit":
			if i.Role != "admin" {
				fail(w, 403, "forbidden", "A tenant administrator token is required to inspect the full tenant audit journal.")
				return
			}
			after, e := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
			if r.URL.Query().Get("after") == "" {
				after = 0
				e = nil
			}
			if e != nil || after < 0 {
				fail(w, 400, "invalid_cursor", "Use a nonnegative sequence number.")
				return
			}
			v, e := s.DB.Events(r.Context(), i, after)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, map[string]any{"items": v, "limit": 1000})
		case strings.HasPrefix(p, "repositories/") && !strings.Contains(strings.TrimPrefix(p, "repositories/"), "/"):
			name := strings.TrimPrefix(p, "repositories/")
			if !store.Name.MatchString(name) || r.URL.RawQuery != "" {
				fail(w, 400, "invalid_repository", "Choose one repository name without query parameters.")
				return
			}
			value, e := s.DB.Repository(r.Context(), i, name)
			if e != nil {
				respondErr(w, e)
				return
			}
			if i.Role != "admin" {
				value.Settings = store.RepositorySettings{}
			}
			writeJSON(w, 200, value)

		case strings.HasPrefix(p, "repositories/") && strings.HasSuffix(p, "/artifacts/reference"):
			s.managementReference(w, r, i, p)
		case strings.HasPrefix(p, "repositories/") && strings.HasSuffix(p, "/artifacts"):
			s.managementPage(w, r, i, strings.TrimSuffix(strings.TrimPrefix(p, "repositories/"), "/artifacts"))
		case strings.HasPrefix(p, "repositories/") && strings.HasSuffix(p, "/cache"):
			name := strings.TrimSuffix(strings.TrimPrefix(p, "repositories/"), "/cache")
			path := r.URL.Query().Get("path")
			if !upstream.SafePath(path) {
				fail(w, 400, "invalid_path", "Choose one canonical package path in the path query.")
				return
			}
			value, e := s.DB.Retrieval(r.Context(), i, name, path)
			if e != nil {
				respondErr(w, e)
				return
			}
			writeJSON(w, 200, value)

		default:
			fail(w, 404, "not_found", "Use a documented management API.")
		}
		return
	}
	if i.Role != "admin" {
		fail(w, 403, "forbidden", "A tenant administrator token is required.")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00") {
		fail(w, 400, "idempotency_key_required", "Supply an 8–128 character Idempotency-Key; reuse it only for an identical request.")
		return
	}
	data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if e != nil {
		fail(w, 413, "request_limit", "Send less than 64 KiB of management JSON.")
		return
	}
	fp := crypt.Digest(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), data...))
	ctx := r.Context()
	var fn func(pgx.Tx) (any, int, error)
	kind := ""
	if p == "repositories" && r.Method == "POST" {
		var v store.Repository
		if !decodeManagement(data, &v) || s.adapters[v.Format] == nil || store.ValidateRepository(&v) != nil {
			fail(w, 400, "invalid_repository", "Use a valid name, access policy, supported format/mode and bounded source configuration.")
			return
		}
		if v.Settings.Upstream != nil {
			if _, e := s.credential(i.Tenant, *v.Settings.Upstream); e != nil {
				fail(w, 400, "upstream_credential_authority", "Configure a tenant-scoped credential bound to this exact upstream authority, path prefix and authentication scheme.")
				return
			}
		}
		for _, source := range v.Settings.DownloadSources {
			if _, e := s.credential(i.Tenant, source); e != nil {
				fail(w, 400, "upstream_credential_authority", "Bind each download credential to its own tenant, approved URL and authentication scheme.")
				return
			}
		}
		if v.Settings.OCITokenEndpoint != nil {
			if _, e := s.credential(i.Tenant, *v.Settings.OCITokenEndpoint); e != nil {
				fail(w, 400, "upstream_credential_authority", "Bind the OCI token credential to its own approved realm and authentication scheme.")
				return
			}
		}

		kind = "repository.created"
		fn = func(tx pgx.Tx) (any, int, error) { e := store.CreateRepository(ctx, tx, i, v); return v, 201, e }

	} else {
		bits := strings.Split(p, "/")
		if len(bits) != 3 || bits[0] != "repositories" || !store.Name.MatchString(bits[1]) || r.Method != "PUT" {
			fail(w, 404, "not_found", "Use a documented mutation endpoint.")
			return
		}
		repo := bits[1]
		switch bits[2] {
		case "yanks":
			var v struct {
				Filename string `json:"filename"`
				Yanked   *bool  `json:"yanked"`
				Reason   string `json:"reason"`
			}
			if !decodeManagement(data, &v) || v.Yanked == nil || !ValidPath(v.Filename) || path.Base(v.Filename) != v.Filename || len(v.Reason) > 4096 {
				fail(w, 400, "invalid_yank", "Choose one distribution basename, yanked boolean and bounded reason.")
				return
			}
			kind = "python.yank.changed"
			fn = func(tx pgx.Tx) (any, int, error) {
				value, e := store.SetPythonYank(ctx, tx, i, repo, v.Filename, *v.Yanked, v.Reason)
				return value, 200, e
			}
		case "cache":
			var v struct {
				Path string `json:"path"`
			}
			if !decodeManagement(data, &v) || !upstream.SafePath(v.Path) {
				fail(w, 400, "invalid_path", "Choose one canonical proxy package path.")
				return
			}
			kind = "proxy.cache.expired"
			fn = func(tx pgx.Tx) (any, int, error) {
				value, e := store.InvalidateRetrieval(ctx, tx, i, repo, v.Path)
				return value, 200, e
			}

		case "grants":
			var v struct {
				Actor string `json:"actor"`
				Read  bool   `json:"read"`
				Write bool   `json:"write"`
			}
			if !decodeManagement(data, &v) || !store.Name.MatchString(v.Actor) || (v.Write && !v.Read) {
				fail(w, 400, "invalid_grant", "Choose a valid actor; write authority also requires read authority.")
				return
			}
			kind = "repository.grant.changed"
			fn = func(tx pgx.Tx) (any, int, error) {
				if _, e := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant,repository,actor) DO UPDATE SET can_read=excluded.can_read,can_write=excluded.can_write`, i.Tenant, repo, v.Actor, v.Read, v.Write); e != nil {
					return nil, 0, e
				}
				return map[string]any{"repository": repo, "actor": v.Actor, "read": v.Read, "write": v.Write}, 200, nil
			}

		case "policy":
			var v struct {
				RequireReview *bool `json:"require_review"`
			}
			if !decodeManagement(data, &v) || v.RequireReview == nil {
				fail(w, 400, "invalid_policy", "Set require_review explicitly.")
				return
			}
			kind = "policy.changed"
			fn = func(tx pgx.Tx) (any, int, error) {
				tag, e := tx.Exec(ctx, `UPDATE cratectl.repositories SET require_review=$1 WHERE name=$2`, *v.RequireReview, repo)
				if e != nil {
					return nil, 0, e
				}
				if tag.RowsAffected() != 1 {
					return nil, 0, store.ErrNotFound
				}
				return map[string]any{"repository": repo, "require_review": *v.RequireReview}, 200, nil
			}
		case "decisions":
			var v struct {
				Path     string `json:"path"`
				Digest   string `json:"digest"`
				Decision string `json:"decision"`
			}
			if !decodeManagement(data, &v) || !ValidPath(v.Path) || len(v.Digest) != 64 || (v.Decision != "allowed" && v.Decision != "denied") {
				fail(w, 400, "invalid_decision", "Choose an exact path, SHA-256 digest and allowed/denied manual decision.")
				return
			}
			kind = "artifact.manual-decision"
			fn = func(tx pgx.Tx) (any, int, error) {
				value, e := store.Decide(ctx, tx, i, repo, v.Path, v.Digest, v.Decision)
				return value, 200, e
			}

		default:
			fail(w, 404, "not_found", "Use a documented mutation endpoint.")
			return
		}
	}
	result, e := s.DB.Mutate(ctx, i, key, fp, kind, fn)
	if e != nil {
		respondErr(w, e)
		return
	}
	if result.Replay {
		w.Header().Set("Idempotent-Replayed", "true")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(result.Status)
	w.Write(result.Body)
}
func (s *Server) serveArtifact(w http.ResponseWriter, r *http.Request, i store.Identity, repo, p string) {
	repository, e := s.DB.Repository(r.Context(), i, repo)
	if e != nil {
		respondErr(w, e)
		return
	}
	resolved, e := s.resolve(r.Context(), i, repository, p, forceRefresh(r))
	if e != nil {
		respondErr(w, e)
		return
	}
	s.serveResolvedArtifact(w, r, i, resolved)
}
func (s *Server) serveResolvedArtifact(w http.ResponseWriter, r *http.Request, i store.Identity, resolved resolvedArtifact) {
	a := resolved.artifact
	p := a.Path
	f, e := s.Blobs.OpenVerified(r.Context(), i.Tenant, a.Digest, a.Size)
	if e != nil {
		respondErr(w, e)
		return
	}
	defer f.Close()
	// Hashing a large object may take time. Re-check policy and a mutable
	// reference immediately before committing response headers. Authorization
	// admits this transfer; later policy changes affect new requests.
	current, e := s.guardResolved(r.Context(), i, resolved)
	if e != nil {
		respondErr(w, e)
		return
	}
	if current.Digest != a.Digest {
		respondErr(w, store.ErrConflict)
		return
	}
	if resolved.source.Format == "oci" {
		_, operation, _ := parseOCIPath(a.Path)
		if operation == "manifests" && !ociAcceptsMediaFields(r.Header.Values("Accept"), a.MediaType) {
			fail(w, 406, "MANIFEST_UNSUPPORTED", "Accept the stored OCI/Docker manifest media type; digest-addressed bytes are served unchanged.")
			return
		}
		w.Header().Set("Docker-Content-Digest", "sha256:"+a.Digest)
	}
	st, e := f.Stat()
	if e != nil || st.Size() != a.Size {
		fail(w, 503, "integrity_failure", "Restore the object from a verified source; do not approve missing bytes.")
		return
	}
	if resolved.cache != "" {
		w.Header().Set("X-Cratectl-Cache", resolved.cache)
	}
	w.Header().Set("X-Cratectl-Repository", resolved.source.Name)
	w.Header().Set("ETag", `"sha256:`+a.Digest+`"`)
	w.Header().Set("Content-Type", a.MediaType)
	w.Header().Set("X-Checksum-Sha256", a.Digest)
	http.ServeContent(w, r, path.Base(p), a.Created, f)
}
func (s *Server) raw(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	var mavenChecksums map[string]string
	if !ValidPath(p) {
		fail(w, 400, "invalid_path", "Use a relative coordinate without dot segments or control characters.")
		return
	}
	if repo.Format == "maven" {
		metadataPath, metadataAlgorithm := p, ""
		for _, algorithm := range []string{"sha1", "sha256", "sha512", "md5"} {
			if strings.HasSuffix(p, "."+algorithm) {
				metadataPath = strings.TrimSuffix(p, "."+algorithm)
				metadataAlgorithm = algorithm
				break
			}
		}
		if path.Base(metadataPath) == "maven-metadata.xml" && (r.Method == "GET" || r.Method == "HEAD") {
			s.serveMavenMetadata(w, r, i, repo, metadataPath, metadataAlgorithm)
			return
		}
		if path.Base(p) == "maven-metadata.xml" && r.Method == "PUT" {
			data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, s.NativeMetadataBytes))
			if e != nil {
				fail(w, 413, "metadata_budget_exceeded", "Reduce Maven metadata size or adjust the native metadata budget after checking capacity.")
				return
			}
			if _, e = parseMavenMetadata(data, p, s.NativeVersionLimit, s.NativeMetadataBytes); e != nil {
				if errors.Is(e, store.ErrMetadataLimit) {
					respondErr(w, e)
				} else {
					fail(w, 400, "invalid_maven_metadata", "Use bounded Maven G/A/V XML whose coordinates and snapshot filenames match this repository path.")
				}
				return
			}
			mavenChecksums = map[string]string{}
			for _, algorithm := range []string{"sha256", "sha512", "sha1", "md5"} {
				hash := crypt.CompatibilityHash(algorithm)
				_, _ = hash.Write(data)
				mavenChecksums[algorithm] = hex.EncodeToString(hash.Sum(nil))
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
		}
		for _, algorithm := range []string{"sha1", "sha256", "sha512", "md5"} {
			if strings.HasSuffix(p, "."+algorithm) {
				parent := strings.TrimSuffix(p, "."+algorithm)
				var a store.Artifact
				var resolved resolvedArtifact
				var e error
				if r.Method == "PUT" {
					a, e = s.DB.ArtifactForPublication(r.Context(), i, repo.Name, parent)
				} else {
					resolved, e = s.resolve(r.Context(), i, repo, parent, forceRefresh(r))
					a = resolved.artifact
				}
				if e != nil {
					respondErr(w, e)
					return
				}
				if r.Method == "PUT" && path.Base(parent) == "maven-metadata.xml" {
					data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
					if err != nil {
						fail(w, 400, "checksum_mismatch", "Use a checksum of the exact accepted metadata publication.")
						return
					}
					err = s.DB.MavenChecksumReceipt(r.Context(), i, repo.Name, parent, algorithm, strings.ToLower(strings.TrimSpace(string(data))))
					if err == nil {
						w.WriteHeader(201)
						return
					}
					if !errors.Is(err, store.ErrNotFound) {
						respondErr(w, err)
						return
					}
					r.Body = io.NopCloser(bytes.NewReader(data))
				}
				file, e := s.Blobs.OpenVerified(r.Context(), i.Tenant, a.Digest, a.Size)
				if e != nil {
					respondErr(w, e)
					return
				}
				defer file.Close()
				h := crypt.CompatibilityHash(algorithm)
				if _, e = io.Copy(h, file); e != nil {
					respondErr(w, e)
					return
				}
				checksum := hex.EncodeToString(h.Sum(nil))
				if r.Method == "GET" || r.Method == "HEAD" {
					if _, e = s.guardResolved(r.Context(), i, resolved); e != nil {
						respondErr(w, e)
						return
					}
					if resolved.cache != "" {
						w.Header().Set("X-Cratectl-Cache", resolved.cache)
					}
					w.Header().Set("Content-Type", "text/plain")
					w.Header().Set("ETag", `"sha256:`+a.Digest+`-`+algorithm+`"`)
					http.ServeContent(w, r, path.Base(p), a.Created, strings.NewReader(checksum))
					return
				}
				if r.Method != "PUT" {
					fail(w, 405, "method_not_allowed", "Publish checksum files with PUT.")
					return
				}
				data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
				if e != nil || strings.TrimSpace(string(data)) != checksum {
					fail(w, 400, "checksum_mismatch", "The checksum must match the exact published parent bytes.")
					return
				}
				w.WriteHeader(201)
				return
			}
		}
	}

	if r.Method == "GET" || r.Method == "HEAD" {
		s.serveArtifact(w, r, i, repo.Name, p)
		return
	}
	if r.Method != "PUT" {
		fail(w, 405, "method_not_allowed", "Publish with PUT.")
		return
	}
	obj, e := s.Blobs.Put(r.Context(), i.Tenant, r.Body, r.Header.Get("X-Checksum-Sha256"), r.ContentLength)
	if e != nil {
		respondErr(w, e)
		return
	}
	a := store.Artifact{Path: p, Digest: obj.Digest, Size: obj.Size, MediaType: "application/octet-stream"}
	if repo.Format == "maven" && path.Base(p) == "maven-metadata.xml" {
		a.MediaType = "application/xml"
		e = s.DB.ReplaceMavenMetadata(r.Context(), i, repo.Name, a, mavenChecksums)
	} else {
		e = s.DB.Publish(r.Context(), i, repo.Name, []store.Artifact{a})
	}
	if e != nil {
		respondErr(w, e)
		return
	}
	writeJSON(w, 201, obj)
}
func (s *Server) url(p string) string { return s.PublicURL + p }
func segment(v string) string         { return url.PathEscape(v) }

func decodeManagement(data []byte, value any) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return false
	}
	var rest any
	return decoder.Decode(&rest) == io.EOF
}
