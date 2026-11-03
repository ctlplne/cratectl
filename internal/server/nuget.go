// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/nuget"
	"ctlplne.dev/cratectl/internal/store"
)

const nugetPublishEndpoint = "api/v2/package"

func nugetListingCoordinate(p string) (string, string, bool) {
	prefix := nugetPublishEndpoint + "/"
	if !strings.HasPrefix(p, prefix) {
		return "", "", false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(p, prefix), "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// requestCredential selects one identity. X-NuGet-ApiKey is authoritative only
// for native publication/listing; Basic/Bearer identities are never merged into it.
func requestCredential(r *http.Request) (string, error) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 3)
	useKey := false
	if len(parts) == 3 && parts[0] == "nuget" && store.Name.MatchString(parts[1]) {
		_, _, listing := nugetListingCoordinate(parts[2])
		useKey = r.Method == "PUT" && strings.TrimSuffix(parts[2], "/") == nugetPublishEndpoint || (r.Method == "DELETE" || r.Method == "POST") && listing
	}
	if useKey {
		values := r.Header.Values("X-NuGet-ApiKey")
		if len(values) != 1 || len(values[0]) < 32 || len(values[0]) > 256 || strings.TrimSpace(values[0]) != values[0] || strings.ContainsAny(values[0], ",\r\n\x00") {
			return "", store.ErrUnauthenticated
		}
		return values[0], nil
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if _, password, ok := r.BasicAuth(); ok {
		token = password
	}
	return token, nil
}

func (s *Server) nuget(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	if repo.Mode != "hosted" {
		fail(w, 405, "nuget_mode_unavailable", "Publish and read through a hosted NuGet repository. Proxy and group support remain unfinished.")
		return
	}
	if strings.TrimSuffix(p, "/") == nugetPublishEndpoint {
		if r.Method != "PUT" {
			w.Header().Set("Allow", "PUT")
			fail(w, 405, "method_not_allowed", "Publish with NuGet push. Unlist or relist using the package ID and version endpoint.")
			return
		}
		s.nugetPush(w, r, i, repo)
		return
	}
	if id, version, ok := nugetListingCoordinate(p); ok {
		if r.Method != "DELETE" && r.Method != "POST" {
			w.Header().Set("Allow", "DELETE, POST")
			fail(w, 405, "method_not_allowed", "Use DELETE to unlist this version or POST to relist it. Unlisting retains package bytes for pinned consumers.")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if _, e := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 0)); e != nil {
			fail(w, 400, "invalid_nuget_listing", "Send the package ID and version in the URL with an empty request body.")
			return
		}
		if e := s.DB.SetNuGetListing(ctx, i, repo.Name, id, version, r.Method == "POST"); e != nil {
			respondErr(w, e)
			return
		}
		if r.Method == "DELETE" {
			w.WriteHeader(204)
		} else {
			w.WriteHeader(200)
		}
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		fail(w, 405, "method_not_allowed", "Read NuGet metadata and package content with GET or HEAD.")
		return
	}
	if p == "index.json" || p == "query" || strings.HasPrefix(p, "registration/") {
		root, e := s.nugetRoot(repo.Name)
		if e != nil {
			fail(w, 503, "public_url_required", "Configure the server's public HTTP(S) URL before using NuGet discovery.")
			return
		}
		if p == "query" {
			s.nugetSearch(w, r, i, repo, root)
			return
		}
		if strings.HasPrefix(p, "registration/") {
			s.nugetRegistration(w, r, i, repo, p, root)
			return
		}
		s.nugetJSON(w, r, map[string]any{"version": "3.0.0", "resources": []map[string]string{{"@id": root + "flat/", "@type": "PackageBaseAddress/3.0.0"}, {"@id": root + nugetPublishEndpoint, "@type": "PackagePublish/2.0.0"}, {"@id": root + "registration/", "@type": "RegistrationsBaseUrl/3.6.0"}, {"@id": root + "query", "@type": "SearchQueryService/3.0.0-rc"}}})
		return
	}
	if !strings.HasPrefix(p, "flat/") {
		respondErr(w, store.ErrNotFound)
		return
	}
	parts := strings.Split(strings.TrimPrefix(p, "flat/"), "/")
	if len(parts) != 2 && len(parts) != 3 {
		respondErr(w, store.ErrNotFound)
		return
	}
	id, e := nuget.IDKey(parts[0])
	if e != nil || id != parts[0] {
		respondErr(w, store.ErrNotFound)
		return
	}
	if len(parts) == 2 && parts[1] == "index.json" {
		versions, e := s.DB.NuGetVersions(r.Context(), i, repo.Name, id, s.NativeVersionLimit, s.NativeMetadataBytes)
		if e != nil {
			respondErr(w, e)
			return
		}
		if len(versions) == 0 {
			respondErr(w, store.ErrNotFound)
			return
		}
		s.nugetJSON(w, r, map[string]any{"versions": versions})
		return
	}
	if len(parts) != 3 {
		respondErr(w, store.ErrNotFound)
		return
	}
	version, e := nuget.VersionKey(parts[1])
	if e != nil || version != parts[1] || (parts[2] != id+"."+version+".nupkg" && parts[2] != id+".nuspec") {
		respondErr(w, store.ErrNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	resolved, e := s.resolve(ctx, i, repo, store.NuGetPath(id, version), false)
	if e != nil {
		respondErr(w, e)
		return
	}
	if strings.HasSuffix(parts[2], ".nupkg") {
		s.serveResolvedArtifact(w, r, i, resolved)
		return
	}
	metadata, e := store.ValidateNuGetArtifact(ctx, resolved.artifact)
	if e != nil {
		respondErr(w, e)
		return
	}
	parent, e := s.Blobs.OpenVerified(ctx, i.Tenant, resolved.artifact.Digest, resolved.artifact.Size)
	if e != nil {
		respondErr(w, e)
		return
	}
	parent.Close()
	if _, e = s.guardResolved(ctx, i, resolved); e != nil {
		respondErr(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Cratectl-Repository", repo.Name)
	w.Header().Set("ETag", `"sha256:`+metadata.NuspecSHA256+`"`)
	http.ServeContent(w, r, id+".nuspec", time.Time{}, bytes.NewReader(metadata.Nuspec))
}

func (s *Server) nugetJSON(w http.ResponseWriter, r *http.Request, value any) {
	data, e := json.Marshal(value)
	if e != nil || int64(len(data)) > s.NativeMetadataBytes {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", `"sha256:`+crypt.Digest(data)+`"`)
	http.ServeContent(w, r, "index.json", time.Time{}, bytes.NewReader(data))
}

func (s *Server) nugetPush(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository) {
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if s.NuGetUploadBytes <= 0 || s.NuGetUploadBytes > 1<<30 {
		respondErr(w, store.ErrMetadataLimit)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.NuGetUploadBytes+(1<<20))
	multipart, e := r.MultipartReader()
	if e != nil {
		fail(w, 400, "invalid_nuget_upload", "Use NuGet multipart package publication.")
		return
	}
	// Raw parts prevent MIME transfer encodings from changing the immutable bytes.
	// The protocol ignores filenames and all other per-part metadata.
	part, e := multipart.NextRawPart()
	if e != nil {
		fail(w, 400, "invalid_nuget_upload", "Include one package as the first multipart item.")
		return
	}
	object, e := s.Blobs.Put(ctx, i.Tenant, io.LimitReader(part, s.NuGetUploadBytes+1), "", -1)
	if e != nil {
		var exceeded *http.MaxBytesError
		if errors.Is(e, io.ErrUnexpectedEOF) {
			fail(w, 400, "invalid_nuget_upload", "Send a complete multipart package without a truncated boundary.")
			return
		}
		if errors.As(e, &exceeded) {
			fail(w, 413, "nuget_upload_budget", "Reduce the total multipart bytes within the upload budget.")
			return
		}
		respondErr(w, e)
		return
	}
	if object.Size > s.NuGetUploadBytes {
		fail(w, 413, "nuget_upload_budget", "Reduce the package bytes within the configured NuGet upload budget.")
		return
	}
	// Later items have no package meaning, but still consume byte/part budgets.
	for count := 1; ; count++ {
		part, e = multipart.NextRawPart()
		if e == io.EOF {
			break
		}
		if e != nil || count >= 128 {
			fail(w, 400, "invalid_nuget_upload", "Use a complete multipart body with at most 128 items within the upload budget.")
			return
		}
		if _, e = io.Copy(io.Discard, part); e != nil {
			fail(w, 413, "nuget_upload_budget", "Reduce the total multipart bytes within the upload budget.")
			return
		}
	}
	if _, e = io.Copy(io.Discard, r.Body); e != nil {
		fail(w, 413, "nuget_upload_budget", "Reduce the total multipart bytes within the upload budget.")
		return
	}
	file, e := s.Blobs.OpenVerified(ctx, i.Tenant, object.Digest, object.Size)
	if e != nil {
		respondErr(w, e)
		return
	}
	inspected, e := nuget.InspectArchive(ctx, file, object.Size, nuget.ArchiveLimits{CompressedBytes: s.NuGetUploadBytes, ExpandedBytes: s.NuGetExpandedBytes, DirectoryBytes: 16 << 20, Files: s.NuGetFileLimit})
	file.Close()
	if e != nil {
		fail(w, 400, "invalid_nuget_archive", "Use an unambiguous bounded ZIP32 package with a root Nuspec and safe paths. ZIP64 and split archives remain unsupported.")
		return
	}
	id, e := nuget.IDKey(inspected.Identity.ID)
	if e != nil {
		fail(w, 400, "invalid_nuget_id", "Use a package ID within the documented invariant transport profile.")
		return
	}
	if _, e = nuget.BuildCatalog(ctx, inspected.Nuspec); e != nil {
		fail(w, 400, "invalid_nuget_metadata", "Use bounded manifest properties and valid active dependency IDs and ranges. An invalid range cannot be treated as unrestricted.")
		return
	}
	m := store.NuGetPackage{ID: inspected.Identity.ID, IDKey: id, IDProfile: nuget.IDKeyProfile, RawVersion: inspected.Identity.RawVersion, VersionKey: inspected.Identity.VersionKey, NuspecPath: inspected.NuspecPath, Nuspec: inspected.Nuspec, NuspecSHA256: crypt.Digest(inspected.Nuspec), Validated: true}
	metadata, _ := json.Marshal(m)
	e = s.DB.PublishNuGet(ctx, i, repo.Name, store.Artifact{Path: store.NuGetPath(id, m.VersionKey), Digest: object.Digest, Size: object.Size, MediaType: "application/octet-stream", Metadata: metadata})
	if e != nil {
		respondErr(w, e)
		return
	}
	w.WriteHeader(http.StatusCreated)
}
