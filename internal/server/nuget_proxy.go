// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/nuget"
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

func nugetUpstreamPath(coordinate store.NuGetProxyCoordinate) string {
	if coordinate.Version == "" {
		return coordinate.ID + "/index.json"
	}
	return coordinate.ID + "/" + coordinate.Version + "/" + coordinate.ID + "." + coordinate.Version + ".nupkg"
}

func parseNuGetProxyVersions(ctx context.Context, data []byte, limit int) ([]string, error) {
	var wire struct {
		Versions []string `json:"versions"`
	}
	if !utf8.Valid(data) || uniqueOCIJSON(data) != nil || !decodeManagement(data, &wire) || wire.Versions == nil || len(wire.Versions) > limit {
		return nil, store.ErrNuGetUnvalidated
	}
	seen := make(map[string]bool, len(wire.Versions))
	for _, value := range wire.Versions {
		version, err := nuget.VersionKey(value)
		if err != nil || version != value || seen[version] {
			return nil, store.ErrNuGetUnvalidated
		}
		seen[version] = true
	}
	return nuget.SortVersionKeys(ctx, wire.Versions)
}

func (s *Server) materializeNuGetProxy(ctx context.Context, i store.Identity, repo store.Repository, coordinate store.NuGetProxyCoordinate,
	endpoint *upstream.Endpoint, path string, response *http.Response, result *store.RetrievalResult) {
	if coordinate.Version == "" {
		limit := min(s.NativeMetadataBytes, 8<<20)
		body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
		if err != nil || int64(len(body)) > limit {
			result.Failure = "upstream_metadata_budget"
			return
		}
		versions, err := parseNuGetProxyVersions(ctx, body, min(s.NativeVersionLimit, 10000))
		if err != nil {
			result.Failure = "upstream_metadata_invalid"
			return
		}
		metadata, err := json.Marshal(store.NuGetProxyCatalog{ID: coordinate.ID, Authority: repo.Settings.Upstream.URL, Versions: versions})
		if err != nil || int64(len(metadata)) > limit {
			result.Failure = "upstream_metadata_budget"
			return
		}
		object, err := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(metadata), "", int64(len(metadata)))
		if err != nil {
			result.Failure = "upstream_transfer_failure"
			return
		}
		result.Object, result.Metadata, result.MediaType = &object, metadata, store.NuGetProxyCatalogMedia
		return
	}
	if response.ContentLength > s.NuGetUploadBytes {
		result.Failure = "upstream_archive_budget"
		return
	}
	object, err := s.Blobs.Put(ctx, i.Tenant, io.LimitReader(response.Body, s.NuGetUploadBytes+1), "", response.ContentLength)
	if err != nil || object.Size > s.NuGetUploadBytes {
		result.Failure = "upstream_transfer_failure"
		return
	}
	file, err := s.Blobs.OpenVerified(ctx, i.Tenant, object.Digest, object.Size)
	if err != nil {
		result.Failure = "upstream_integrity_failure"
		return
	}
	defer file.Close()
	if repo.Settings.Cache.RequireChecksum {
		integrity, err := nugetProxyChecksum(ctx, endpoint, path)
		if err != nil || integrity.Verify(file) != nil {
			result.Failure = "upstream_integrity_failure"
			return
		}
	}
	inspected, err := nuget.InspectArchive(ctx, file, object.Size, nuget.ArchiveLimits{
		CompressedBytes: s.NuGetUploadBytes, ExpandedBytes: s.NuGetExpandedBytes, DirectoryBytes: 16 << 20, Files: s.NuGetFileLimit,
	})
	if err != nil {
		result.Failure = "upstream_archive_invalid"
		return
	}
	id, err := nuget.IDKey(inspected.Identity.ID)
	if err != nil || id != coordinate.ID || inspected.Identity.VersionKey != coordinate.Version {
		result.Failure = "upstream_nuget_coordinate_mismatch"
		return
	}
	catalog, err := nuget.BuildCatalog(ctx, inspected.Nuspec)
	if err != nil {
		result.Failure = "upstream_metadata_invalid"
		return
	}
	digest := crypt.Digest(inspected.Nuspec)
	catalog.SourceSHA = digest
	metadata, err := json.Marshal(store.NuGetPackage{ID: inspected.Identity.ID, IDKey: id, IDProfile: nuget.IDKeyProfile,
		RawVersion: inspected.Identity.RawVersion, VersionKey: coordinate.Version, NuspecPath: inspected.NuspecPath,
		Nuspec: inspected.Nuspec, NuspecSHA256: digest, Validated: true, Catalog: &catalog, SourceAuthority: repo.Settings.Upstream.URL})
	if err != nil || len(metadata) > store.MaxNuGetMetadataBytes {
		result.Failure = "upstream_metadata_budget"
		return
	}
	result.Object, result.Metadata, result.MediaType = &object, metadata, "application/octet-stream"
}

func nugetProxyChecksum(ctx context.Context, endpoint *upstream.Endpoint, path string) (crypt.SourceIntegrity, error) {
	response, err := endpoint.Get(ctx, path+".sha512", nil)
	if err != nil {
		return crypt.SourceIntegrity{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") {
		return crypt.SourceIntegrity{}, errUpstreamIntegrity
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 129))
	if err != nil || len(data) > 128 {
		return crypt.SourceIntegrity{}, errUpstreamIntegrity
	}
	checksum := strings.TrimSpace(string(data))
	decoded, err := base64.StdEncoding.Strict().DecodeString(checksum)
	if err != nil || len(decoded) != 64 || base64.StdEncoding.EncodeToString(decoded) != checksum {
		return crypt.SourceIntegrity{}, errUpstreamIntegrity
	}
	return crypt.ParseSourceIntegrity("sha512-"+checksum, "", false)
}
