// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/upstream"
)

const nugetPackageBaseAddress = "PackageBaseAddress/3.0.0"

func nugetServiceIndexMatches(body []byte, approved string) bool {
	var index struct {
		Version   string `json:"version"`
		Resources []struct {
			ID   string          `json:"@id"`
			Type json.RawMessage `json:"@type"`
		} `json:"resources"`
	}
	if !utf8.Valid(body) || uniqueOCIJSON(body) != nil || json.Unmarshal(body, &index) != nil || index.Version != "3.0.0" || len(index.Resources) > 256 {
		return false
	}
	matches := 0
	for _, resource := range index.Resources {
		var names []string
		var name string
		if json.Unmarshal(resource.Type, &name) == nil && name != "" {
			names = []string{name}
		} else if json.Unmarshal(resource.Type, &names) != nil || len(names) == 0 || len(names) > 16 {
			return false
		}
		if !slices.Contains(names, nugetPackageBaseAddress) {
			continue
		}
		if len(resource.ID) > 2048 || strings.TrimSuffix(resource.ID, "/") != strings.TrimSuffix(approved, "/") {
			return false
		}
		matches++
	}
	return matches == 1
}

func (s *Server) nugetServiceIndexEndpoint(ctx context.Context, tenant string, index *upstream.Endpoint, base upstream.Config) (*upstream.Endpoint, string) {
	response, err := index.GetExact(ctx)
	if err != nil {
		if errors.Is(err, upstream.ErrDestination) || errors.Is(err, upstream.ErrRedirect) || errors.Is(err, upstream.ErrPath) {
			return nil, "upstream_destination_rejected"
		}
		return nil, "transient_upstream_failure"
	}
	defer response.Body.Close()
	if response.StatusCode >= 500 {
		return nil, "transient_upstream_failure"
	}
	if response.StatusCode != http.StatusOK || (response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") {
		return nil, "upstream_nuget_service_index_invalid"
	}
	limit := min(s.NativeMetadataBytes, 1<<20)
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit || !nugetServiceIndexMatches(body, base.URL) {
		return nil, "upstream_nuget_service_index_invalid"
	}
	credential, err := s.credential(tenant, base)
	if err != nil {
		return nil, "upstream_credential_authority"
	}
	endpoint, err := upstream.New(base, credential, s.PrivateUpstreamNetworks...)
	if err != nil {
		return nil, "upstream_destination_rejected"
	}
	return endpoint, ""
}
