// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/management"
)

const managementRoot = "/api/v1/repositories"
const maxResponse = 256 << 10

var (
	cursorPattern = regexp.MustCompile(`^p1\.[a-zA-Z0-9_-]+$`)
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type bridge struct {
	config string
	scope  scope
	slots  chan struct{}
}

type scope struct {
	Registry string `json:"registry"`
	Tenant   string `json:"tenant"`
}

type identity struct {
	Tenant  string   `json:"tenant"`
	Role    string   `json:"role"`
	Formats []string `json:"formats"`
}

type pageRequest struct {
	Limit  *int   `json:"limit,omitempty" jsonschema:"Page size from 1 through 50, default 20."`
	Search string `json:"search,omitempty" jsonschema:"Literal substring in the same authorized repository or artifact inventory."`
	Cursor string `json:"cursor,omitempty" jsonschema:"An opaque cursor returned by this tool with the same scope and search."`
}

func (p pageRequest) query() (url.Values, int, error) {
	limit := 20
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 1 || limit > 50 || !boundedText(p.Search, 256) || !validCursor(p.Cursor) {
		return nil, 0, errors.New("invalid_page: use a limit from 1 through 50, a bounded search and an original cursor")
	}
	query := url.Values{"limit": {strconv.Itoa(limit)}}
	if p.Search != "" {
		query.Set("q", p.Search)
	}
	if p.Cursor != "" {
		query.Set("cursor", p.Cursor)
	}
	return query, limit, nil
}

func validCursor(cursor string) bool {
	return cursor == "" || (len(cursor) <= 3000 && cursorPattern.MatchString(cursor))
}

func boundedText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func validArtifactPath(value string) bool {
	return value != "" && boundedText(value, 2048) && path.Clean(value) == value &&
		!strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") &&
		value != "." && value != ".." && !strings.HasPrefix(value, "../")
}

func endpoint(repositoryName, suffix string) (string, error) {
	if !management.ValidRepositoryName(repositoryName) {
		return "", errors.New("invalid_repository: use a canonical repository name")
	}
	return managementRoot + "/" + repositoryName + suffix, nil
}

type page[T any] struct {
	Items    []T    `json:"items"`
	Limit    int    `json:"limit"`
	Next     string `json:"next"`
	Previous string `json:"previous"`
}

func (p page[T]) valid(requested int) bool {
	return p.Items != nil && len(p.Items) <= requested && p.Limit == requested && validCursor(p.Next) && validCursor(p.Previous)
}

type repository struct {
	Name          string `json:"name"`
	Format        string `json:"format"`
	Mode          string `json:"mode"`
	Access        string `json:"access"`
	RequireReview *bool  `json:"require_review"`
}

func (r repository) valid() bool {
	return management.ValidRepositoryName(r.Name) && boundedText(r.Format, 32) && r.Format != "" &&
		slices.Contains([]string{"hosted", "proxy", "group"}, r.Mode) &&
		slices.Contains([]string{"tenant", "restricted"}, r.Access) && r.RequireReview != nil
}

type artifact struct {
	Repository string `json:"repository"`
	Path       string `json:"path"`
	Digest     string `json:"digest"`
	Size       *int64 `json:"size"`
	MediaType  string `json:"media_type"`
	Decision   string `json:"decision"`
	Deleted    bool   `json:"deleted,omitempty"`
}

func (a artifact) valid(repositoryName string) bool {
	return a.Repository == repositoryName && validArtifactPath(a.Path) && len(a.Digest) == 64 && digestPattern.MatchString(a.Digest) &&
		a.Size != nil && *a.Size >= 0 && boundedText(a.MediaType, 512) && a.Decision != "" && boundedText(a.Decision, 64)
}

func (b *bridge) open() (*http.Client, string, func(), error) {
	client, authority, token, closeClient, err := management.OpenClient(b.config)
	if err != nil {
		return nil, "", nil, errors.New("registry_configuration: check the private configuration and TLS trust")
	}
	if authority != b.scope.Registry {
		closeClient()
		return nil, "", nil, errors.New("registry_scope: configured authority changed")
	}
	client.Transport.(*http.Transport).Proxy = nil
	return client, token, closeClient, nil
}

func (b *bridge) read(ctx context.Context, route string, query url.Values, output any) (identity, error) {
	select {
	case b.slots <- struct{}{}:
		defer func() { <-b.slots }()
	default:
		return identity{}, errors.New("registry_busy: retry the scoped read")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	client, token, closeClient, err := b.open()
	if err != nil {
		return identity{}, err
	}
	defer closeClient()
	var current identity
	if err = get(ctx, client, token, b.scope.Registry+"/api/v1/session", &current); err != nil {
		return identity{}, err
	}
	if current.Tenant != b.scope.Tenant || !slices.Contains([]string{"admin", "writer", "reader"}, current.Role) ||
		current.Formats == nil || len(current.Formats) > 16 {
		return identity{}, errors.New("registry_scope: current credential is outside the expected tenant")
	}
	for _, format := range current.Formats {
		if format == "" || !boundedText(format, 32) {
			return identity{}, errors.New("registry_response: invalid format inventory")
		}
	}
	if route != "" {
		target := b.scope.Registry + route
		if len(query) != 0 {
			target += "?" + query.Encode()
		}
		if err = get(ctx, client, token, target, output); err != nil {
			return identity{}, err
		}
	}
	return current, nil
}

func get(ctx context.Context, client *http.Client, token, target string, value any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return errors.New("registry_request: invalid scoped request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("registry_request: check connectivity and configured TLS trust")
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusUnauthorized:
		return errors.New("registry_unauthenticated: configure a current tenant credential")
	case http.StatusForbidden:
		return errors.New("registry_denied: current cratectl authorization or policy denies this read")
	case http.StatusNotFound:
		return errors.New("registry_absent: no visible reference in this tenant and repository")
	case http.StatusOK:
	default:
		return fmt.Errorf("registry_response: HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxResponse {
		return errors.New("registry_response_limit: registry result exceeds the bounded metadata budget")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || len(raw) > maxResponse {
		return errors.New("registry_response_limit: incomplete or oversized registry result")
	}
	if json.Unmarshal(raw, value) != nil {
		return errors.New("registry_response: invalid JSON")
	}
	return nil
}
