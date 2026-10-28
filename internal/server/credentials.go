// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
	"errors"
	"net/url"
	"strings"
)

// UpstreamCredential is operator-owned private configuration, never API data.
// Keys are tenant/ref. Both the destination and authentication type are bound.
type UpstreamCredential struct {
	Value          string `json:"value"`
	AllowedURL     string `json:"allowed_url"`
	Authentication string `json:"authentication,omitempty"`
}

func (s *Server) credential(tenant string, config upstream.Config) (string, error) {
	if config.CredentialRef == "" {
		return "", nil
	}
	binding, ok := s.UpstreamCredentials[tenant+"/"+config.CredentialRef]
	if !ok {
		return "", errors.New("tenant credential reference is not configured")
	}
	requested, e := url.Parse(config.URL)
	if e != nil {
		return "", upstream.ErrDestination
	}
	allowed, e := url.Parse(binding.AllowedURL)
	if e != nil {
		return "", upstream.ErrDestination
	}
	prefix := strings.TrimRight(allowed.Path, "/") + "/"
	candidate := strings.TrimRight(requested.Path, "/") + "/"
	if requested.Scheme != allowed.Scheme || requested.Host != allowed.Host || !strings.HasPrefix(candidate, prefix) {
		return "", upstream.ErrDestination
	}
	scheme := config.Authentication
	if scheme == "" {
		scheme = "bearer"
	}
	expected := binding.Authentication
	if expected == "" {
		expected = "bearer"
	}
	if scheme != expected {
		return "", upstream.ErrDestination
	}
	return binding.Value, nil
}
func (s *Server) ValidateCredentials() error {
	for key, binding := range s.UpstreamCredentials {
		parts := strings.Split(key, "/")
		if len(parts) != 2 || !store.Name.MatchString(parts[0]) || !store.Name.MatchString(parts[1]) || binding.Value == "" || len(binding.Value) > 4096 || strings.ContainsAny(binding.Value, "\r\n\x00") {
			return errors.New("invalid private upstream credential entry")
		}
		endpoint, e := upstream.New(upstream.Config{URL: binding.AllowedURL, Networks: []string{"0.0.0.0/0", "::/0"}, Authentication: binding.Authentication}, binding.Value)
		if e != nil {
			return errors.New("invalid private upstream credential authority")
		}
		endpoint.Close()
	}
	return nil
}

func (s *Server) ConfigureConcurrency(transfers, fills, tenantFills int) error {
	if transfers < 2 || fills <= 0 || fills >= transfers || tenantFills <= 0 {
		return errors.New("positive concurrency budgets must reserve at least one non-fill request slot")
	}
	s.slots = make(chan struct{}, transfers)
	s.fillSlots = make(chan struct{}, fills)
	s.TenantProxyLimit = tenantFills
	return nil
}

func (s *Server) ConfigureOCIDelivery(redirects int, limits upstream.RegistryDeliveryLimits) error {
	if redirects < 0 || redirects > 64 || limits.Validate() != nil {
		return errors.New("OCI delivery requires 0–64 redirects, positive bounded URL/query budgets, query bytes within URL bytes, and URL bytes within the 32 KiB response-header ceiling")
	}
	s.OCIDeliveryRedirects, s.OCIDeliveryLimits = redirects, limits
	return nil
}
