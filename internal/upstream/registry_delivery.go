// SPDX-License-Identifier: BUSL-1.1
package upstream

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

var ErrRegistryDelivery = errors.New("OCI delivery request failed")

type RegistryDeliveryLimits struct {
	URLBytes, QueryBytes, QueryPairs int
}

func DefaultRegistryDeliveryLimits() RegistryDeliveryLimits {
	return RegistryDeliveryLimits{URLBytes: 16384, QueryBytes: 8192, QueryPairs: 64}
}
func (l RegistryDeliveryLimits) Validate() error {
	if l.URLBytes <= 0 || l.URLBytes > 32<<10 || l.QueryBytes <= 0 || l.QueryBytes > l.URLBytes || l.QueryPairs <= 0 || l.QueryPairs > 4096 {
		return ErrDestination
	}
	return nil
}
func (e *Endpoint) ConfigureRegistryDelivery(l RegistryDeliveryLimits) error {
	if err := l.Validate(); err != nil {
		return err
	}
	e.deliveryLimits = l
	return nil
}

// RegistryDeliveryScope selects the most specific configured path authority
// before testing its query permission. A stricter source cannot fall through to
// a broader source's credentials when it rejects a signed query.
func (e *Endpoint) RegistryDeliveryScope(raw string) int {
	if len(raw) > e.deliveryLimits.URLBytes || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return 0
	}
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.User != nil || u.Opaque != "" || u.Scheme != e.base.Scheme || u.Host != e.base.Host {
		return 0
	}
	if u.Path != e.exactPath && (!strings.HasPrefix(u.Path, e.base.Path) || !SafePath(strings.TrimSuffix(strings.TrimPrefix(u.Path, e.base.Path), "/"))) {
		return 0
	}
	return len(e.base.Path)
}

// RegistryDeliveryPriority checks a complete ephemeral redirect URL. Query bytes
// are validated but never re-encoded: changing their order/escaping can break a
// source's signature. Ordinary durable package URLs still use AllowsURL.
func (e *Endpoint) RegistryDeliveryPriority(raw string) int {
	priority := e.RegistryDeliveryScope(raw)
	if priority == 0 {
		return 0
	}
	u, _ := url.Parse(raw)
	if u.RawQuery != "" || u.ForceQuery {
		if !e.allowSignedQuery || u.RawQuery == "" || len(u.RawQuery) > e.deliveryLimits.QueryBytes {
			return 0
		}
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil || len(values) == 0 || len(values) > e.deliveryLimits.QueryPairs {
			return 0
		}
		count := 0
		for key, list := range values {
			if key == "" || strings.IndexFunc(key, unicode.IsControl) >= 0 {
				return 0
			}
			count += len(list)
			for _, value := range list {
				if strings.IndexFunc(value, unicode.IsControl) >= 0 {
					return 0
				}
			}
		}
		if count > e.deliveryLimits.QueryPairs {
			return 0
		}
	}
	return priority
}

// Each redirect is a new request with this endpoint's credentials only. No
// automatic redirects, cookies or Referer can carry authority to another hop.
func (e *Endpoint) GetRegistryDelivery(ctx context.Context, raw string, validators http.Header, bearer ...string) (*http.Response, error) {
	if e.RegistryDeliveryPriority(raw) == 0 {
		return nil, ErrDestination
	}
	u, _ := url.Parse(raw)
	response, err := e.getRegistryOnce(ctx, u, validators, bearer...)
	return response, sanitizeRegistryError(ctx, err)
}

func sanitizeRegistryError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	// net/http parses Location before invoking CheckRedirect, even when that
	// callback refuses following. Malformed Location errors can contain secrets
	// too, including on an otherwise unsigned origin or realm request.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for _, kind := range []error{ErrDestination, ErrPath, ErrRedirect} {
		if errors.Is(err, kind) {
			return kind
		}
	}
	return ErrRegistryDelivery
}
func (e *Endpoint) getRegistryOnce(ctx context.Context, u *url.URL, validators http.Header, bearer ...string) (*http.Response, error) {
	client := *e.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return e.getUsing(ctx, u, validators, &client, bearer...)
}
