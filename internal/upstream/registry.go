// SPDX-License-Identifier: BUSL-1.1
package upstream

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Registry requests construct their own narrow query parameters. Neither client
// Authorization nor arbitrary URLs/queries enter this transport.
func (e *Endpoint) GetRegistry(ctx context.Context, p string, query url.Values, validators http.Header, bearer string) (*http.Response, error) {
	if !SafePath(p) {
		return nil, ErrPath
	}
	for key, values := range query {
		if len(values) != 1 {
			return nil, ErrPath
		}
		switch key {
		case "n":
			n, err := strconv.Atoi(values[0])
			if err != nil || n <= 0 || n > 10000 {
				return nil, ErrPath
			}
		case "last":
			if !SafePath(values[0]) || strings.Contains(values[0], "/") {
				return nil, ErrPath
			}
		case "artifactType":
			if len(values[0]) > 255 || strings.ContainsAny(values[0], "\r\n\x00") {
				return nil, ErrPath
			}
		default:
			return nil, ErrPath
		}
	}
	u := *e.base
	u.Path += p
	u.RawQuery = query.Encode()
	if bearer != "" {
		return e.get(ctx, &u, validators, bearer)
	}
	return e.get(ctx, &u, validators)
}

func (e *Endpoint) RegistryRealm(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(raw) <= 2048 && u.Scheme == e.base.Scheme && u.Host == e.base.Host && u.Path == e.exactPath && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.User == nil && u.Fragment == "" && u.Opaque == ""
}
func (e *Endpoint) GetRegistryToken(ctx context.Context, service, scope string) (*http.Response, error) {
	if service == "" || len(service) > 255 || strings.ContainsAny(service+scope, "\r\n\x00") || !strings.HasPrefix(scope, "repository:") || !strings.HasSuffix(scope, ":pull") {
		return nil, ErrPath
	}
	u := *e.base
	u.Path = e.exactPath
	u.RawQuery = url.Values{"service": {service}, "scope": {scope}, "client_id": {"cratectl"}}.Encode()
	client := *e.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRedirect }
	return e.getUsing(ctx, &u, nil, &client)
}
