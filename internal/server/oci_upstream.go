// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"ctlplne.dev/cratectl/internal/store"
	"ctlplne.dev/cratectl/internal/upstream"
)

type ociRegistryClient struct {
	origin, realm          *upstream.Endpoint
	service, scope, bearer string
}

func parseOCIChallenge(raw string) (map[string]string, error) {
	if len(raw) > 32768 || len(raw) < 7 || !strings.EqualFold(raw[:7], "Bearer ") {
		return nil, upstream.ErrDestination
	}
	raw = strings.TrimSpace(raw[7:])
	values := map[string]string{}
	for raw != "" {
		key, tail, ok := strings.Cut(raw, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || key == "" || len(values) > 8 || values[key] != "" {
			return nil, upstream.ErrDestination
		}
		for _, c := range key {
			if c < 'a' || c > 'z' {
				if c != '_' {
					return nil, upstream.ErrDestination
				}
			}
		}
		tail = strings.TrimSpace(tail)
		var value strings.Builder
		if strings.HasPrefix(tail, `"`) {
			tail = tail[1:]
			closed := false
			for len(tail) > 0 {
				c := tail[0]
				tail = tail[1:]
				if c == '"' {
					closed = true
					break
				}
				if c == '\\' {
					if len(tail) == 0 {
						return nil, upstream.ErrDestination
					}
					c = tail[0]
					tail = tail[1:]
				}
				if c < 32 || c == 127 {
					return nil, upstream.ErrDestination
				}
				value.WriteByte(c)
			}
			if !closed {
				return nil, upstream.ErrDestination
			}
		} else {
			part, rest, found := strings.Cut(tail, ",")
			value.WriteString(strings.TrimSpace(part))
			tail = ""
			if found {
				tail = "," + rest
			}
		}
		if value.Len() == 0 {
			return nil, upstream.ErrDestination
		}
		values[key] = value.String()
		tail = strings.TrimSpace(tail)
		if tail == "" {
			break
		}
		if tail[0] != ',' {
			return nil, upstream.ErrDestination
		}
		raw = strings.TrimSpace(tail[1:])
		if raw == "" {
			return nil, upstream.ErrDestination
		}
	}
	if values["realm"] == "" || values["service"] == "" {
		return nil, upstream.ErrDestination
	}
	return values, nil
}

func upstreamOCIImage(repo store.Repository, image string) string {
	u, _ := url.Parse(repo.Settings.Upstream.URL)
	if n := strings.LastIndex(u.Path, "/v2/"); n >= 0 {
		prefix := strings.Trim(u.Path[n+4:], "/")
		if prefix != "" {
			return prefix + "/" + image
		}
	}
	return image
}
func (s *Server) newOCIRegistryClient(i store.Identity, repo store.Repository, image string) (*ociRegistryClient, error) {
	if repo.Settings.Upstream == nil {
		return nil, store.ErrConflict
	}
	credential, e := s.credential(i.Tenant, *repo.Settings.Upstream)
	if e != nil {
		return nil, upstream.ErrDestination
	}
	origin, e := upstream.New(*repo.Settings.Upstream, credential, s.PrivateUpstreamNetworks...)
	if e != nil {
		return nil, e
	}
	client := &ociRegistryClient{origin: origin, scope: "repository:" + upstreamOCIImage(repo, image) + ":pull", service: repo.Settings.OCITokenService}
	if config := repo.Settings.OCITokenEndpoint; config != nil {
		credential, e = s.credential(i.Tenant, *config)
		if e != nil {
			origin.Close()
			return nil, upstream.ErrDestination
		}
		client.realm, e = upstream.New(*config, credential, s.PrivateUpstreamNetworks...)
		if e != nil {
			origin.Close()
			return nil, e
		}
	}
	return client, nil
}
func (c *ociRegistryClient) close() {
	c.origin.Close()
	if c.realm != nil {
		c.realm.Close()
	}
	c.bearer = ""
}
func (c *ociRegistryClient) get(ctx context.Context, p string, q url.Values, h http.Header) (*http.Response, error) {
	response, e := c.origin.GetRegistry(ctx, p, q, h, c.bearer)
	if e != nil || response.StatusCode != 401 || c.realm == nil {
		return response, e
	}
	defer response.Body.Close()
	var challenge map[string]string
	for _, raw := range response.Header.Values("WWW-Authenticate") {
		if len(raw) >= 7 && strings.EqualFold(raw[:7], "Bearer ") {
			if challenge != nil {
				return nil, upstream.ErrDestination
			}
			challenge, e = parseOCIChallenge(raw)
			if e != nil {
				return nil, e
			}
		}
	}
	if challenge == nil || !c.realm.RegistryRealm(challenge["realm"]) || challenge["service"] != c.service || (challenge["scope"] != "" && challenge["scope"] != c.scope) {
		return nil, upstream.ErrDestination
	}
	token, e := c.realm.GetRegistryToken(ctx, c.service, c.scope)
	if e != nil {
		return nil, e
	}
	defer token.Body.Close()
	if token.StatusCode != 200 {
		return nil, errors.New("OCI token endpoint rejected request")
	}
	data, e := io.ReadAll(io.LimitReader(token.Body, 65537))
	if e != nil || len(data) > 65536 {
		return nil, upstream.ErrDestination
	}
	var payload struct {
		Token   string `json:"token"`
		Access  string `json:"access_token"`
		Expires *int64 `json:"expires_in"`
	}
	if uniqueOCIJSON(data) != nil || json.Unmarshal(data, &payload) != nil || (payload.Token != "" && payload.Access != "" && payload.Token != payload.Access) || (payload.Expires != nil && (*payload.Expires <= 0 || *payload.Expires > 86400)) {
		return nil, upstream.ErrDestination
	}
	c.bearer = payload.Token
	if c.bearer == "" {
		c.bearer = payload.Access
	}
	if c.bearer == "" || len(c.bearer) > 16384 || strings.IndexFunc(c.bearer, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil, upstream.ErrDestination
	}
	return c.origin.GetRegistry(ctx, p, q, h, c.bearer)
}
