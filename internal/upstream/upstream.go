// SPDX-License-Identifier: BUSL-1.1
// Package upstream binds repository retrieval to operator-authorized destinations.
package upstream

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrDestination = errors.New("upstream destination is outside the configured network authority")
var ErrRedirect = errors.New("upstream redirect escaped the configured authority or path")
var ErrPath = errors.New("ambiguous upstream package path")

type Config struct {
	Authentication string   `json:"authentication,omitempty"`
	URL            string   `json:"url"`
	Networks       []string `json:"networks"`
	CredentialRef  string   `json:"credential_ref,omitempty"`
}
type Endpoint struct {
	base            *url.URL
	exactPath       string
	networks        []netip.Prefix
	privateNetworks []netip.Prefix
	client          *http.Client
	transport       *http.Transport
	credential      string
	authentication  string
	lookup          func(context.Context, string, string) ([]netip.Addr, error)
}

func New(c Config, credential string, privateNetworks ...string) (*Endpoint, error) {
	u, err := url.Parse(c.URL)
	if len(c.URL) > 2048 || err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") || u.RawPath != "" {
		return nil, ErrDestination
	}
	if u.Scheme == "http" {
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !ip.IsLoopback() {
			return nil, ErrDestination
		}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	exactPath := u.Path
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	if u.Path != "/" && !SafePath(strings.Trim(u.Path, "/")) {
		return nil, ErrDestination
	}
	if path.Clean(u.Path)+"/" != u.Path && u.Path != "/" {
		return nil, ErrDestination
	}
	e := &Endpoint{base: u, exactPath: exactPath, credential: credential, authentication: c.Authentication, lookup: net.DefaultResolver.LookupNetIP}
	if len(c.Networks) == 0 || len(c.Networks) > 64 {
		return nil, ErrDestination
	}
	for _, s := range c.Networks {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, ErrDestination
		}
		e.networks = append(e.networks, p)
	}
	for _, raw := range privateNetworks {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, ErrDestination
		}
		e.privateNetworks = append(e.privateNetworks, prefix)
	}

	if strings.ContainsAny(credential, "\r\n\x00") {
		return nil, ErrDestination
	}
	if c.Authentication == "basic" && credential != "" && !strings.Contains(credential, ":") {
		return nil, ErrDestination
	}
	if c.Authentication != "" && c.Authentication != "bearer" && c.Authentication != "basic" {
		return nil, ErrDestination
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.MaxConnsPerHost = 2
	transport.MaxIdleConns = 2
	transport.MaxIdleConnsPerHost = 2
	transport.MaxResponseHeaderBytes = 32 << 10
	transport.ResponseHeaderTimeout = 15 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, ErrDestination
		}
		if host != e.base.Hostname() {
			return nil, ErrDestination
		}
		addresses, err := e.lookup(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("upstream DNS resolution failed")
		}
		if len(addresses) == 0 || len(addresses) > 64 {
			return nil, ErrDestination
		}
		for _, a := range addresses {
			allowed := false
			a = a.Unmap()
			for _, p := range e.networks {
				if p.Contains(a) {
					allowed = true
					break
				}
			}
			if a.IsUnspecified() || a.IsMulticast() {
				return nil, ErrDestination
			}
			if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || !a.IsGlobalUnicast() {
				operatorAllowed := false
				for _, prefix := range e.privateNetworks {
					if prefix.Contains(a) {
						operatorAllowed = true
						break
					}
				}
				if !operatorAllowed {
					return nil, ErrDestination
				}
			}

			if !allowed {
				return nil, ErrDestination
			}
		}
		dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		var last error
		for _, a := range addresses {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
	e.transport = transport
	e.client = &http.Client{Transport: transport, Timeout: 120 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 || !e.permitted(r.URL) {
			return ErrRedirect
		}
		return nil
	}}
	return e, nil
}
func (e *Endpoint) Close() { e.transport.CloseIdleConnections() }
func SafePath(p string) bool {
	return p != "" && len(p) <= 2048 && utf8.ValidString(p) && path.Clean(p) == p && !strings.HasPrefix(p, "/") && p != "." && p != ".." && !strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "%\\?\x00\r\n#") && strings.IndexFunc(p, unicode.IsControl) < 0
}
func (e *Endpoint) Get(ctx context.Context, p string, validators http.Header) (*http.Response, error) {
	if !SafePath(p) {
		return nil, ErrPath
	}
	u := *e.base
	u.Path += p
	return e.get(ctx, &u, validators)
}

func (e *Endpoint) permitted(u *url.URL) bool {
	return u.Scheme == e.base.Scheme && u.Host == e.base.Host && u.User == nil && u.Opaque == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && strings.HasPrefix(u.Path, e.base.Path) && SafePath(strings.TrimSuffix(strings.TrimPrefix(u.Path, e.base.Path), "/"))
}

// AllowsURL checks a complete download URL before it can become a durable source
// binding. The decoded path must be canonical; double-encoded traversal fails.
func (e *Endpoint) AllowsURL(raw string) bool {
	u, err := url.Parse(raw)
	return len(raw) <= 2048 && err == nil && e.permitted(u)
}

func (e *Endpoint) GetURL(ctx context.Context, raw string, validators http.Header) (*http.Response, error) {
	if !e.AllowsURL(raw) {
		return nil, ErrDestination
	}
	u, _ := url.Parse(raw)
	return e.get(ctx, u, validators)
}

func (e *Endpoint) GetPackage(ctx context.Context, name string, validators http.Header) (*http.Response, error) {
	if !SafePath(name) {
		return nil, ErrPath
	}
	u := *e.base
	u.Path += name
	u.RawPath = e.base.EscapedPath() + url.PathEscape(name)
	return e.get(ctx, &u, validators)
}
func (e *Endpoint) GetIndex(ctx context.Context, name string, validators http.Header) (*http.Response, error) {
	if !SafePath(name) {
		return nil, ErrPath
	}
	u := *e.base
	u.Path += name + "/"
	return e.get(ctx, &u, validators)
}

func (e *Endpoint) get(ctx context.Context, u *url.URL, validators http.Header, override ...string) (*http.Response, error) {
	return e.getUsing(ctx, u, validators, e.client, override...)
}
func (e *Endpoint) getUsing(ctx context.Context, u *url.URL, validators http.Header, client *http.Client, override ...string) (*http.Response, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, ErrPath
	}
	// Validators are retained source metadata, never arbitrary downstream headers.
	for _, h := range []string{"If-None-Match", "If-Modified-Since", "Accept"} {
		if v := validators.Get(h); v != "" {
			r.Header.Set(h, v)
		}
	}
	if len(override) > 0 {
		if len(override[0]) > 16384 || strings.ContainsAny(override[0], "\r\n\x00") {
			return nil, ErrDestination
		}
		r.Header.Set("Authorization", "Bearer "+override[0])
	} else if e.credential != "" {
		if e.authentication == "basic" {
			user, password, ok := strings.Cut(e.credential, ":")
			if !ok {
				return nil, ErrDestination
			}
			r.SetBasicAuth(user, password)
		} else {
			r.Header.Set("Authorization", "Bearer "+e.credential)
		}
	}
	r.Header.Set("Accept-Encoding", "identity")
	return client.Do(r)
}
