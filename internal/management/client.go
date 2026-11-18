// SPDX-License-Identifier: BUSL-1.1
package management

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
)

// OpenClient opens a bounded, non-redirecting client from private local configuration.
func OpenClient(path string) (*http.Client, string, string, func(), error) {
	var c configfile.Client
	if err := configfile.Read(path, &c); err != nil {
		return nil, "", "", nil, err
	}
	u, err := url.Parse(c.URL)
	if err != nil || len(c.URL) > 2048 || c.Version != 1 || c.TokenFile == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.Trim(u.Path, "/") != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, "", "", nil, errors.New("client config requires a credential-free HTTPS authority and private token file")
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, "", "", nil, errors.New("HTTP is restricted to a literal loopback address")
		}
	}
	token, err := configfile.ReadBytes(c.TokenFile, 257, true)
	if err != nil {
		return nil, "", "", nil, err
	}
	value := strings.TrimSpace(string(token))
	clear(token)
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return nil, "", "", nil, errors.New("invalid private token")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.MaxResponseHeaderBytes = 32 << 10
	transport.ResponseHeaderTimeout = 15 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.MaxConnsPerHost = 1
	transport.MaxIdleConnsPerHost = 1
	if c.CAFile != "" {
		pem, err := configfile.ReadBytes(c.CAFile, 1<<20, false)
		if err != nil {
			return nil, "", "", nil, err
		}
		transport.TLSClientConfig, err = crypt.TLSWithCA(pem)
		if err != nil {
			return nil, "", "", nil, err
		}
	}
	client := &http.Client{Transport: transport, Timeout: time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, strings.TrimRight(c.URL, "/"), value, transport.CloseIdleConnections, nil
}
