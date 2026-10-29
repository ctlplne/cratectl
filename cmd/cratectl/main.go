// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
)

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "npm-config" {
		return runNPMConfig(os.Args[2:])
	}
	f := flag.NewFlagSet("cratectl", flag.ContinueOnError)
	configuration := f.String("config", "", "private client JSON from cratectld init")
	caFile := f.String("ca-file", "", "PEM CA trust file; TLS verification remains enabled")
	base := f.String("url", "https://localhost:38443", "server URL")
	tokenFile := f.String("token-file", "", "private token file")
	method := f.String("method", "GET", "HTTP method")
	p := f.String("path", "/api/v1/repositories", "API path")
	file := f.String("body-file", "", "JSON request file")
	key := f.String("idempotency-key", "", "durable mutation key")
	if e := f.Parse(os.Args[1:]); e != nil {
		return e
	}
	if *configuration != "" {
		var c configfile.Client
		if e := configfile.Read(*configuration, &c); e != nil {
			return e
		}
		if c.Version != 1 || c.URL == "" || c.TokenFile == "" {
			return errors.New("invalid client configuration version or required fields")
		}
		set := map[string]bool{}
		f.Visit(func(v *flag.Flag) { set[v.Name] = true })
		if !set["url"] {
			*base = c.URL
		}
		if !set["token-file"] {
			*tokenFile = c.TokenFile
		}
		if !set["ca-file"] {
			*caFile = c.CAFile
		}
	}
	if !strings.HasPrefix(*p, "/api/v1/") {
		return errors.New("management path must start /api/v1/")
	}
	u, e := url.Parse(*base)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("server URL must be an HTTPS authority without credentials")
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return errors.New("HTTP is restricted to a literal loopback address")
		}
	}
	token, e := configfile.ReadBytes(*tokenFile, 257, true)
	if e != nil {
		return e
	}
	defer clear(token)
	var body []byte
	if *file != "" {
		body, e = configfile.ReadBytes(*file, 4<<20, false)
		if e != nil {
			return e
		}
	}
	req, e := http.NewRequest(*method, strings.TrimRight(*base, "/")+*p, bytes.NewReader(body))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", *key)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if *caFile != "" {
		data, e := configfile.ReadBytes(*caFile, 1<<20, false)
		if e != nil {
			return e
		}
		transport.TLSClientConfig, e = crypt.TLSWithCA(data)
		if e != nil {
			return e
		}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return errors.New("request failed; check the URL and configured TLS trust")
	}
	defer resp.Body.Close()
	_, e = io.Copy(os.Stdout, io.LimitReader(resp.Body, 4<<20))
	if e != nil {
		return e
	}
	fmt.Println()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("management request returned HTTP %d", resp.StatusCode)
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
