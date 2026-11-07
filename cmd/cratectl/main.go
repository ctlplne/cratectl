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
	"regexp"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
)

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "go-export-set-offline" {
		return runGoExportSetOffline(os.Args[2:], os.Stdout)
	}
	if len(os.Args) > 1 && os.Args[1] == "go-export-set-collect" {
		return runGoExportSetCollect(os.Args[2:], os.Stdout)
	}
	if len(os.Args) > 1 && os.Args[1] == "go-export-set-verify" {
		return runGoExportSetVerify(os.Args[2:], os.Stdout)
	}
	if len(os.Args) > 1 && os.Args[1] == "go-export-index-verify" {
		return runGoExportIndexVerify(os.Args[2:], os.Stdout)
	}
	if len(os.Args) > 1 && os.Args[1] == "go-export-import" {
		return runGoExportImport(os.Args[2:], os.Stdout)
	}
	if len(os.Args) > 1 && os.Args[1] == "go-export-collect" {
		return runGoExportCollect(os.Args[2:], os.Stdout)
	}
	if len(os.Args) > 1 && os.Args[1] == "go-module-offline" {
		return runGoModuleOffline(os.Args[2:], os.Stdout)
	}
	if len(os.Args) > 1 && os.Args[1] == "journal-checkpoint" {
		return runJournalCheckpoint(os.Args[2:], os.Stdout)
	}
	if len(os.Args) > 1 && os.Args[1] == "journal-export" {
		return runJournalExport(os.Args[2:], os.Stdout)
	}
	if len(os.Args) > 1 && os.Args[1] == "journal-verify" {
		return runJournalVerify(os.Args[2:], os.Stdout)
	}
	if len(os.Args) > 1 && os.Args[1] == "go-checksum-verify" {
		return runGoChecksumVerify(os.Args[2:], os.Stdout)
	}
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
	moduleTime := f.String("go-module-time", "", "stable RFC3339 publication instant for a complete Go module ZIP")
	file := f.String("body-file", "", "JSON request file")
	upload := f.String("upload-file", "", "stream exact publication or repair bytes from this regular file")
	timeout := f.Duration("timeout", 30*time.Second, "request timeout, 1s–24h; increase explicitly for large repair sources")
	responseLimit := f.Int64("response-limit", 4<<20, "maximum management response bytes, 1–1073741824; increase explicitly for complete large previews")
	rawResponse := f.Bool("raw-response", false, "write exact response bytes without an added newline; use for hashed evidence downloads")
	key := f.String("idempotency-key", "", "durable mutation key")
	if e := f.Parse(os.Args[1:]); e != nil {
		return e
	}
	if *file != "" && *upload != "" || *timeout < time.Second || *timeout > 24*time.Hour {
		return errors.New("choose body-file or upload-file and a timeout from 1s through 24h")
	}
	if *responseLimit < 1 || *responseLimit > 1<<30 {
		return errors.New("response-limit must be 1–1073741824 bytes")
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
	if e := validateClientPath(*p, *method, *upload, *moduleTime); e != nil {
		return e
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
	var reader io.Reader = bytes.NewReader(body)
	length := int64(len(body))
	if *upload != "" {
		source, e := os.Open(*upload)
		if e != nil {
			return errors.New("cannot open repair source file")
		}
		defer source.Close()
		info, e := source.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() >= 1<<62 {
			return errors.New("repair source must be a regular file with a bounded declared size")
		}
		reader = source
		length = info.Size()
	}
	req, e := http.NewRequest(*method, strings.TrimRight(*base, "/")+*p, reader)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	if *upload != "" {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.ContentLength = length
	}
	if *moduleTime != "" {
		req.Header.Set("X-Cratectl-Module-Time", *moduleTime)
	}
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
	client := &http.Client{Transport: transport, Timeout: *timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return errors.New("request failed; check the URL and configured TLS trust")
	}
	defer resp.Body.Close()
	if resp.ContentLength > *responseLimit {
		return managementResponseLimit(*responseLimit)
	}
	if e = copyManagementResponse(os.Stdout, resp.Body, *responseLimit); e != nil {
		return e
	}
	if !*rawResponse {
		fmt.Println()
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("management request returned HTTP %d", resp.StatusCode)
	}
	return nil
}

var repositoryName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func validateClientPath(p, method, upload, moduleTime string) error {
	if moduleTime == "" {
		if strings.HasPrefix(p, "/api/v1/") {
			return nil
		}
		return errors.New("management path must start /api/v1/; Go publication also requires --go-module-time")
	}
	invalid := errors.New("Go publication requires PUT, upload-file, a canonical /go/REPOSITORY/MODULE/@v/VERSION.zip path and a matching RFC3339 instant")
	relative, ok := strings.CutPrefix(p, "/go/")
	repository, coordinate, found := strings.Cut(relative, "/")
	if !ok || !found || !repositoryName.MatchString(repository) || method != "PUT" || upload == "" {
		return invalid
	}
	request, e := gomodule.ParseRequest(coordinate)
	if e != nil || request.Operation != "zip" {
		return invalid
	}
	if _, e := gomodule.VersionInfo(request.Coordinate, moduleTime); e != nil {
		return invalid
	}
	return nil
}

func managementResponseLimit(limit int64) error {
	return fmt.Errorf("management response exceeds %d bytes and is incomplete; retry the identical request/key with a larger --response-limit or use a smaller read page", limit)
}
func copyManagementResponse(out io.Writer, body io.Reader, limit int64) error {
	n, e := io.Copy(out, io.LimitReader(body, limit))
	if e != nil {
		return e
	}
	if n < limit {
		return nil
	}
	var sentinel [1]byte
	_, e = io.ReadFull(body, sentinel[:])
	if e == io.EOF {
		return nil
	}
	if e != nil {
		return e
	}
	return managementResponseLimit(limit)
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
