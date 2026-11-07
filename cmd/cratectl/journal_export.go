// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
)

// Collection uses the same explicitly supplied anchors as offline verification.
// No checkpoint fetched from this server is silently promoted into trust.
func runJournalExport(args []string, out io.Writer) error {
	f := flag.NewFlagSet("journal-export", flag.ContinueOnError)
	checkpointFiles := journalCheckpointFlags(f)
	configuration := f.String("config", "", "owner-private cratectl client JSON")
	output := f.String("output", "", "new owner-private JSONL file; existing files are never replaced")
	tenant := f.String("tenant", "", "tenant from the independently authenticated checkpoint")
	after := f.String("after", "0", "exact start sequence, zero for genesis")
	afterHash := f.String("after-hash", "", "exact start hash, empty at genesis")
	through := f.String("through", "", "exact terminal sequence from a separate trusted record")
	throughHash := f.String("through-hash", "", "separately authenticated terminal SHA-256")
	limit := f.Int("limit", 100, "events per request, 1–1000, also subject to response-byte bounds")
	budget := f.Int64("max-bytes", 1<<30, "total JSONL byte budget, 1–68719476736")
	timeout := f.Duration("timeout", 5*time.Minute, "total collection and verification timeout, at most 1h")
	if err := f.Parse(args); err != nil {
		return err
	}
	a, ae := strconv.ParseInt(*after, 10, 64)
	h, he := strconv.ParseInt(*through, 10, 64)
	start := crypt.JournalAnchor{Tenant: *tenant, Sequence: a, Hash: *afterHash}
	head := crypt.JournalAnchor{Tenant: *tenant, Sequence: h, Hash: *throughHash}
	if f.NArg() != 0 || *configuration == "" || *output == "" || ae != nil || he != nil || strconv.FormatInt(a, 10) != *after || strconv.FormatInt(h, 10) != *through || !start.Valid() || !head.Valid() || a > h || *limit < 1 || *limit > crypt.MaxJournalPageEvents || *budget < 1 || *budget > crypt.MaxJournalInputBytes || *timeout <= 0 || *timeout > time.Hour {
		return errors.New("supply config, new output, tenant and exact separately trusted after/through bindings, limit 1–1000, max-bytes 1–64 GiB and timeout within 1h")
	}
	signature, err := checkpointFiles.verify(head)
	if err != nil {
		return err
	}
	var c configfile.Client
	if err := configfile.Read(*configuration, &c); err != nil {
		return err
	}
	u, err := url.Parse(c.URL)
	if err != nil || c.Version != 1 || c.TokenFile == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" || u.Opaque != "" || u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("client config requires version 1, token_file and an HTTPS authority without credentials")
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return errors.New("HTTP is restricted to a literal loopback address")
		}
	}
	token, err := configfile.ReadBytes(c.TokenFile, 257, true)
	if err != nil {
		return err
	}
	defer clear(token)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if c.CAFile != "" {
		pem, err := configfile.ReadBytes(c.CAFile, 1<<20, false)
		if err != nil {
			return err
		}
		transport.TLSClientConfig, err = crypt.TLSWithCA(pem)
		if err != nil {
			return err
		}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	file, err := os.OpenFile(*output, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create new private export; choose a path that does not already exist")
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	receipt, err := collectJournal(ctx, client, strings.TrimRight(c.URL, "/"), strings.TrimSpace(string(token)), file, start, head, *limit, *budget)
	if err != nil {
		return errors.New("journal collection failed; output is incomplete and has no success receipt. Preserve it, inspect current access, supplied checkpoints and limits, then retry into a new file with the same trusted bindings")
	}
	return writeJournalReceipt(out, receipt, signature)
}

func collectJournal(ctx context.Context, client *http.Client, base, token string, file *os.File, start, head crypt.JournalAnchor, limit int, budget int64) (crypt.JournalVerification, error) {
	current := start
	var size int64
	for pages := 0; ; pages++ {
		if pages >= crypt.MaxJournalFrames {
			return crypt.JournalVerification{}, crypt.ErrJournalLimit
		}
		q := url.Values{"after": {strconv.FormatInt(current.Sequence, 10)}, "after_hash": {current.Hash}, "through": {strconv.FormatInt(head.Sequence, 10)}, "through_hash": {head.Hash}, "limit": {strconv.Itoa(limit)}}
		req, err := http.NewRequestWithContext(ctx, "GET", base+"/api/v1/audit/export?"+q.Encode(), nil)
		if err != nil {
			return crypt.JournalVerification{}, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		response, err := client.Do(req)
		if err != nil {
			return crypt.JournalVerification{}, err
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, crypt.MaxJournalPageBytes+1))
		response.Body.Close()
		if readErr != nil || response.StatusCode != 200 || len(raw) > crypt.MaxJournalPageBytes || !bytes.HasSuffix(raw, []byte{'\n'}) {
			return crypt.JournalVerification{}, crypt.ErrJournalEvidence
		}
		if int64(len(raw)) > budget-size {
			return crypt.JournalVerification{}, crypt.ErrJournalLimit
		}
		page, err := crypt.DecodeJournalPage(raw[:len(raw)-1])
		if err != nil {
			return crypt.JournalVerification{}, err
		}
		current, err = crypt.VerifyJournalPage(ctx, page, current, head)
		if err != nil {
			return crypt.JournalVerification{}, err
		}
		if n, err := file.Write(raw); err != nil || n != len(raw) {
			return crypt.JournalVerification{}, errors.New("cannot retain complete journal page")
		}
		size += int64(len(raw))
		if !page.More {
			break
		}
	}
	if err := file.Sync(); err != nil {
		return crypt.JournalVerification{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return crypt.JournalVerification{}, err
	}
	// Verify the complete persisted bytes, including EOF, before any receipt.
	return crypt.VerifyJournalExport(ctx, file, start, head, budget)
}
