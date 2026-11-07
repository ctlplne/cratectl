// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

func TestGoChecksumFailureObserverRetainsBoundedOriginalBytesWithoutHeadersOrErrors(t *testing.T) {
	for _, scenario := range []string{"status", "malformed", "encoding", "range", "trailer", "overflow", "no-store", "no-store-opt-in", "partial", "no-store-partial", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := goChecksumPublic(t)
			body := []byte("owned original invalid checksum observation")
			if scenario == "overflow" {
				body = bytes.Repeat([]byte("x"), 64<<10+4)
			}
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Do-Not-Retain", "private-synthetic-header")
				if scenario == "no-store" || scenario == "no-store-opt-in" || scenario == "no-store-partial" {
					w.Header().Set("Cache-Control", "no-store")
				}
				switch scenario {
				case "status":
					w.WriteHeader(503)
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
				case "range":
					w.Header().Set("Content-Range", "bytes 0-2/100")
				case "trailer":
					w.Header().Set("Trailer", "X-Checksum-Private")
				case "partial", "no-store-partial":
					w.Header().Set("Content-Length", strconv.Itoa(len(body)+10))
				case "duplicate":
					w.Header().Add("ETag", "private-synthetic-header")
					w.Header().Add("ETag", "second-private-header")
				}
				w.Write(body)
				if scenario == "trailer" {
					w.Header().Set("X-Checksum-Private", "private-synthetic-header")
				}
			}))
			s, i, repo := goChecksumServer(t, origin.URL, fixture)
			repo.Settings.Cache.AllowNoStore = scenario == "no-store-opt-in"
			got, err := s.fetchGoModuleChecksumProof(context.Background(), i, repo, gomodule.Coordinate{Module: fixture.Module, Version: fixture.Version}, fixture.ZIPHash, fixture.ModHash, fixture.Initial)
			var observed *goChecksumCollectionError
			if err == nil || !errors.As(err, &observed) || got.Object.Digest != "" || len(observed.failure.Report.Attempts) != 1 {
				t.Fatal("failed collection exposed staged success or lost its original attempt", err)
			}
			report := observed.failure.Report
			attempt := report.Attempts[0]
			if report.VerifierKey != fixture.Key || !bytes.Equal(report.Checkpoint, fixture.Initial) || len(attempt.Body) > 64<<10+1 {
				t.Fatal("observation lost separately supplied trust or exceeded body bound")
			}
			if scenario == "no-store" || scenario == "no-store-partial" {
				if !attempt.Omitted || attempt.Code != "cache_policy" || len(attempt.Body) != 0 || attempt.OmittedPrefixBytes != len(body) || attempt.OmittedPrefixSHA256 != crypt.Digest(body) {
					t.Fatal("source storage policy was overridden by failure retention")
				}
			} else if scenario == "overflow" {
				if len(attempt.Body) != 64<<10+1 || !bytes.Equal(attempt.Body, body[:64<<10+1]) || attempt.Code != "overflow" && attempt.Code != "length" {
					t.Fatal("oversized failure did not retain only its declared bounded prefix")
				}
			} else if !bytes.Equal(attempt.Body, body) || attempt.Omitted {
				t.Fatal("failed response was rewritten or its original bytes were lost", attempt.Code)
			}
			encoded, encodeErr := json.Marshal(report)
			if encodeErr != nil || bytes.Contains(encoded, []byte("private-synthetic-header")) || strings.Contains(err.Error(), string(body)) || len(encoded) > store.MaxGoChecksumFailureEvidence {
				t.Fatal("observation exposed headers/error text or exceeded encoded bounds", encodeErr)
			}
		})
	}
}

func TestGoChecksumFailureObserverCancelsAndJoinsActiveBodyReaders(t *testing.T) {
	fixture := goChecksumPublic(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, stopped := make(chan struct{}), make(chan struct{})
	origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1024")
		w.Write([]byte("owned partial response"))
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	s, i, repo := goChecksumServer(t, origin.URL, fixture)
	finished := make(chan error, 1)
	go func() {
		_, err := s.fetchGoModuleChecksumProof(ctx, i, repo, gomodule.Coordinate{Module: fixture.Module, Version: fixture.Version}, fixture.ZIPHash, fixture.ModHash, fixture.Initial)
		finished <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("owned partial response never started")
	}
	cancel()
	var err error
	select {
	case err = <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled observation failed to join its body reader")
	}
	var observed *goChecksumCollectionError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &observed) || len(observed.failure.Report.Attempts) != 1 {
		t.Fatal("cancellation lost bounded original observations", err)
	}
	// Marshal immediately after return under -race: no callback may still mutate
	// the transferred observations after their reader lifetime has been joined.
	if _, err := json.Marshal(observed.failure.Report); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled observer left its owned HTTP handler active")
	}
}

func TestGoChecksumBlockedAuthorityReportsOperatorActionWithoutPrivateCoordinates(t *testing.T) {
	for _, err := range []error{store.ErrGoChecksumAuthorityBlocked, fmt.Errorf("private-synthetic-header: %w", store.ErrGoChecksumAuthorityBlocked)} {
		w := httptest.NewRecorder()
		respondErr(w, err)
		if w.Code != 409 || !strings.Contains(w.Body.String(), "go_checksum_authority_blocked") || !strings.Contains(w.Body.String(), "separately trusted authority key") || strings.Contains(w.Body.String(), "private-synthetic-header") {
			t.Fatal("fork block became retryable/not-found or exposed private error text", w.Code, w.Body.String())
		}
	}
}

func TestGoChecksumUnverifiedCredentialReflectionsAreOmittedWithoutASecretHash(t *testing.T) {
	for _, authentication := range []string{"bearer", "basic"} {
		t.Run(authentication, func(t *testing.T) {
			fixture := goChecksumPublic(t)
			const secret = "owned-synthetic-credential-reflection"
			value := secret
			if authentication == "basic" {
				value = "owned:" + secret
			}
			origin := goOriginStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(503)
				w.Write([]byte("owned rejected request: " + r.Header.Get("Authorization")))
			}))
			s, i, repo := goChecksumServer(t, origin.URL, fixture)
			repo.Settings.GoChecksumAuthority.Endpoint.Authentication = authentication
			repo.Settings.GoChecksumAuthority.Endpoint.CredentialRef = "observed-source"
			s.UpstreamCredentials = map[string]UpstreamCredential{i.Tenant + "/observed-source": {Value: value, AllowedURL: origin.URL + "/checksum/", Authentication: authentication}}
			_, err := s.fetchGoModuleChecksumProof(context.Background(), i, repo, gomodule.Coordinate{Module: fixture.Module, Version: fixture.Version}, fixture.ZIPHash, fixture.ModHash, fixture.Initial)
			var observation *goChecksumCollectionError
			if !errors.As(err, &observation) || len(observation.failure.Report.Attempts) != 1 {
				t.Fatal("credential reflection fixture lost its bounded failure", err)
			}
			attempt := observation.failure.Report.Attempts[0]
			if !attempt.Omitted || attempt.Code != "credential" || attempt.OmittedPrefixSHA256 != "" || len(attempt.Body) != 0 || attempt.OmittedPrefixBytes == 0 {
				t.Fatal("unverified reflected credential was retained or reduced to a secret hash")
			}
			encoded, err := json.Marshal(observation.failure.Report)
			if err != nil || bytes.Contains(encoded, []byte(secret)) || bytes.Contains(encoded, []byte(value)) {
				t.Fatal("credential value leaked into control evidence", err)
			}
		})
	}
}
