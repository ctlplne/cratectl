// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/upstream"
)

func checksumPublicFixture(t *testing.T) (GoChecksumAuthority, GoModuleChecksumProof, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../server/testdata/go-checksum-public.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Module    string            `json:"module"`
		Version   string            `json:"version"`
		ZIPHash   string            `json:"zip_h1"`
		ModHash   string            `json:"mod_h1"`
		Key       string            `json:"verifier_key"`
		Initial   []byte            `json:"initial_checkpoint"`
		Advanced  []byte            `json:"advanced_checkpoint"`
		Responses map[string][]byte `json:"responses"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	a := GoChecksumAuthority{Endpoint: upstream.Config{URL: "http://127.0.0.1:38443/checksum/", Networks: []string{"127.0.0.1/32"}}, VerifierKey: f.Key, InitialCheckpoint: f.Initial}
	p := GoModuleChecksumProof{Profile: GoModuleChecksumProfile, Module: f.Module, Version: f.Version, ZIPHash: f.ZIPHash, ModHash: f.ModHash, Snapshot: crypt.GoSumDBSnapshot{VerifierKey: f.Key, Checkpoint: f.Initial, Responses: f.Responses}}
	return a, p, f.Advanced
}

func TestGoChecksumAuthorityRequiresExplicitTrustAndBoundedEndpoint(t *testing.T) {
	for _, scenario := range []string{"valid", "missing-url", "public-http", "networks", "credential-ref", "signed-query", "key", "unsigned-bootstrap", "wrong-format", "hosted", "public-proxy-still-gated"} {
		t.Run(scenario, func(t *testing.T) {
			a, _, _ := checksumPublicFixture(t)
			switch scenario {
			case "missing-url":
				a.Endpoint.URL = ""
			case "public-http":
				a.Endpoint.URL = "http://public.cratectl.invalid/checksum/"
			case "networks":
				a.Endpoint.Networks = nil
			case "credential-ref":
				a.Endpoint.CredentialRef = "invalid/ref"
			case "signed-query":
				a.Endpoint.AllowSignedQuery = true
			case "key":
				a.VerifierKey += "bad"
			case "unsigned-bootstrap":
				a.InitialCheckpoint = nil
			}
			if scenario == "wrong-format" || scenario == "hosted" || scenario == "public-proxy-still-gated" {
				r := Repository{Name: "source", Format: "go", Mode: "proxy", Settings: RepositorySettings{Upstream: &a.Endpoint, GoChecksumAuthority: &a}}
				if scenario == "wrong-format" {
					r.Format = "generic"
				}
				if scenario == "hosted" {
					r.Mode = "hosted"
					r.Settings.Upstream = nil
				}
				if err := ValidateRepository(&r); err == nil {
					t.Fatal("authority bypassed current public format/mode admission")
				}
				return
			}
			err := a.Validate()
			if scenario == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("invalid authority admitted")
			}
		})
	}
}

func TestGoChecksumProofBindsBothHashesCoordinateAndSeparateCurrentTrust(t *testing.T) {
	for _, scenario := range []string{"valid", "profile", "module", "version", "zip-hash", "mod-hash", "proof-key", "current-key", "current-checkpoint", "missing-proof", "forged-proof"} {
		t.Run(scenario, func(t *testing.T) {
			a, p, advanced := checksumPublicFixture(t)
			c := gomodule.Coordinate{Module: p.Module, Version: p.Version}
			zipHash, modHash, key, pinned := p.ZIPHash, p.ModHash, a.VerifierKey, a.InitialCheckpoint
			switch scenario {
			case "profile":
				p.Profile = "unknown"
			case "module":
				p.Module += "/other"
			case "version":
				p.Version = "v1.0.1"
			case "zip-hash":
				zipHash = modHash
			case "mod-hash":
				modHash = zipHash
			case "proof-key":
				p.Snapshot.VerifierKey += "bad"
			case "current-key":
				key += "bad"
			case "current-checkpoint":
				pinned = advanced
			case "missing-proof":
				p.Snapshot.Responses = nil
			case "forged-proof":
				for path, data := range p.Snapshot.Responses {
					data[0] ^= 1
					p.Snapshot.Responses[path] = data
				}
			}
			got, err := VerifyGoModuleChecksumProof(context.Background(), p, c, zipHash, modHash, key, pinned)
			if scenario == "valid" {
				if err != nil || !bytes.Equal(got.Checkpoint, advanced) {
					t.Fatal("original proof failed current binding", err)
				}
			} else if !errors.Is(err, crypt.ErrGoChecksumAuthority) || !reflect.DeepEqual(got, crypt.GoSumDBVerification{}) {
				t.Fatal("proof returned partial trust or bypassed independent bindings", err)
			}
		})
	}
}

func TestGoChecksumProposalCannotAdmitPublicationOrCachedBytesWithoutDurableFence(t *testing.T) {
	a, p, _ := checksumPublicFixture(t)
	c := gomodule.Coordinate{Module: p.Module, Version: p.Version}
	for _, required := range []bool{false, true} {
		r := Repository{Name: "source", Format: "go", Mode: "proxy", Settings: RepositorySettings{GoChecksumAuthority: &a, Cache: CacheSettings{RequireChecksum: required}}}
		if err := validateGoModuleRetrieval(r, Retrieval{}, RetrievalResult{}); !errors.Is(err, ErrGoModuleUnvalidated) {
			t.Fatal("unfenced configured checksum publication admitted", err)
		}
		if out, err := goModuleProxyArtifactInTx(context.Background(), nil, r, c.Prefix()+".zip", c, false, nil); !errors.Is(err, ErrGoModuleUnvalidated) || !reflect.DeepEqual(out, Artifact{}) {
			t.Fatal("unfenced configured checksum cache admitted", err)
		}
	}
}
