// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

func cliChecksumRecord(t *testing.T) (store.GoChecksumFailureRecord, string) {
	t.Helper()
	raw, err := os.ReadFile("../../internal/store/testdata/go-checksum-timeline-public.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Module    string                `json:"module"`
		Key       string                `json:"verifier_key"`
		One       []byte                `json:"first_checkpoint"`
		ZIPHashes map[string]string     `json:"zip_h1"`
		ModHash   string                `json:"mod_h1"`
		Fork      crypt.GoSumDBSnapshot `json:"fork"`
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	key, err := crypt.ParseGoSumDBCheckpoint(f.Key, f.One)
	if err != nil {
		t.Fatal(err)
	}
	r := store.GoChecksumFailureRecord{Profile: store.GoChecksumFailureEvidenceProfile, Tenant: "owned-team", Repository: "owned", RootPath: (gomodule.Coordinate{Module: f.Module, Version: "v1.0.0"}).Prefix() + ".zip", Generation: 2, KeyDigest: key.KeyDigest, ExpectedCheckpointRevision: 2, CurrentCheckpointRevision: 2, CurrentCheckpoint: f.One, Classification: "fork", Report: store.GoChecksumFailureReport{Profile: store.GoChecksumFailureProfile, Module: f.Module, Version: "v1.0.0", ZIPHash: f.ZIPHashes["v1.0.0"], ModHash: f.ModHash, VerifierKey: f.Key, Checkpoint: f.One}}
	paths := []string{}
	for p := range f.Fork.Responses {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		r.Report.Attempts = append(r.Report.Attempts, store.GoChecksumFailureAttempt{Path: p, Status: 200, Code: "ok", Body: f.Fork.Responses[p]})
	}
	return r, f.Key
}

func TestOfflineChecksumCommandRequiresSeparateTrustAndExactPrivateBytes(t *testing.T) {
	for _, scenario := range []string{"fork", "unverified", "wrong-key", "wrong-digest", "missing-digest", "missing-key", "extra-argument", "unknown-field", "duplicate-field", "trailing-newline", "overflow", "symlink", "public-evidence", "broken-output"} {
		t.Run(scenario, func(t *testing.T) {
			r, key := cliChecksumRecord(t)
			if scenario == "unverified" {
				r.Classification = "unverified"
				r.Report.Attempts = []store.GoChecksumFailureAttempt{{Path: "/lookup/owned", Status: 503, Code: "status", Body: []byte("private upstream original")}}
			}
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "wrong-key":
				key += "wrong"
			case "unknown-field":
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			case "duplicate-field":
				raw = append([]byte(`{"classification":"fork",`), raw[1:]...)
			case "trailing-newline":
				raw = append(raw, '\n')
			case "overflow":
				raw = bytes.Repeat([]byte("x"), store.MaxGoChecksumFailureEvidence+1)
			}
			dir := t.TempDir()
			evidence := filepath.Join(dir, "evidence.json")
			keyPath := filepath.Join(dir, "verifier.pub")
			if err = os.WriteFile(evidence, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(keyPath, []byte(key+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if scenario == "public-evidence" {
				if err = os.Chmod(evidence, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "symlink" {
				target := evidence
				evidence = filepath.Join(dir, "link.json")
				if err = os.Symlink(target, evidence); err != nil {
					t.Fatal(err)
				}
			}
			digest := crypt.Digest(raw)
			if scenario == "wrong-digest" {
				digest = strings.Repeat("0", 64)
			}
			args := []string{"--evidence-file", evidence, "--key-file", keyPath, "--expected-sha256", digest}
			if scenario == "missing-digest" {
				args = args[:4]
			}
			if scenario == "missing-key" {
				args = []string{"--evidence-file", evidence, "--expected-sha256", digest}
			}
			if scenario == "extra-argument" {
				args = append(args, "unused")
			}
			var output bytes.Buffer
			var writer io.Writer = &output
			if scenario == "broken-output" {
				writer = checksumBrokenWriter{}
			}
			err = runGoChecksumVerify(args, writer)
			if scenario == "fork" || scenario == "unverified" {
				if (err == nil) != (scenario == "fork") {
					t.Fatal("unverified observation became a successful fork verification", err)
				}
				var result map[string]any
				if json.Unmarshal(output.Bytes(), &result) != nil || result["classification"] != r.Classification || result["evidence_sha256"] != digest || result["package_admission"] != false || result["supplied_digest_matched"] != true {
					t.Fatal("missing verification outcome", output.String())
				}
				if bytes.Contains(output.Bytes(), []byte(r.Report.Module)) || bytes.Contains(output.Bytes(), []byte(r.Repository)) || bytes.Contains(output.Bytes(), []byte(key)) || bytes.Contains(output.Bytes(), []byte("private upstream original")) {
					t.Fatal("command printed private observation/attribution or configured key")
				}
			} else if err == nil || output.Len() != 0 {
				t.Fatal("invalid trust/bytes acknowledged or partial record printed", err, output.Len())
			}
		})
	}
}

type checksumBrokenWriter struct{}

func (checksumBrokenWriter) Write([]byte) (int, error) { return 0, errors.New("owned output failure") }

func TestCLIRawResponsePreservesExactEvidenceBytes(t *testing.T) {
	body := `{"original":"exact bytes"}`
	if err, n := runCLIResponseFixture(t, body, "--raw-response"); err != nil || n != int64(len(body)) {
		t.Fatal("raw evidence download changed byte length", err, n)
	}
}
