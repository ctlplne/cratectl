// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/upstream"
)

type checksumTimeline struct {
	Module      string                `json:"module"`
	Payload     string                `json:"payload"`
	ModHash     string                `json:"mod_h1"`
	ZIPHashes   map[string]string     `json:"zip_h1"`
	Key         string                `json:"verifier_key"`
	Initial     []byte                `json:"initial_checkpoint"`
	One         []byte                `json:"first_checkpoint"`
	Two         []byte                `json:"second_checkpoint"`
	First       crypt.GoSumDBSnapshot `json:"first"`
	Second      crypt.GoSumDBSnapshot `json:"second"`
	OldAtSecond crypt.GoSumDBSnapshot `json:"old_at_second"`
	Fork        crypt.GoSumDBSnapshot `json:"fork"`
}

func checksumTimelineFixture(t testing.TB) checksumTimeline {
	t.Helper()
	raw, err := os.ReadFile("testdata/go-checksum-timeline-public.json")
	if err != nil {
		t.Fatal(err)
	}
	var f checksumTimeline
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f checksumTimeline) authority() GoChecksumAuthority {
	return GoChecksumAuthority{Endpoint: upstream.Config{URL: "http://127.0.0.1:38443/checksum/", Networks: []string{"127.0.0.1/32"}}, VerifierKey: f.Key, InitialCheckpoint: f.Initial, ProofPolicy: &GoChecksumProofPolicy{Mode: "retained"}}
}

func (f checksumTimeline) publication(t testing.TB, version string, snapshot crypt.GoSumDBSnapshot, expected int64) GoModuleChecksumPublication {
	t.Helper()
	p := GoModuleChecksumPublication{ZIPHash: f.ZIPHashes[version], ModHash: f.ModHash, ExpectedCheckpointRevision: expected}
	p.Proof = GoModuleChecksumProof{Profile: GoModuleChecksumProfile, Module: f.Module, Version: version, ZIPHash: p.ZIPHash, ModHash: p.ModHash, Snapshot: snapshot}
	raw, err := json.Marshal(p.Proof)
	if err != nil {
		t.Fatal(err)
	}
	p.Object = blob.Object{Digest: crypt.Digest(raw), Size: int64(len(raw))}
	return p
}

func TestGoChecksumOfflineRebasePreservesConcurrentHistoryAndDistinguishesFork(t *testing.T) {
	for _, scenario := range []string{"initial", "identical-winner", "extension", "older-lookup-current-head", "missing-consistency-tiles", "signed-fork", "wrong-original-pin", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			f := checksumTimelineFixture(t)
			p := f.publication(t, "v1.0.0", f.First, 0)
			expected, current, want := f.Initial, f.Initial, f.One
			var wantErr error
			ctx := context.Background()
			switch scenario {
			case "identical-winner":
				current = f.One
			case "extension":
				p = f.publication(t, "v1.1.0", f.Second, 2)
				expected = f.One
				current = f.One
				want = f.Two
			case "older-lookup-current-head":
				p = f.publication(t, "v1.0.0", f.OldAtSecond, 2)
				expected = f.One
				current = f.Two
				want = f.Two
			case "missing-consistency-tiles":
				current = f.Two
				wantErr = ErrGoChecksumCheckpointChanged
			case "signed-fork":
				p = f.publication(t, "v1.0.0", f.Fork, 0)
				p.ZIPHash = f.ModHash
				p.Proof.ZIPHash = f.ModHash
				current = f.One
				wantErr = crypt.ErrGoChecksumFork
			case "wrong-original-pin":
				expected = f.One
				current = f.One
				wantErr = crypt.ErrGoChecksumAuthority
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				wantErr = context.Canceled
			}
			before, _ := json.Marshal(p)
			got, err := rebaseGoChecksumProof(ctx, p, gomodule.Coordinate{Module: p.Proof.Module, Version: p.Proof.Version}, f.Key, expected, current)
			if wantErr != nil {
				if !errors.Is(err, wantErr) || !reflect.DeepEqual(got, crypt.GoSumDBVerification{}) {
					t.Fatal("failed proof returned trust or lost failure classification", err)
				}
			} else if err != nil || !bytes.Equal(got.Checkpoint, want) {
				t.Fatal("offline current-timeline admission failed", err)
			}
			after, _ := json.Marshal(p)
			if !bytes.Equal(before, after) {
				t.Fatal("rebase changed original staged proof")
			}
		})
	}
}

func TestGoChecksumPublicationBindsInspectedHashesAndStagedOriginalBytes(t *testing.T) {
	for _, scenario := range []string{"valid", "missing", "required-no-authority", "self-selected-authority", "wrong-coordinate", "hash-substitution", "wrong-key", "negative-revision", "wrong-size", "wrong-digest", "changed-response", "response-count", "oversized-response", "oversized-path", "oversized-pin"} {
		t.Run(scenario, func(t *testing.T) {
			f := checksumTimelineFixture(t)
			a := f.authority()
			p := f.publication(t, "v1.0.0", f.First, 0)
			r := Repository{Settings: RepositorySettings{GoChecksumAuthority: &a}}
			ptr := &p
			c := gomodule.Coordinate{Module: f.Module, Version: "v1.0.0"}
			switch scenario {
			case "missing":
				ptr = nil
			case "required-no-authority":
				r.Settings.GoChecksumAuthority = nil
				r.Settings.Cache.RequireChecksum = true
			case "self-selected-authority":
				r.Settings.GoChecksumAuthority = nil
			case "wrong-coordinate":
				c.Version = "v1.1.0"
			case "hash-substitution":
				p.ZIPHash = p.ModHash
			case "wrong-key":
				p.Proof.Snapshot.VerifierKey += "x"
			case "negative-revision":
				p.ExpectedCheckpointRevision = -1
			case "wrong-size":
				p.Object.Size++
			case "wrong-digest":
				p.Object.Digest = strings.Repeat("0", 64)
			case "changed-response":
				for path, body := range p.Proof.Snapshot.Responses {
					body[0] ^= 1
					p.Proof.Snapshot.Responses[path] = body
					break
				}
			case "response-count":
				p.Proof.Snapshot.Responses = map[string][]byte{}
				for n := 0; n < 129; n++ {
					p.Proof.Snapshot.Responses[strings.Repeat("x", n+1)] = []byte("x")
				}
			case "oversized-response":
				p.Proof.Snapshot.Responses = map[string][]byte{"/lookup/a": make([]byte, 1<<20+1)}
			case "oversized-path":
				p.Proof.Snapshot.Responses = map[string][]byte{strings.Repeat("x", 2049): []byte("x")}
			case "oversized-pin":
				p.Proof.Snapshot.Checkpoint = make([]byte, 16<<10+1)
			}
			err := validateGoChecksumPublication(r, ptr, c)
			if scenario == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrGoModuleUnvalidated) {
				t.Fatal("unbound publication admitted", err)
			}
		})
	}
}
