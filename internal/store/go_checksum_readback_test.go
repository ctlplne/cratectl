// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
)

func checksumReadbackFixture(t testing.TB) (checksumTimeline, GoModuleChecksumReadback, GoModuleChecksumProof) {
	t.Helper()
	f := checksumTimelineFixture(t)
	p := f.publication(t, "v1.0.0", f.First, 0)
	head, err := crypt.ParseGoSumDBCheckpoint(f.Key, f.One)
	if err != nil {
		t.Fatal(err)
	}
	v := GoModuleChecksumReadback{key: f.Key, checkpoint: bytes.Clone(f.One), binding: goChecksumBinding{proofPolicy: GoChecksumProofPolicy{Mode: "retained"}, tenant: "proof-team", repository: "owned", rootPath: (gomodule.Coordinate{Module: f.Module, Version: "v1.0.0"}).Prefix() + ".zip", sourceRevision: 0, generation: 1, validationGeneration: 1, keyDigest: head.KeyDigest, checkpointDigest: crypt.Digest(f.One), checkpointRevision: 2, proofDigest: p.Object.Digest, proofSize: p.Object.Size, module: f.Module, version: "v1.0.0", zipHash: p.ZIPHash, modHash: p.ModHash, rawDigests: [3]string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)}}}
	return f, v, p.Proof
}

func TestGoChecksumReadbackUsesRetainedTrustAndRequiresCanonicalBoundedProof(t *testing.T) {
	for _, scenario := range []string{"valid", "consistent-newer-head", "older-proof-missing-tiles", "missing-tile", "wrong-profile", "wrong-coordinate", "wrong-hash", "wrong-key", "unsigned-original-pin", "signed-original-fork", "noncanonical-json", "duplicate-field", "unknown-field", "unknown-snapshot-field", "trailing-json", "bad-base64", "oversized-path", "oversized-map", "oversized-raw", "wrong-object-digest", "wrong-object-size", "zero-view", "invalid-source", "invalid-generation", "invalid-checkpoint-revision", "invalid-raw-digest", "invalid-raw-size", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			f, v, p := checksumReadbackFixture(t)
			ctx := context.Background()
			want := error(ErrGoModuleUnvalidated)
			switch scenario {
			case "valid":
				want = nil
			case "consistent-newer-head":
				p.Snapshot = f.OldAtSecond
				v.checkpoint = f.Two
				v.binding.checkpointDigest = crypt.Digest(f.Two)
				v.binding.checkpointRevision = 3
				want = nil
			case "older-proof-missing-tiles":
				v.checkpoint = f.Two
				v.binding.checkpointDigest = crypt.Digest(f.Two)
				v.binding.checkpointRevision = 3
				want = crypt.ErrGoChecksumAuthority
			case "missing-tile":
				for path := range p.Snapshot.Responses {
					if strings.HasPrefix(path, "/tile/") {
						delete(p.Snapshot.Responses, path)
					}
				}
				want = crypt.ErrGoChecksumAuthority
			case "wrong-profile":
				p.Profile = "unknown"
			case "wrong-coordinate":
				p.Version = "v1.1.0"
			case "wrong-hash":
				p.ZIPHash = f.ModHash
			case "wrong-key":
				p.Snapshot.VerifierKey += "x"
			case "unsigned-original-pin":
				p.Snapshot.Checkpoint = []byte("unsigned")
				want = crypt.ErrGoChecksumAuthority
			case "signed-original-fork":
				fork, err := crypt.VerifyGoSumDB(ctx, f.Module, "v1.0.0", f.ModHash, f.ModHash, f.Fork)
				if err != nil {
					t.Fatal(err)
				}
				p.Snapshot.Checkpoint = fork.Checkpoint
				want = crypt.ErrGoChecksumFork
			case "oversized-path":
				p.Snapshot.Responses = map[string][]byte{strings.Repeat("x", 2049): []byte("x")}
			case "oversized-map":
				p.Snapshot.Responses = map[string][]byte{}
				for n := 0; n < 129; n++ {
					p.Snapshot.Responses[strings.Repeat("x", n+1)] = []byte("x")
				}
			case "invalid-source":
				v.binding.sourceRevision = -1
			case "invalid-generation":
				v.binding.validationGeneration = 2
			case "invalid-checkpoint-revision":
				v.binding.checkpointRevision = 0
			case "invalid-raw-digest":
				v.binding.rawDigests[2] = "invalid"
			case "invalid-raw-size":
				v.binding.rawSizes[2] = -1
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "noncanonical-json":
				raw = append([]byte(" "), raw...)
			case "duplicate-field":
				raw = append([]byte(`{"profile":"unknown",`), raw[1:]...)
			case "unknown-field":
				raw = append([]byte(`{"unreviewed":true,`), raw[1:]...)
			case "unknown-snapshot-field":
				raw = bytes.Replace(raw, []byte(`"snapshot":{`), []byte(`"snapshot":{"unknown":true,`), 1)
			case "trailing-json":
				raw = append(raw, []byte("{}")...)
			case "bad-base64":
				raw = bytes.Replace(raw, []byte(`"checkpoint":"`), []byte(`"checkpoint":"!`), 1)
			case "oversized-raw":
				raw = bytes.Repeat([]byte{'x'}, MaxGoModuleChecksumProof+1)
			}
			v.binding.proofDigest = crypt.Digest(raw)
			v.binding.proofSize = int64(len(raw))
			if scenario == "wrong-object-digest" {
				v.binding.proofDigest = strings.Repeat("0", 64)
			}
			if scenario == "wrong-object-size" {
				v.binding.proofSize++
			}
			if scenario == "zero-view" {
				v = GoModuleChecksumReadback{}
			}
			before := bytes.Clone(raw)
			checkpoint := bytes.Clone(v.checkpoint)
			marker, err := VerifyGoModuleChecksumReadback(ctx, v, raw)
			if want == nil {
				if err != nil || marker == nil || marker.binding != v.binding {
					t.Fatal("exact original proof did not produce the bound opaque admission", err)
				}
				encoded, _ := json.Marshal(marker)
				if string(encoded) != "{}" {
					t.Fatal("internal admission became a serializable verified flag")
				}
			} else if !errors.Is(err, want) || marker != nil {
				t.Fatal("unverified readback produced admission or wrong stable error", err)
			}
			if !bytes.Equal(before, raw) || !bytes.Equal(checkpoint, v.checkpoint) {
				t.Fatal("readback verification mutated proof or retained trust")
			}
		})
	}
}

func FuzzGoChecksumReadbackCanonicalProof(f *testing.F) {
	_, view, proof := checksumReadbackFixture(f)
	seed, err := json.Marshal(proof)
	if err != nil {
		f.Fatal(err)
	}
	if marker, err := VerifyGoModuleChecksumReadback(context.Background(), view, seed); err != nil || marker == nil {
		f.Fatal("deterministic public worker seed must authenticate", err)
	}
	f.Add(seed)
	f.Add([]byte(`{"profile":"unknown"}`))
	f.Add(append([]byte(" "), seed...))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxGoModuleChecksumProof {
			return
		}
		v := view
		v.binding.proofDigest = crypt.Digest(raw)
		v.binding.proofSize = int64(len(raw))
		marker, err := VerifyGoModuleChecksumReadback(context.Background(), v, raw)
		if err != nil {
			if marker != nil {
				t.Fatal("failed proof returned an admission")
			}
			return
		}
		if marker == nil || marker.binding != v.binding {
			t.Fatal("proof verification lost repository/source/lease/object bindings")
		}
		var decoded GoModuleChecksumProof
		if json.Unmarshal(raw, &decoded) != nil {
			t.Fatal("malformed proof admitted")
		}
		canonical, _ := json.Marshal(decoded)
		if !bytes.Equal(canonical, raw) {
			t.Fatal("ambiguous proof encoding admitted")
		}
	})
}
