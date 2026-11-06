// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGoChecksumProofMetadataRemainsInertBoundedAndKeyBound(t *testing.T) {
	for _, scenario := range []string{"unassessed", "invalid-json", "wrong-key", "wrong-profile", "oversized", "media", "zero-size", "large-proof"} {
		t.Run(scenario, func(t *testing.T) {
			key := strings.Repeat("a", 64)
			raw, err := json.Marshal(map[string]string{"go_checksum_profile": GoModuleChecksumProfile, "go_checksum_key_digest": key})
			if err != nil {
				t.Fatal(err)
			}
			proof := Artifact{Size: 100, MediaType: GoChecksumProofMedia, Metadata: raw, Decision: "unassessed"}
			switch scenario {
			case "invalid-json":
				proof.Metadata = []byte(`{"go_checksum_profile":`)
			case "wrong-key":
				key = strings.Repeat("b", 64)
			case "wrong-profile":
				proof.Metadata = []byte(strings.Replace(string(raw), GoModuleChecksumProfile, "unknown", 1))
			case "oversized":
				proof.Metadata = append(raw, []byte(strings.Repeat(" ", 4097))...)
			case "media":
				proof.MediaType = "application/json"
			case "zero-size":
				proof.Size = 0
			case "large-proof":
				proof.Size = MaxGoModuleChecksumProof + 1
			}
			if ok := validateGoChecksumProofArtifact(proof, key) == nil; ok != (scenario == "unassessed") {
				t.Fatal("proof metadata lost its bound/key/media contract", scenario)
			}
		})
	}
}

func FuzzGoChecksumProofArtifactMetadata(f *testing.F) {
	key := strings.Repeat("a", 64)
	seed, err := json.Marshal(map[string]string{"go_checksum_profile": GoModuleChecksumProfile, "go_checksum_key_digest": key})
	if err != nil || validateGoChecksumProofArtifact(Artifact{Size: 1, MediaType: GoChecksumProofMedia, Metadata: seed}, key) != nil {
		f.Fatal("public proof metadata seed must be valid", err)
	}
	f.Add(seed, int64(1))
	f.Add([]byte(`{"go_checksum_profile":null}`), int64(0))
	f.Add(append(seed, []byte(strings.Repeat(" ", 4097))...), int64(1))
	f.Fuzz(func(t *testing.T, raw []byte, size int64) {
		if len(raw) > 8192 {
			return
		}
		err := validateGoChecksumProofArtifact(Artifact{Size: size, MediaType: GoChecksumProofMedia, Metadata: raw}, key)
		if err == nil && (size <= 0 || size > MaxGoModuleChecksumProof || len(raw) > 4096 || !json.Valid(raw)) {
			t.Fatal("invalid or unbounded proof metadata admitted")
		}
	})
}
