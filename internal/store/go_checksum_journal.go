// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	crypt "ctlplne.dev/cratectl/internal/crypto"
)

// Required bindings are case-sensitive and unique, including within data.
// Extra metadata is retained by the original event, never promoted into proof.
func checksumJournalObject(raw []byte, required ...string) (map[string]json.RawMessage, bool) {
	if len(raw) > crypt.MaxJournalPayload {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || len(name) > 128 || len(fields) >= 64 {
			return nil, false
		}
		if _, exists := fields[name]; exists {
			return nil, false
		}
		for _, key := range required {
			if name != key && strings.EqualFold(name, key) {
				return nil, false
			}
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, false
		}
		fields[name] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, false
	}
	var rest any
	if d.Decode(&rest) != io.EOF {
		return nil, false
	}
	for _, key := range required {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
	}
	return fields, true
}

// Bind canonical failure bytes to one original event. This validates bindings,
// not the checkpoint signer or checksum authority: callers must independently
// verify the complete anchored journal range and original authority evidence.
// It is never a package admission token or a reconstruction of legacy labels.
func BindGoChecksumFailureJournalEvent(raw []byte, record GoChecksumFailureRecord, event crypt.JournalEvent) (string, error) {
	if len(raw) == 0 || len(raw) > MaxGoChecksumFailureEvidence || record.Profile != GoChecksumFailureEvidenceProfile || !Name.MatchString(record.Tenant) || !Name.MatchString(record.Repository) || len(record.RootPath) > 2048 || record.RootPath == "" || record.SourceRevision < 0 || record.Generation < 1 || record.ExpectedCheckpointRevision < 0 || record.CurrentCheckpointRevision < 0 || len(record.CurrentCheckpoint) > 16<<10 || !uploadDigest.MatchString(record.KeyDigest) || validateGoChecksumFailureReport(record.Report) != nil {
		return "", ErrGoModuleUnvalidated
	}
	failure := "upstream_checksum_unverified"
	if record.Classification == "fork" {
		failure = "upstream_checksum_fork"
	} else if record.Classification != "unverified" {
		return "", ErrGoModuleUnvalidated
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(raw, canonical) || crypt.VerifyJournalEvent(record.Tenant, event) != nil {
		return "", ErrGoModuleUnvalidated
	}
	envelope, ok := checksumJournalObject([]byte(event.Payload), "tenant", "sequence", "kind", "data")
	if !ok {
		return "", ErrGoModuleUnvalidated
	}
	var tenant, kind string
	var sequence int64
	if json.Unmarshal(envelope["tenant"], &tenant) != nil || json.Unmarshal(envelope["sequence"], &sequence) != nil || json.Unmarshal(envelope["kind"], &kind) != nil || tenant != record.Tenant || sequence != event.Sequence || kind != "proxy.retrieval.failed" {
		return "", ErrGoModuleUnvalidated
	}
	data, ok := checksumJournalObject(envelope["data"], "repository", "path", "generation", "source_revision", "state", "failure", "go_checksum_failure_digest")
	if !ok {
		return "", ErrGoModuleUnvalidated
	}
	var repository, path, state, classification, digest string
	var generation, source int64
	if json.Unmarshal(data["repository"], &repository) != nil || json.Unmarshal(data["path"], &path) != nil || json.Unmarshal(data["generation"], &generation) != nil || json.Unmarshal(data["source_revision"], &source) != nil || json.Unmarshal(data["state"], &state) != nil || json.Unmarshal(data["failure"], &classification) != nil || json.Unmarshal(data["go_checksum_failure_digest"], &digest) != nil || repository != record.Repository || path != record.RootPath || generation != record.Generation || source != record.SourceRevision || state != "failed" || classification != failure || !uploadDigest.MatchString(digest) || digest != crypt.Digest(raw) {
		return "", ErrGoModuleUnvalidated
	}
	return digest, nil
}
