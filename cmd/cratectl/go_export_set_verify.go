// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"encoding/json"
	"errors"
	"flag"
	"io"
)

func runGoExportSetVerify(args []string, out io.Writer) error {
	f := flag.NewFlagSet("go-export-set-verify", flag.ContinueOnError)
	j := checksumJournalArguments(f)
	file := f.String("manifest-file", "", "private exact common canonical manifest")
	id := f.String("set-id", "", "exact independently selected original common-set identity")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *file == "" || !store.ValidGoExportID(*id) || *j.file == "" {
		return errors.New("supply a private canonical common manifest, exact set identity, complete journal and independent external checkpoint trust")
	}
	attribution, event, err := j.selectEvent(f)
	if err != nil {
		return err
	}
	if attribution == nil {
		return errors.New("complete signed journal attribution required")
	}
	raw, err := configfile.ReadBytes(*file, store.MaxGoExportSetManifest, true)
	if err != nil {
		return errors.New("cannot read bounded private common manifest")
	}
	defer clear(raw)
	m, err := store.BindGoExportSetManifest(raw, *j.tenant, *id, event)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Profile                     string                      `json:"profile"`
		SetID                       string                      `json:"set_id"`
		ManifestSHA256              string                      `json:"manifest_sha256"`
		ManifestBytes               int                         `json:"manifest_bytes"`
		Roots                       int                         `json:"roots"`
		DeclaredArtifactBytes       int64                       `json:"declared_artifact_bytes"`
		Attribution                 *checksumJournalAttribution `json:"attribution"`
		CommonSnapshotManifestBound bool                        `json:"common_snapshot_manifest_bound"`
		ArtifactBytesVerified       bool                        `json:"artifact_bytes_verified"`
		DependencyClosure           bool                        `json:"dependency_closure"`
		ChecksumAuthority           bool                        `json:"checksum_authority_verified"`
		CurrentAdmission            bool                        `json:"current_registry_admission"`
		Trust                       string                      `json:"trust"`
	}{Profile: "cratectl.go.export-set.binding.v1", SetID: *id, ManifestSHA256: crypt.Digest(raw), ManifestBytes: len(raw), Roots: len(m.Entries), DeclaredArtifactBytes: m.DeclaredArtifactBytes, Attribution: attribution, CommonSnapshotManifestBound: true, Trust: "Exact common-snapshot manifest is bound to its original creation event through the complete journal under the independently selected external signer/head. This authenticates the server's historical statement, not physical package bytes, automatic dependency/permission/provenance closure, checksum authority, current admission or history beyond that supplied head. Private paths and original policy bodies are omitted."})
}
