// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

const goExportIndexProfile = "cratectl.go.export.index.v1"
const maxGoExportIndexBytes = 256 << 10
const goExportIndexSelectionBytes = 4 << 20

var errGoExportIndex = errors.New("invalid bounded export index or original manifest binding")

type goExportIndexEntry struct {
	Repository    string `json:"repository"`
	Module        string `json:"module"`
	Version       string `json:"version"`
	ExportID      string `json:"export_id"`
	EventSequence int64  `json:"event_sequence"`
	ManifestFile  string `json:"manifest_file"`
}
type goExportIndex struct {
	Profile string               `json:"profile"`
	Entries []goExportIndexEntry `json:"entries"`
}
type goExportIndexBinding struct {
	Repository            string `json:"repository"`
	Module                string `json:"module"`
	Version               string `json:"version"`
	ExportID              string `json:"export_id"`
	EventSequence         int64  `json:"event_sequence"`
	EventHash             string `json:"event_hash"`
	ManifestSHA256        string `json:"manifest_sha256"`
	ManifestBytes         int    `json:"manifest_bytes"`
	DeclaredArtifactBytes int64  `json:"declared_artifact_bytes"`
}

func parseGoExportIndex(raw []byte) (goExportIndex, error) {
	var index goExportIndex
	if len(raw) == 0 || len(raw) > maxGoExportIndexBytes || json.Unmarshal(raw, &index) != nil || index.Profile != goExportIndexProfile || len(index.Entries) < 1 || len(index.Entries) > crypt.MaxJournalSelectedEvents {
		return goExportIndex{}, errGoExportIndex
	}
	canonical, err := json.Marshal(index)
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return goExportIndex{}, errGoExportIndex
	}
	coordinates, ids, sequences := map[gomodule.Coordinate]bool{}, map[string]bool{}, map[int64]bool{}
	for _, entry := range index.Entries {
		c, err := gomodule.Canonical(entry.Module, entry.Version)
		if err != nil || !store.Name.MatchString(entry.Repository) || !store.ValidGoExportID(entry.ExportID) || entry.EventSequence < 1 || len(entry.ManifestFile) > 4096 || !filepath.IsAbs(entry.ManifestFile) || filepath.Clean(entry.ManifestFile) != entry.ManifestFile || coordinates[c] || ids[entry.ExportID] || sequences[entry.EventSequence] {
			return goExportIndex{}, errGoExportIndex
		}
		coordinates[c], ids[entry.ExportID], sequences[entry.EventSequence] = true, true, true
	}
	return index, nil
}

// The caller must first verify the entire signed journal and independently
// selected signer. Individual event hashes alone never establish that trust.
// No bindings or partial byte total escape if any later member fails.
func bindGoExportIndex(ctx context.Context, index goExportIndex, tenant string, events []crypt.JournalEvent, read func(string) ([]byte, error), maximum int64) ([]goExportIndexBinding, int64, error) {
	if len(events) != len(index.Entries) || len(events) < 1 || len(events) > crypt.MaxJournalSelectedEvents || maximum < 1 || maximum > crypt.MaxJournalInputBytes {
		return nil, 0, errGoExportIndex
	}
	bindings := make([]goExportIndexBinding, 0, len(events))
	var total int64
	for n, entry := range index.Entries {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		event := events[n]
		if event.Sequence != entry.EventSequence {
			return nil, 0, errGoExportIndex
		}
		raw, err := read(entry.ManifestFile)
		if err != nil {
			return nil, 0, errGoExportIndex
		}
		c, err := gomodule.Canonical(entry.Module, entry.Version)
		if err != nil {
			clear(raw)
			return nil, 0, errGoExportIndex
		}
		manifest, err := store.BindGoExportManifest(raw, tenant, entry.Repository, entry.ExportID, c, event)
		if err != nil {
			clear(raw)
			return nil, 0, errGoExportIndex
		}
		binding := goExportIndexBinding{Repository: entry.Repository, Module: entry.Module, Version: entry.Version, ExportID: entry.ExportID, EventSequence: event.Sequence, EventHash: event.Hash, ManifestSHA256: crypt.Digest(raw), ManifestBytes: len(raw)}
		clear(raw)
		for _, artifact := range manifest.Artifacts {
			if artifact.Size > maximum-total {
				return nil, 0, errors.New("export index exceeds its declared representation-byte budget")
			}
			total += artifact.Size
			binding.DeclaredArtifactBytes += artifact.Size
		}
		bindings = append(bindings, binding)
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	return bindings, total, nil
}

func runGoExportIndexVerify(args []string, out io.Writer) error {
	f := flag.NewFlagSet("go-export-index-verify", flag.ContinueOnError)
	j := checksumJournalArguments(f)
	input := f.String("index-file", "", "private canonical index of selected exports; each manifest_file is an absolute private path")
	maximum := f.Int64("max-artifact-bytes", 1<<30, "sum of declared representation sizes, positive through64GiB; no artifact bytes are read")
	if err := f.Parse(args); err != nil {
		return err
	}
	singleSupplied := false
	f.Visit(func(v *flag.Flag) {
		if v.Name == "journal-event-sequence" {
			singleSupplied = true
		}
	})
	if f.NArg() != 0 || *input == "" || *j.file == "" || singleSupplied || *maximum < 1 || *maximum > crypt.MaxJournalInputBytes || *j.timeout <= 0 || *j.timeout > time.Hour || runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("supply a private export index, complete signed journal and independent checkpoint key, bounded time/bytes on Linux or macOS; the index selects every event")
	}
	raw, err := configfile.ReadBytes(*input, maxGoExportIndexBytes, true)
	if err != nil {
		return errors.New("cannot read bounded private export index")
	}
	index, err := parseGoExportIndex(raw)
	indexDigest := crypt.Digest(raw)
	clear(raw)
	if err != nil {
		return err
	}
	parse := func(value string) (int64, bool) {
		n, err := strconv.ParseInt(value, 10, 64)
		return n, err == nil && n >= 0 && strconv.FormatInt(n, 10) == value
	}
	a, aok := parse(*j.after)
	h, hok := parse(*j.through)
	start := crypt.JournalAnchor{Tenant: *j.tenant, Sequence: a, Hash: *j.afterHash}
	head := crypt.JournalAnchor{Tenant: *j.tenant, Sequence: h, Hash: *j.throughHash}
	if !aok || !hok || !start.Valid() || !head.Valid() || a > h || *j.maxBytes < 1 || *j.maxBytes > crypt.MaxJournalInputBytes {
		return errGoExportIndex
	}
	sequences := make([]int64, 0, len(index.Entries))
	for _, entry := range index.Entries {
		if entry.EventSequence <= a || entry.EventSequence > h {
			return errGoExportIndex
		}
		sequences = append(sequences, entry.EventSequence)
	}
	signature, err := j.checkpoint.verify(head)
	if err != nil {
		return err
	}
	if signature == nil {
		return errors.New("export index verification requires the external checkpoint statement/signature and an independently selected public key")
	}
	journal, err := configfile.OpenBounded(*j.file, *j.maxBytes, true)
	if err != nil {
		return errors.New("cannot open bounded private complete journal")
	}
	defer journal.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *j.timeout)
	defer cancel()
	verification, events, err := crypt.VerifyJournalExportEvents(ctx, journal, start, head, *j.maxBytes, sequences, goExportIndexSelectionBytes)
	if err != nil {
		return errors.New("complete signed journal failed; no export index binding was established")
	}
	bindings, total, err := bindGoExportIndex(ctx, index, *j.tenant, events, func(name string) ([]byte, error) { return configfile.ReadBytes(name, store.MaxGoExportManifest, true) }, *maximum)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Profile               string                               `json:"profile"`
		IndexSHA256           string                               `json:"index_sha256"`
		Journal               crypt.JournalVerification            `json:"journal"`
		Signature             *crypt.JournalCheckpointVerification `json:"checkpoint_signature"`
		Bindings              []goExportIndexBinding               `json:"bindings"`
		DeclaredArtifactBytes int64                                `json:"declared_artifact_bytes"`
		ArtifactBytesVerified bool                                 `json:"artifact_bytes_verified"`
		DependencyClosure     bool                                 `json:"dependency_closure"`
		ConsistentSnapshot    bool                                 `json:"consistent_server_snapshot"`
		CurrentAdmission      bool                                 `json:"current_registry_admission"`
		ChecksumAuthority     bool                                 `json:"checksum_authority_verified"`
		Trust                 string                               `json:"trust"`
	}{Profile: goExportIndexProfile, IndexSHA256: indexDigest, Journal: verification, Signature: signature, Bindings: bindings, DeclaredArtifactBytes: total, Trust: "Selected historical export manifests are bound to their original creation events in one complete journal under the independently selected signer. This verifies no package bytes, dependency/authority/permission/provenance closure, common snapshot, destination admission or latest/revoked history. Private paths and original policy bodies are omitted."})
}
