// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
)

// Field order matches the canonical normal publication response. Unknown,
// duplicate and alternate-case fields cannot survive exact reserialization.
type goImportPublication struct {
	Module          string            `json:"module"`
	Repository      string            `json:"repository"`
	Representations map[string]string `json:"representations_sha256"`
	Version         string            `json:"version"`
}
type goImportIntent struct {
	Profile     string                      `json:"profile"`
	Authority   string                      `json:"destination_authority"`
	Repository  string                      `json:"destination_repository"`
	Key         string                      `json:"idempotency_key"`
	Publication store.GoHostedPublication   `json:"source_publication"`
	Journal     *checksumJournalAttribution `json:"source_journal"`
	Export      *goOfflineExportSnapshot    `json:"source_export"`
}
type goImportReceipt struct {
	Intent                   goImportIntent      `json:"intent"`
	Publication              goImportPublication `json:"destination_publication"`
	PublicationRecorded      bool                `json:"destination_publication_recorded"`
	CurrentRegistryAdmission bool                `json:"current_registry_admission"`
	ChecksumAuthority        bool                `json:"checksum_authority_verified"`
	DependencyClosure        bool                `json:"dependency_closure"`
}

func runGoExportImport(args []string, out io.Writer) error {
	f := flag.NewFlagSet("go-export-import", flag.ContinueOnError)
	j := checksumJournalArguments(f)
	configuration := f.String("config", "", "private destination client configuration")
	repository := f.String("repository", "", "exact original source repository")
	destination := f.String("destination-repository", "", "current authorized hosted Go destination")
	module := f.String("module", "", "exact canonical original module")
	version := f.String("version", "", "exact canonical original version")
	manifestFile := f.String("manifest-file", "", "private original canonical export manifest")
	exportID := f.String("export-id", "", "exact original export ID")
	zipFile := f.String("zip-file", "", "private original ZIP")
	modFile := f.String("mod-file", "", "private original go.mod")
	infoFile := f.String("info-file", "", "private original info")
	output := f.String("output-directory", "", "new owner-private attempt directory; retained after any request")
	key := f.String("idempotency-key", "", "stable destination mutation key; reuse for identical retries")
	timeout := f.Duration("timeout", 5*time.Minute, "verification and destination request budget, positive through 1h")
	if err := f.Parse(args); err != nil {
		return err
	}
	c, err := gomodule.Canonical(*module, *version)
	if err != nil || f.NArg() != 0 || !store.Name.MatchString(*repository) || !store.Name.MatchString(*destination) || *configuration == "" || *j.file == "" || *manifestFile == "" || !store.ValidGoExportID(*exportID) || *zipFile == "" || *modFile == "" || *infoFile == "" || *output == "" || *key == "" || len(*key) > 200 || !utf8.ValidString(*key) || strings.ContainsFunc(*key, unicode.IsControl) || *timeout <= 0 || *timeout > time.Hour {
		return errors.New("supply the exact signed source export, three private files, destination config/repository, stable idempotency-key and a new private output-directory")
	}
	attribution, event, err := j.selectEvent(f)
	if err != nil {
		return err
	}
	raw, err := configfile.ReadBytes(*manifestFile, store.MaxGoExportManifest, true)
	if err != nil {
		return errors.New("cannot read original private export manifest")
	}
	manifest, err := store.BindGoExportManifest(raw, *j.tenant, *repository, *exportID, c, event)
	if err != nil || attribution == nil {
		return errors.New("source export is not bound to the complete journal and independently selected signer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	prepared, err := prepareOfflineGo(ctx, manifest.Publication(), attribution, [3]string{*zipFile, *modFile, *infoFile}, *output, goOfflineSnapshot{*exportID, raw})
	if err != nil {
		return err
	}
	client, authority, token, closeClient, err := collectionClient(*configuration)
	if err != nil {
		return err
	}
	defer closeClient()
	client.Timeout = *timeout
	receipt, err := importPreparedGo(ctx, client, authority, token, *destination, *key, *output, prepared)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(receipt)
}

// Reuse the destination's ordinary hosted publication path, never source
// policy/approval fields. Missing destination scan evidence remains unassessed.
// No automatic retry: an uncertain response may follow a committed transaction.
func importPreparedGo(ctx context.Context, client *http.Client, authority, token, repository, key, output string, prepared goOfflineReceipt) (goImportReceipt, error) {
	var empty goImportReceipt
	c := prepared.Publication.Coordinate
	root, err := os.OpenRoot(output)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	info, err := configfile.ReadBytes(filepath.Join(output, "proxy", c.Prefix()+".info"), gomodule.MaxVersionInfo, true)
	if err != nil || crypt.Digest(info) != prepared.Publication.Info {
		return empty, errors.New("prepared info changed from the signed source identity")
	}
	parsed, err := gomodule.ParseVersionInfo(info, c)
	if err != nil {
		return empty, err
	}
	instant := parsed.Time.UTC().Format(time.RFC3339Nano)
	canonical, err := gomodule.VersionInfo(c, instant)
	if err != nil || !bytes.Equal(info, canonical) {
		return empty, errors.New("original info cannot be reproduced exactly by normal hosted publication; preserve it, no destination request was made")
	}
	zip, err := openCollectionMember(root, "proxy/"+c.Prefix()+".zip")
	if err != nil {
		return empty, err
	}
	defer zip.Close()
	stat, err := zip.Stat()
	if err != nil || stat.Size() > maxOfflineGoZIP {
		return empty, errors.New("prepared ZIP exceeds import budget")
	}
	if err := verifyCollectionFile(ctx, zip, blob.Object{Digest: prepared.Publication.ZIP, Size: stat.Size()}); err != nil {
		return empty, err
	}
	if _, err := zip.Seek(0, io.SeekStart); err != nil {
		return empty, err
	}
	intent := goImportIntent{"cratectl.go.hosted.import.v1", authority, repository, key, prepared.Publication, prepared.Journal, prepared.ExportSnapshot}
	if err := publishCollectionJSON(root, "import-intent.json", ".import-intent.pending", collectionJSON(intent), false); err != nil {
		return empty, err
	}
	req, err := http.NewRequestWithContext(ctx, "PUT", authority+"/go/"+repository+"/"+c.Prefix()+".zip", io.LimitReader(offlineGoReader{ctx, zip}, stat.Size()))
	if err != nil {
		return empty, err
	}
	req.ContentLength = stat.Size()
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-Checksum-Sha256", prepared.Publication.ZIP)
	req.Header.Set("X-Cratectl-Module-Time", instant)
	req.Header.Set("Idempotency-Key", key)
	unconfirmed := errors.New("destination publication is unconfirmed; preserve this attempt directory and retry with the same key and a new private output-directory")
	response, err := client.Do(req)
	if err != nil {
		return empty, unconfirmed
	}
	defer response.Body.Close()
	if response.StatusCode != 201 || response.Header.Get("Content-Encoding") != "" {
		return empty, fmt.Errorf("%w (HTTP %d)", unconfirmed, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, collectionJSONLimit+1))
	want := goImportPublication{c.Module, repository, map[string]string{"zip": prepared.Publication.ZIP, "mod": prepared.Publication.Mod, "info": prepared.Publication.Info}, c.Version}
	var observed goImportPublication
	if err != nil || len(body) > collectionJSONLimit || json.Unmarshal(body, &observed) != nil || !reflect.DeepEqual(observed, want) || !bytes.Equal(body, bytes.TrimSuffix(collectionJSON(observed), []byte("\n"))) {
		return empty, unconfirmed
	}
	receipt := goImportReceipt{Intent: intent, Publication: observed, PublicationRecorded: true}
	if err := publishCollectionJSON(root, "import-receipt.json", ".import-receipt.pending", collectionJSON(receipt), false); err != nil {
		return empty, fmt.Errorf("%w: local receipt publication failed", unconfirmed)
	}
	return receipt, nil
}
