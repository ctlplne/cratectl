//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

// This journey uses real owned PostgreSQL/CAS, the actual candidate CLI, an
// external OpenSSL signature and the real pinned native Go SDK. There is no
// registry/network fallback and no fixture code is compiled or executed.
func TestGoModuleHostedOfflinePublicationPreparesExactStockClientBytes(t *testing.T) {
	f := newGoIntakeFixture(t)
	ctx := context.Background()
	const repo = "hosted-offline"
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		return CreateRepository(ctx, tx, f.i, Repository{Name: repo, Format: "go", RequireReview: true, Access: "restricted"})
	}); err != nil {
		t.Fatal(err)
	}
	result, err := f.s.PublishGoModule(ctx, f.i, repo, f.result.GoModule.Objects, "owned-offline-publication")
	if err != nil || result.Replay {
		t.Fatal("actual hosted publication", err)
	}
	var sequence int64
	if err := f.s.Tx(ctx, f.i, false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sequence FROM cratectl.events WHERE payload::jsonb->>'kind'='go.module.published' AND payload::jsonb->'data'->>'repository'=$1`, repo).Scan(&sequence)
	}); err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	var files [3]string
	for n, a := range f.result.GoModule.Objects {
		if _, err := f.s.Artifact(ctx, f.i, repo, a.Path); !errors.Is(err, ErrDenied) {
			t.Fatal("unassessed bundle escaped current policy", err)
		}
		if _, err := f.s.Mutate(ctx, f.i, "owned-offline-allow-"+strconv.Itoa(n), a.Digest, "artifact.decision", func(tx pgx.Tx) (any, int, error) {
			data, err := Decide(ctx, tx, f.i, repo, a.Path, a.Digest, "allowed")
			return data, 200, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	for n, original := range f.result.GoModule.Objects {
		a, err := f.s.Artifact(ctx, f.i, repo, original.Path)
		if err != nil || a.Digest != original.Digest {
			t.Fatal("current authorized source bundle", err)
		}
		input, err := f.objects.OpenVerified(ctx, f.i.Tenant, a.Digest, a.Size)
		if err != nil {
			t.Fatal(err)
		}
		files[n] = filepath.Join(private, "original."+[]string{"zip", "mod", "info"}[n])
		output, err := os.OpenFile(files[n], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			input.Close()
			t.Fatal(err)
		}
		count, err := io.Copy(output, io.LimitReader(input, a.Size+1))
		input.Close()
		if syncErr := output.Sync(); err == nil {
			err = syncErr
		}
		if closeErr := output.Close(); err == nil {
			err = closeErr
		}
		if err != nil || count != a.Size {
			t.Fatal("actual original CAS readback", err)
		}
	}
	// A later event and one-event pages make a verified prefix insufficient.
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		return appendEventIntent(ctx, tx, f.i, "owned.offline.later", map[string]bool{"historical_publication_only": true}, false)
	}); err != nil {
		t.Fatal(err)
	}
	head, err := f.s.JournalCheckpoint(ctx, f.i)
	if err != nil || head.Sequence <= sequence {
		t.Fatal(err)
	}
	var journal bytes.Buffer
	query := JournalRange{Through: head.Sequence, ThroughHash: head.Hash, Limit: 1}
	for {
		page, err := f.s.JournalPage(ctx, f.i, query)
		if err != nil || json.NewEncoder(&journal).Encode(page) != nil {
			t.Fatal("actual publication journal", err)
		}
		if !page.More {
			break
		}
		query.After, query.AfterHash = page.NextAfter, page.NextHash
	}
	_, event, err := crypt.VerifyJournalExportEvent(ctx, bytes.NewReader(journal.Bytes()), crypt.JournalAnchor{Tenant: f.i.Tenant}, head, 1<<20, sequence)
	if err != nil {
		t.Fatal(err)
	}
	c := f.result.GoModule.Objects[0]
	metadata, err := ValidateGoModuleArtifact(c)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := BindGoHostedPublication(f.i.Tenant, repo, gomodule.Coordinate{Module: metadata.Module, Version: metadata.Version}, event)
	if err != nil || publication.ZIP != c.Digest {
		t.Fatal("actual original publication binding", err)
	}
	verifyNativeGoOffline(t, private, files, journal.Bytes(), head, sequence, repo, metadata.Module, metadata.Version)
}

type nativeGoExportSnapshot struct {
	id  string
	raw []byte
}

func verifyNativeGoOffline(t *testing.T, private string, files [3]string, journal []byte, head crypt.JournalAnchor, sequence int64, repo, module, version string, snapshots ...nativeGoExportSnapshot) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	directory := os.Getenv("CRATECTL_QUALIFICATION_BIN_DIR")
	if directory == "" {
		t.Fatal("CRATECTL_QUALIFICATION_BIN_DIR required for actual owned candidate CLI")
	}
	if !filepath.IsAbs(directory) {
		directory = filepath.Join(root, directory)
	}
	cli := filepath.Join(directory, "cratectl")
	if st, err := os.Stat(cli); err != nil || !st.Mode().IsRegular() {
		t.Fatal("actual candidate CLI missing")
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal("actual external OpenSSL required")
	}
	run := func(ok bool, env []string, argv ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, argv[0], argv[1:]...)
		command.Dir = private
		command.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
		command.WaitDelay = 2 * time.Second
		var stdout, stderr goJournalCommandOutput
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		if ctx.Err() != nil || ok && err != nil || !ok && err == nil {
			// These fixed fixture commands have no credential environment or
			// network source. Signing commands always write keys/signatures to
			// files; their bounded error text and inert download result are safe
			// to retain, so a first native failure remains diagnosable.
			t.Fatalf("native %s outcome mismatch, expected success=%t: %v; fixture stdout=%q stderr=%q", filepath.Base(argv[0]), ok, err, stdout.Bytes()[:min(stdout.Len(), 16<<10)], stderr.Bytes()[:min(stderr.Len(), 16<<10)])
		}
		return bytes.Clone(stdout.Bytes())
	}
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(private, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	statement, err := crypt.JournalCheckpointBytes(head)
	if err != nil {
		t.Fatal(err)
	}
	statementFile, journalFile := write("checkpoint.json", statement), write("journal.jsonl", journal)
	privateKey, publicKey, signature := filepath.Join(private, "signer-private.pem"), filepath.Join(private, "signer-public.pem"), filepath.Join(private, "checkpoint.sig")
	opensslVersion := strings.Fields(string(run(true, nil, openssl, "version")))
	if len(opensslVersion) < 2 || opensslVersion[0] != "OpenSSL" || !strings.HasPrefix(opensslVersion[1], "3.") && !strings.HasPrefix(opensslVersion[1], "4.") {
		t.Fatal("unsupported external tool")
	}
	run(true, nil, openssl, "genpkey", "-algorithm", "ED25519", "-out", privateKey)
	if err := os.Chmod(privateKey, 0600); err != nil {
		t.Fatal(err)
	}
	run(true, nil, openssl, "pkey", "-in", privateKey, "-pubout", "-out", publicKey)
	run(true, nil, openssl, "pkeyutl", "-sign", "-rawin", "-inkey", privateKey, "-in", statementFile, "-out", signature)
	run(true, nil, openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", publicKey, "-in", statementFile, "-sigfile", signature)
	output := filepath.Join(private, "offline package")
	args := []string{cli, "go-module-offline", "--repository", repo, "--module", module, "--version", version, "--zip-file", files[0], "--mod-file", files[1], "--info-file", files[2], "--output-directory", output, "--journal-file", journalFile, "--journal-tenant", head.Tenant, "--journal-event-sequence", strconv.FormatInt(sequence, 10), "--journal-through", strconv.FormatInt(head.Sequence, 10), "--journal-through-hash", head.Hash, "--checkpoint-file", statementFile, "--checkpoint-signature-file", signature, "--checkpoint-key-file", publicKey}
	if len(snapshots) > 1 {
		t.Fatal("fixture requires one exact snapshot")
	}
	if len(snapshots) == 1 {
		args = append(args, "--manifest-file", write("export-manifest.json", snapshots[0].raw), "--export-id", snapshots[0].id)
	}
	var receipt struct {
		ExportSnapshot struct {
			ID     string `json:"id"`
			Digest string `json:"manifest_sha256"`
		} `json:"export_snapshot"`
		Profile   string
		Proxy     string `json:"goproxy"`
		ZIPHash   string `json:"zip_h1"`
		ModHash   string `json:"mod_h1"`
		Current   bool   `json:"current_registry_admission"`
		Authority bool   `json:"checksum_authority_verified"`
		Journal   struct {
			Sequence  int64                               `json:"event_sequence"`
			Range     crypt.JournalVerification           `json:"journal"`
			Signature crypt.JournalCheckpointVerification `json:"checkpoint_signature"`
		} `json:"journal_attribution"`
	}
	if raw := run(true, nil, args...); json.Unmarshal(raw, &receipt) != nil || receipt.Profile != "cratectl.go.hosted.offline.v1" || receipt.Proxy == "" || receipt.Current || receipt.Authority || receipt.Journal.Sequence != sequence || !receipt.Journal.Range.MatchesSuppliedCheckpoint || receipt.Journal.Range.ExportSHA256 != crypt.Digest(journal) || !receipt.Journal.Signature.SignatureVerified {
		t.Fatal("native CLI did not bind complete historical publication")
	}
	if len(snapshots) == 1 {
		if receipt.ExportSnapshot.ID != snapshots[0].id || receipt.ExportSnapshot.Digest != crypt.Digest(snapshots[0].raw) {
			t.Fatal("native CLI detached manifest snapshot")
		}
		saved, err := os.ReadFile(filepath.Join(output, "export-manifest.json"))
		if err != nil || !bytes.Equal(saved, snapshots[0].raw) {
			t.Fatal("native CLI lost original policy manifest", err)
		}
	}

	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	if !strings.Contains(string(run(true, nil, goBinary, "version")), "go1.27.3 ") {
		t.Fatal("pinned actual native Go1.27.3 required")
	}
	env := []string{"GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOTELEMETRY=off", "GOAUTH=off", "GOVCS=*:off", "GOPROXY=" + receipt.Proxy, "GOSUMDB=off", "GONOSUMDB=*", "GONOPROXY=none", "GOPRIVATE=", "GOFLAGS=", "GOCACHE=" + filepath.Join(private, "go-build"), "GOMODCACHE=" + filepath.Join(private, "go-mod"), "GOPATH=" + filepath.Join(private, "go-path")}
	// The real SDK deliberately makes extracted cache directories read-only.
	// Its native cleaner knows how to remove them. Run before TempDir cleanup,
	// including on assertion failure, and keep the normal cache permissions and
	// every byte/signature/journal assertion unchanged. This environment names
	// only this test's new cache, never the runner's shared development cache.
	t.Cleanup(func() { run(true, env, goBinary, "clean", "-modcache") })
	var downloaded struct{ Path, Version, Sum, GoModSum, Dir, Error string }
	if raw := run(true, env, goBinary, "mod", "download", "-json", module+"@"+version); json.Unmarshal(raw, &downloaded) != nil || downloaded.Path != module || downloaded.Version != version || downloaded.Sum != receipt.ZIPHash || downloaded.GoModSum != receipt.ModHash || downloaded.Error != "" || !strings.HasPrefix(downloaded.Dir, filepath.Join(private, "go-mod")+string(filepath.Separator)) {
		t.Fatal("actual offline Go SDK did not consume exact original bytes")
	}
	asset, err := os.ReadFile(filepath.Join(downloaded.Dir, "assets", "owned.txt"))
	if err != nil || string(asset) != "original bytes" {
		t.Fatal("actual offline extraction differs", err)
	}
	// Existing output and a missing terminal suffix must not emit a partial
	// success or overwrite the accepted private file proxy.
	if raw := run(false, nil, args...); len(raw) != 0 {
		t.Fatal("existing output emitted a receipt")
	}
	truncated := journal[:bytes.LastIndex(bytes.TrimSuffix(journal, []byte("\n")), []byte("\n"))+1]
	if len(truncated) == 0 || len(truncated) >= len(journal) {
		t.Fatal("fixture did not retain a prefix")
	}
	badArgs := append([]string(nil), args...)
	for n := range badArgs {
		if badArgs[n] == journalFile {
			badArgs[n] = write("truncated.jsonl", truncated)
		}
		if badArgs[n] == output {
			badArgs[n] = filepath.Join(private, "rejected")
		}
	}
	if raw := run(false, nil, badArgs...); len(raw) != 0 {
		t.Fatal("incomplete history emitted native success")
	}
	if _, err := os.Stat(filepath.Join(private, "rejected")); !os.IsNotExist(err) {
		t.Fatal("incomplete history created native proxy")
	}
	if len(snapshots) == 1 {
		wrong := append([]string(nil), args...)
		wrong = append(wrong, "--export-id", strings.Repeat("0", 64), "--output-directory", filepath.Join(private, "wrong-export"))
		if raw := run(false, nil, wrong...); len(raw) != 0 {
			t.Fatal("wrong export identity emitted receipt")
		}
		if _, err := os.Stat(filepath.Join(private, "wrong-export")); !os.IsNotExist(err) {
			t.Fatal("wrong export identity exposed proxy")
		}
	}
	if os.Getenv("CRATECTL_GO_EXPORT_PORTABLE_OUT") != "" {
		if len(snapshots) != 1 {
			t.Fatal("portable fixture requires the owned export snapshot test only")
		}
		writeNativeGoPortableFixture(t, root, private, files, journal, statement, head, sequence, repo, module, version, snapshots[0], receipt.ZIPHash, receipt.ModHash)
	}
}

// Only the dedicated GitHub-hosted fixture job may retain this synthetic input.
// The exhaustive file list excludes the signer private key, database/API tokens,
// configs, command logs and SDK caches. This is not a customer export path.
func writeNativeGoPortableFixture(t *testing.T, root, private string, files [3]string, journal, statement []byte, head crypt.JournalAnchor, sequence int64, repo, module, version string, snapshot nativeGoExportSnapshot, zipH1, modH1 string) {
	t.Helper()
	destination := filepath.Join(root, ".cache", "go-export-portable-upload")
	if os.Getenv("RUNNER_NAME") == "" || len(os.Getenv("RUNNER_NAME")) > 256 {
		t.Fatal("portable source requires the actual bounded runner identity")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("GITHUB_JOB") != "produce" || os.Getenv("CRATECTL_GO_EXPORT_PORTABLE_OUT") != destination || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || head.Tenant != "schema-team" || repo != "exported" || module != "go.cratectl.invalid/Owned/intake" || version != "v1.0.0" || len(journal) > 1<<20 {
		t.Fatal("portable fixture output is restricted to the declared owned native CI job")
	}
	data := map[string][]byte{"manifest.json": snapshot.raw, "journal.jsonl": journal, "checkpoint.json": statement}
	for n, name := range []string{"original.zip", "original.mod", "original.info", "signer-public.pem", "checkpoint.sig"} {
		path := filepath.Join(private, name)
		if n < 3 {
			path = files[n]
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(f, 4<<20+1))
		f.Close()
		if err != nil || len(raw) > 4<<20 {
			t.Fatal("portable fixture exceeds its input bound", err)
		}
		data[name] = raw
	}
	fixture := map[string]any{"profile": "cratectl.go.export.portable.fixture.v1", "candidate": os.Getenv("GITHUB_SHA"), "source_run_id": os.Getenv("GITHUB_RUN_ID"), "source_job": "produce", "source_runner_sha256": crypt.Digest([]byte(os.Getenv("RUNNER_NAME"))), "source_os": runtime.GOOS, "source_arch": runtime.GOARCH, "tenant": head.Tenant, "repository": repo, "module": module, "version": version, "export_id": snapshot.id, "created_sequence": sequence, "through": head, "zip_h1": zipH1, "mod_h1": modH1, "files": data}
	raw, err := json.Marshal(fixture)
	if err != nil || len(raw)+1 > 8<<20 {
		t.Fatal("portable fixture capsule exceeds its byte bound", err)
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal("portable output must be a new private directory", err)
	}
	f, err := os.OpenFile(filepath.Join(destination, "fixture.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write(append(raw, '\n'))
	if err := f.Sync(); writeErr == nil {
		writeErr = err
	}
	if err := f.Close(); writeErr == nil {
		writeErr = err
	}
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	folder, err := os.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	err = folder.Sync()
	folder.Close()
	if err != nil {
		t.Fatal(err)
	}
}
