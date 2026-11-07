//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

type collectionCommandOutput struct{ bytes.Buffer }

func (b *collectionCommandOutput) Write(raw []byte) (int, error) {
	if b.Len()+len(raw) > 64<<10 {
		return 0, errors.New("owned collection command output exceeded64KiB")
	}
	return b.Buffer.Write(raw)
}

// Real PG/CAS/socket/CLI/OpenSSL/stock Go. Owned faults stop the collector at a
// second-range barrier and close one import socket after its real DB commit.
func TestGoModuleExportCollectorNativeSocketKillRenewalReplayAndOffline(t *testing.T) {
	s, d, token, admin := schemaServer(t)
	// The shared schema helper deliberately caps objects at1MiB. This owned
	// transfer fixture retains its original2MiB asset and uses a separate4MiB
	// CAS; neither the shared helper nor production admission limits change.
	ownedBlobs, err := blob.New(t.TempDir(), 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	s.Blobs = ownedBlobs
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binaryDir := os.Getenv("CRATECTL_QUALIFICATION_BIN_DIR")
	if binaryDir == "" {
		t.Fatal("actual candidate CLI directory required")
	}
	if !filepath.IsAbs(binaryDir) {
		binaryDir = filepath.Join(root, binaryDir)
	}
	cli := filepath.Join(binaryDir, "cratectl")
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal("external OpenSSL required")
	}
	environment := []string{"PATH=" + os.Getenv("PATH")}
	command := func(arguments []string, env []string) (*exec.Cmd, *collectionCommandOutput, *collectionCommandOutput) {
		cmd := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
		cmd.Dir = private
		cmd.Env = append(append([]string{}, environment...), env...)
		cmd.WaitDelay = 2 * time.Second
		stdout, stderr := new(collectionCommandOutput), new(collectionCommandOutput)
		cmd.Stdout, cmd.Stderr = stdout, stderr
		return cmd, stdout, stderr
	}
	run := func(ok bool, env []string, arguments ...string) []byte {
		t.Helper()
		cmd, out, diagnostic := command(arguments, env)
		err := cmd.Run()
		if (err == nil) != ok {
			t.Fatalf("owned %s expected success=%t: %v; bounded stdout=%q stderr=%q", filepath.Base(arguments[0]), ok, err, out.Bytes(), diagnostic.Bytes())
		}
		if !ok && out.Len() != 0 {
			t.Fatal("failed collector emitted a success-shaped body")
		}
		return bytes.Clone(out.Bytes())
	}
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(private, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	mavenRepositories(t, s, admin, store.Repository{Name: "exported", Format: "go", RequireReview: true, Access: "restricted"})
	coordinate := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/app", Version: "v1.0.0"}
	// Hash-derived inert data avoids an all-compressible ZIP and requires several
	// real bounded ranges. It is never compiled or executed.
	var asset bytes.Buffer
	for n := 0; asset.Len() < 2<<20; n++ {
		asset.WriteString(crypt.Digest([]byte(fmt.Sprintf("owned-collector-asset/%d", n))))
	}
	zip, _ := goPublicationFixture(t, coordinate, asset.String())
	if len(zip) < 2*(64<<10) || len(zip) > 4<<20 {
		t.Fatal("owned ZIP does not exercise range continuation")
	}
	if response := goHTTP(t, s, token, "PUT", "/go/exported/"+coordinate.Prefix()+".zip", zip); response.Code != 201 {
		t.Fatal("actual module publication", response.Code)
	}
	artifacts := goInventory(t, s, admin, "exported")
	for _, a := range artifacts {
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, "exported", a.Path, a.Digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	req := store.GoExportRequest{Repository: "exported", Module: coordinate.Module, Version: coordinate.Version, LifetimeSeconds: 3600}
	raw, _ := json.Marshal(req)
	created := goHTTP(t, s, token, "POST", "/api/v1/go/exports", raw, "Idempotency-Key", "native-collector-export", "Content-Type", "application/json")
	var session store.GoExportSession
	if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &session) != nil {
		t.Fatal("actual export creation", created.Code)
	}
	head, err := s.DB.JournalCheckpoint(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	var journal bytes.Buffer
	query := store.JournalRange{Through: head.Sequence, ThroughHash: head.Hash, Limit: 1}
	for {
		page, err := s.DB.JournalPage(ctx, admin, query)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(&journal).Encode(page); err != nil {
			t.Fatal(err)
		}
		if !page.More {
			break
		}
		query.After, query.AfterHash = page.NextAfter, page.NextHash
	}
	statement, err := crypt.JournalCheckpointBytes(head)
	if err != nil {
		t.Fatal(err)
	}
	journalPath, statementPath := write("journal.jsonl", journal.Bytes()), write("checkpoint.json", statement)
	privateKey, publicKey, signature := filepath.Join(private, "external-private.pem"), filepath.Join(private, "external-public.pem"), filepath.Join(private, "external.sig")
	version := strings.Fields(string(run(true, nil, openssl, "version")))
	if len(version) < 2 || version[0] != "OpenSSL" || (!strings.HasPrefix(version[1], "3.") && !strings.HasPrefix(version[1], "4.")) {
		t.Fatal("qualified external OpenSSL3/4 required")
	}
	run(true, nil, openssl, "genpkey", "-algorithm", "ED25519", "-out", privateKey)
	if err := os.Chmod(privateKey, 0600); err != nil {
		t.Fatal(err)
	}
	run(true, nil, openssl, "pkey", "-in", privateKey, "-pubout", "-out", publicKey)
	run(true, nil, openssl, "pkeyutl", "-sign", "-rawin", "-inkey", privateKey, "-in", statementPath, "-out", signature)
	run(true, nil, openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", publicKey, "-in", statementPath, "-sigfile", signature)
	reached, release := make(chan struct{}), make(chan struct{})
	var barrier, lostImportResponse sync.Once
	listener, err := net.Listen("tcp4", "127.0.0.1:38443")
	if err != nil {
		t.Fatal("owned collector loopback port", err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/go/imported/") {
			dropped := false
			lostImportResponse.Do(func() {
				// Execute the real publication transaction, then deliberately close
				// its actual socket before any response reaches the CLI.
				result := httptest.NewRecorder()
				s.ServeHTTP(result, r)
				if result.Code != 201 {
					t.Errorf("owned lost-response publication returned %d", result.Code)
				}
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error("owned lost-response socket", err)
				} else {
					connection.Close()
				}
				dropped = true
			})
			if dropped {
				return
			}
		}
		if strings.HasSuffix(r.URL.Path, "/zip") && r.URL.Query().Get("generation") == "1" && r.Header.Get("Range") == "bytes=65536-131071" {
			barrier.Do(func() { close(reached) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		s.ServeHTTP(w, r)
	})
	server := httptest.NewUnstartedServer(handler)
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	tokenPath := write("admin.token", []byte(token))
	configRaw, _ := json.Marshal(configfile.Client{Version: 1, URL: server.URL, TokenFile: tokenPath})
	configPath := write("client.json", configRaw)
	output := filepath.Join(private, "collected package")
	journalArguments := []string{"--journal-file", journalPath, "--journal-tenant", admin.Tenant, "--journal-event-sequence", strconv.FormatInt(session.CreatedSequence, 10), "--journal-through", strconv.FormatInt(head.Sequence, 10), "--journal-through-hash", head.Hash, "--checkpoint-file", statementPath, "--checkpoint-signature-file", signature, "--checkpoint-key-file", publicKey}
	args := []string{cli, "go-export-collect", "--config", configPath, "--export-id", session.ID, "--generation", "1", "--repository", req.Repository, "--module", req.Module, "--version", req.Version, "--output-directory", output, "--chunk-bytes", "65536"}
	args = append(args, journalArguments...)
	child, out, diagnostic := command(args, nil)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case <-reached:
	case err := <-done:
		t.Fatalf("collector stopped before actual range barrier: %v, stdout=%q stderr=%q", err, out.Bytes(), diagnostic.Bytes())
	case <-time.After(45 * time.Second):
		child.Process.Kill()
		<-done
		t.Fatal("collector did not reach bounded range barrier")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("killed collector reported success")
	}
	close(release)
	partial, err := os.ReadFile(filepath.Join(output, "original.zip"))
	if err != nil || len(partial) != 65536 || !bytes.Equal(partial, zip[:65536]) || out.Len() != 0 {
		t.Fatal("actual process kill lost checkpoint or emitted completion", err, len(partial))
	}
	if _, err := os.Stat(filepath.Join(output, "receipt.json")); !os.IsNotExist(err) {
		t.Fatal("killed process exposed receipt")
	}
	beforeEvents := func() int {
		t.Helper()
		var count int
		if err := s.DB.Tx(ctx, admin, false, func(tx pgx.Tx) error { return tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.events`).Scan(&count) }); err != nil {
			t.Fatal(err)
		}
		return count
	}
	renewed, err := s.DB.ChangeGoExport(ctx, admin, session.ID, store.GoExportChange{Action: "renew", ExpectedGeneration: 1, ManifestSHA256: session.Manifest.Digest, LifetimeSeconds: 3600}, "native-collector-renew")
	if err != nil || renewed.Status != 200 {
		t.Fatal("actual renewal", err)
	}
	failedResume := append(append([]string{}, args...), "--resume")
	run(false, nil, failedResume...)
	resume := append(append([]string{}, failedResume...), "--generation", "2")
	count := beforeEvents()
	receipt := run(true, nil, resume...)
	var collected struct {
		CollectedGeneration int64 `json:"collected_generation"`
		BytesVerified       bool  `json:"bytes_verified"`
		Current             bool  `json:"current_registry_admission"`
		Authority           bool  `json:"checksum_authority_verified"`
		Closure             bool  `json:"dependency_closure"`
		Delivery            bool  `json:"delivery_verified"`
	}
	if json.Unmarshal(receipt, &collected) != nil || collected.CollectedGeneration != 2 || !collected.BytesVerified || collected.Current || collected.Authority || collected.Closure || collected.Delivery {
		t.Fatal("collection changed historical scope")
	}
	if again := run(true, nil, resume...); !bytes.Equal(again, receipt) || beforeEvents() != count {
		t.Fatal("completion replay changed original receipt or server journal")
	}
	// Declared filesystem crash states supplement the real process kill: an
	// interrupted JSON prefix after a newer renewal, then both post-link aliases.
	if err := os.Rename(filepath.Join(output, "receipt.json"), filepath.Join(output, "receipt.2.pending")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "receipt.2.pending"), receipt[:128], 0600); err != nil {
		t.Fatal(err)
	}
	advanced, err := s.DB.ChangeGoExport(ctx, admin, session.ID, store.GoExportChange{Action: "renew", ExpectedGeneration: 2, ManifestSHA256: session.Manifest.Digest, LifetimeSeconds: 3600}, "native-collector-metadata-renew")
	if err != nil || advanced.Status != 200 {
		t.Fatal("metadata renewal", err)
	}
	resume = append(resume, "--generation", "3")
	if recovered := run(true, nil, resume...); !bytes.Equal(recovered, receipt) {
		t.Fatal("pending completion changed its original generation or bytes")
	}
	for _, pair := range [][2]string{{"bindings.json", ".bindings.pending"}, {"receipt.json", "receipt.2.pending"}} {
		if err := os.Link(filepath.Join(output, pair[0]), filepath.Join(output, pair[1])); err != nil {
			t.Fatal(err)
		}
	}
	if recovered := run(true, nil, resume...); !bytes.Equal(recovered, receipt) {
		t.Fatal("post-link publication replay changed receipt")
	}
	otherToken, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Provision(ctx, d.OwnerDSN, "collector-other", "operator", "admin", otherToken, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	otherTokenPath := write("other.token", []byte(otherToken))
	otherConfig, _ := json.Marshal(configfile.Client{Version: 1, URL: server.URL, TokenFile: otherTokenPath})
	otherConfigPath := write("other-client.json", otherConfig)
	crossTenant := append(append([]string{}, resume...), "--config", otherConfigPath)
	run(false, nil, crossTenant...)
	for _, name := range []string{"manifest.json", "journal.jsonl", "checkpoint.json", "checkpoint.sig", "signer-public.pem", "original.zip", "original.mod", "original.info", "bindings.json", "receipt.json"} {
		st, err := os.Lstat(filepath.Join(output, name))
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
			t.Fatal("collected member is not private", name, err)
		}
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 10 {
		t.Fatal("credential/config/private key or unexpected member copied", err)
	}
	if original, _ := os.ReadFile(filepath.Join(output, "original.zip")); !bytes.Equal(original, zip) {
		t.Fatal("resumed original ZIP changed")
	}
	offline := filepath.Join(private, "offline verified")
	offlineArgs := []string{cli, "go-module-offline", "--repository", req.Repository, "--module", req.Module, "--version", req.Version, "--export-id", session.ID, "--manifest-file", filepath.Join(output, "manifest.json"), "--zip-file", filepath.Join(output, "original.zip"), "--mod-file", filepath.Join(output, "original.mod"), "--info-file", filepath.Join(output, "original.info"), "--output-directory", offline}
	// All proof bytes come from collection, but trust still selects the independent
	// original public key outside the bundle, never its adjacent key alone.
	offlineJournal := append([]string{}, journalArguments...)
	for n := 0; n < len(offlineJournal); n += 2 {
		switch offlineJournal[n] {
		case "--journal-file":
			offlineJournal[n+1] = filepath.Join(output, "journal.jsonl")
		case "--checkpoint-file":
			offlineJournal[n+1] = filepath.Join(output, "checkpoint.json")
		case "--checkpoint-signature-file":
			offlineJournal[n+1] = filepath.Join(output, "checkpoint.sig")
		}
	}
	offlineArgs = append(offlineArgs, offlineJournal...)
	offlineReceipt := run(true, nil, offlineArgs...)
	var prepared struct {
		Proxy   string `json:"goproxy"`
		ZIPHash string `json:"zip_h1"`
		ModHash string `json:"mod_h1"`
	}
	if json.Unmarshal(offlineReceipt, &prepared) != nil || prepared.Proxy == "" || !strings.HasPrefix(prepared.ZIPHash, "h1:") || !strings.HasPrefix(prepared.ModHash, "h1:") {
		t.Fatal("collected signed bytes did not prepare native proxy")
	}
	consumer := filepath.Join(private, "consumer")
	if err := os.Mkdir(consumer, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(consumer, "go.mod"), []byte("module owned.invalid/collector-consumer\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	goBinary := filepath.Join(root, ".cache/go/bin/go")
	cache := filepath.Join(consumer, "modcache")
	sdkEnv := []string{"GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOAUTH=off", "GOPROXY=" + prepared.Proxy, "GOSUMDB=off", "GONOSUMDB=*", "GONOPROXY=none", "GOVCS=*:off", "GOTELEMETRY=off", "GOMODCACHE=" + cache, "GOPATH=" + filepath.Join(consumer, "gopath"), "GOCACHE=" + filepath.Join(consumer, "buildcache")}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cleanup, goBinary, "clean", "-modcache")
		cmd.Dir = consumer
		cmd.Env = append(append([]string{}, environment...), sdkEnv...)
		cmd.WaitDelay = 2 * time.Second
		if err := cmd.Run(); err != nil {
			t.Error("native owned SDK cache cleanup failed")
		}
	})
	cmd, downloadOut, downloadErr := command([]string{goBinary, "mod", "download", "-json", req.Module + "@" + req.Version}, sdkEnv)
	cmd.Dir = consumer
	if err := cmd.Run(); err != nil {
		t.Fatalf("stock native Go download failed: %v; bounded stdout=%q stderr=%q", err, downloadOut.Bytes(), downloadErr.Bytes())
	}
	var installed struct {
		Dir      string
		Sum      string
		GoModSum string
	}
	if json.Unmarshal(downloadOut.Bytes(), &installed) != nil || installed.Sum != prepared.ZIPHash || installed.GoModSum != prepared.ModHash {
		t.Fatal("stock SDK h1 identities differ")
	}
	extracted, err := os.ReadFile(filepath.Join(installed.Dir, "assets/owned.txt"))
	if err != nil || !bytes.Equal(extracted, asset.Bytes()) {
		t.Fatal("stock SDK extracted different inert bytes", err)
	}
	// Source approval never grants destination admission. A scoped publisher
	// imports only through the existing current-authorized publication path.
	mavenRepositories(t, s, admin, store.Repository{Name: "imported", Format: "go", Access: "restricted", RequireReview: true})
	importToken, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Provision(ctx, d.OwnerDSN, admin.Tenant, "export-importer", "publisher", importToken, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	grantImport := func(allowed bool) {
		t.Helper()
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO cratectl.repository_grants(tenant,repository,actor,can_read,can_write) VALUES($1,'imported','export-importer',true,$2) ON CONFLICT(tenant,repository,actor) DO UPDATE SET can_write=$2`, admin.Tenant, allowed)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	grantImport(true)
	importConfig, _ := json.Marshal(configfile.Client{Version: 1, URL: server.URL, TokenFile: write("import.token", []byte(importToken))})
	importConfigPath := write("import-client.json", importConfig)
	importArgs := append([]string{cli, "go-export-import"}, offlineArgs[2:]...)
	importArgs = append(importArgs, "--config", importConfigPath, "--destination-repository", "imported", "--idempotency-key", "native-signed-import-v1")
	attempt := func(name string) []string {
		return append(append([]string{}, importArgs...), "--output-directory", filepath.Join(private, name))
	}
	lost := "import-lost-response"
	run(false, nil, attempt(lost)...)
	if _, err := os.Stat(filepath.Join(private, lost, "import-intent.json")); err != nil {
		t.Fatal("unconfirmed import lost its durable intent", err)
	}
	if _, err := os.Stat(filepath.Join(private, lost, "import-receipt.json")); !os.IsNotExist(err) {
		t.Fatal("unconfirmed import claimed completion")
	}
	imported := goInventory(t, s, admin, "imported")
	if len(imported) != 3 {
		t.Fatal("actual committed import did not retain all three references")
	}
	for _, a := range imported {
		if a.Decision != "unassessed" {
			t.Fatal("source approval became destination scan evidence", a.Decision)
		}
		if denied := goHTTP(t, s, token, "GET", "/go/imported/"+a.Path, nil); denied.Code != 403 {
			t.Fatal("unassessed destination content served", denied.Code)
		}
	}
	importEvents := beforeEvents()
	confirmed := run(true, nil, attempt("import-confirmed-replay")...)
	var importedReceipt struct {
		Recorded  bool `json:"destination_publication_recorded"`
		Current   bool `json:"current_registry_admission"`
		Authority bool `json:"checksum_authority_verified"`
		Closure   bool `json:"dependency_closure"`
	}
	if json.Unmarshal(confirmed, &importedReceipt) != nil || !importedReceipt.Recorded || importedReceipt.Current || importedReceipt.Authority || importedReceipt.Closure || beforeEvents() != importEvents {
		t.Fatal("destination replay changed original effect or admission scope")
	}
	grantImport(false)
	run(false, nil, attempt("import-current-grant-denied")...)
	if beforeEvents() != importEvents {
		t.Fatal("denied durable replay created an effect")
	}
	mavenRepositories(t, s, admin, store.Repository{Name: "import-conflict", Format: "go", Access: "restricted", RequireReview: true})
	conflictingZIP, _ := goPublicationFixture(t, coordinate, "different destination bytes")
	if seeded := goHTTP(t, s, token, "PUT", "/go/import-conflict/"+coordinate.Prefix()+".zip", conflictingZIP); seeded.Code != 201 {
		t.Fatal("owned conflicting destination setup", seeded.Code)
	}
	conflictBefore := beforeEvents()
	conflictArgs := append(attempt("import-coordinate-conflict"), "--config", configPath, "--destination-repository", "import-conflict", "--idempotency-key", "native-import-conflict-v1")
	run(false, nil, conflictArgs...)
	conflictAfter := goInventory(t, s, admin, "import-conflict")
	if len(conflictAfter) != 3 || beforeEvents() != conflictBefore {
		t.Fatal("conflicting import changed references or journal")
	}
	for _, a := range conflictAfter {
		if strings.HasSuffix(a.Path, ".zip") && a.Digest != crypt.Digest(conflictingZIP) {
			t.Fatal("conflicting import replaced original ZIP")
		}
	}
	// A local receipt is not allowed to invent a future completed generation.
	corrupt := bytes.Replace(receipt, []byte(`"collected_generation":2`), []byte(`"collected_generation":4`), 1)
	if bytes.Equal(corrupt, receipt) {
		t.Fatal("owned receipt generation fixture absent")
	}
	if err := os.WriteFile(filepath.Join(output, "receipt.json"), corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	run(false, nil, resume...)
	if preserved, _ := os.ReadFile(filepath.Join(output, "receipt.json")); !bytes.Equal(preserved, corrupt) {
		t.Fatal("corrupt receipt was silently replaced")
	}
	if err := os.WriteFile(filepath.Join(output, "receipt.json"), receipt, 0600); err != nil {
		t.Fatal(err)
	}
	// Current source policy and credential checks also fence completed replay.
	zipArtifact := artifacts[0]
	for _, a := range artifacts {
		if strings.HasSuffix(a.Path, ".zip") {
			zipArtifact = a
		}
	}
	decide := func(value string) {
		t.Helper()
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, "exported", zipArtifact.Path, zipArtifact.Digest, value)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	decide("denied")
	run(false, nil, resume...)
	decide("allowed")
	if replay := run(true, nil, resume...); !bytes.Equal(replay, receipt) {
		t.Fatal("policy reopening rewrote historical collection")
	}
	owner, err := pgx.Connect(ctx, d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	if _, err := owner.Exec(ctx, `UPDATE cratectl_private.tokens SET revoked=true WHERE hash=$1`, admin.CredentialHash); err != nil {
		t.Fatal(err)
	}
	run(false, nil, resume...)
	saved, err := os.ReadFile(filepath.Join(output, "receipt.json"))
	if err != nil || !bytes.Equal(saved, receipt) {
		t.Fatal("denial/revocation changed original persisted receipt", err)
	}
}

var _ io.Writer = (*collectionCommandOutput)(nil)
