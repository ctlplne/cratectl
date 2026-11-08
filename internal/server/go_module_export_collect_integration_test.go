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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/configfile"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

// Compare fixed metadata selections with the actual pinned SDK after authentic
// PostgreSQL creation, external signing and TLS collection. Replacement logical
// names deliberately disagree with physical source ordering. No package runs.
func TestGoModuleRequirementNativeReplacementAndExclusionDifferentials(t *testing.T) {
	s, _, token, admin := schemaServer(t)
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
	binaries := os.Getenv("CRATECTL_QUALIFICATION_BIN_DIR")
	if binaries == "" {
		t.Fatal("actual candidate CLI directory required")
	}
	if !filepath.IsAbs(binaries) {
		binaries = filepath.Join(root, binaries)
	}
	cli := filepath.Join(binaries, "cratectl")
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(private, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	run := func(arguments ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
		cmd.Dir, cmd.Env, cmd.WaitDelay = private, []string{"PATH=" + os.Getenv("PATH"), "HOME=" + private}, 2*time.Second
		out, diagnostic := new(collectionCommandOutput), new(collectionCommandOutput)
		cmd.Stdout, cmd.Stderr = out, diagnostic
		if err := cmd.Run(); err != nil {
			t.Fatalf("owned differential command %s: %v; bounded stdout=%q stderr=%q", filepath.Base(arguments[0]), err, out.Bytes(), diagnostic.Bytes())
		}
		return bytes.Clone(out.Bytes())
	}
	identity, err := crypt.LocalIdentity("127.0.0.1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ca, cert, key := write("server-ca.pem", []byte(identity.CA)), write("server.pem", []byte(identity.Certificate)), write("server-key.pem", []byte(identity.Key))
	listener, err := net.Listen("tcp4", "127.0.0.1:38443")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, cert, key) }()
	config, err := json.Marshal(configfile.Client{Version: 1, URL: "https://127.0.0.1:38443", TokenFile: write("admin.token", []byte(token)), CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	configPath := write("client.json", config)
	fixtures := nativeRequirementDifferentials()
	sessions := make([]store.GoRequirementExportSession, len(fixtures))
	for n, fixture := range fixtures {
		repository := "differential-" + fixture.Name
		mavenRepositories(t, s, admin, store.Repository{Name: repository, Format: "go", Access: "restricted", RequireReview: true})
		for _, input := range fixture.Inputs {
			archive := goPublicationFixtureMod(t, input.Source, "owned inert differential asset", input.Mod)
			if response := goHTTP(t, s, token, "PUT", "/go/"+repository+"/"+input.Source.Prefix()+".zip", archive); response.Code != 201 {
				t.Fatal("differential original publication", fixture.Name, input.Source, response.Code)
			}
		}
		for _, a := range goInventory(t, s, admin, repository) {
			if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
				_, err := store.Decide(ctx, tx, admin, repository, a.Path, a.Digest, "allowed")
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		request, err := json.Marshal(goRequirementRequest{Repository: repository, MainGoMod: string(fixture.Main), LifetimeSeconds: 3600, MaxArtifactBytes: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		requestPath := write(fixture.Name+"-request.json", request)
		arguments := []string{cli, "--config", configPath, "--method", "POST", "--path", "/api/v1/go/export-sets/requirements", "--body-file", requestPath,
			"--idempotency-key", "native-differential-" + fixture.Name, "--timeout", "2m", "--response-limit", "16777216", "--raw-response"}
		created := run(arguments...)
		if json.Unmarshal(created, &sessions[n]) != nil || sessions[n].Profile != store.GoRequirementExportProfile ||
			sessions[n].SourceCount != len(fixture.Inputs) || sessions[n].RootCount != len(fixture.Expected) || sessions[n].DeliveryVerified {
			t.Fatal("native differential creation changed its exact original scope", fixture.Name)
		}
		if replay := run(arguments...); !bytes.Equal(created, replay) {
			t.Fatal("native differential creation replay changed", fixture.Name)
		}
	}
	head, err := s.DB.JournalCheckpoint(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	var journal bytes.Buffer
	query := store.JournalRange{Through: head.Sequence, ThroughHash: head.Hash, Limit: 7}
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
	privateKey, publicKey, signature := filepath.Join(private, "external-private.pem"), filepath.Join(private, "independent-public.pem"), filepath.Join(private, "external.sig")
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal("external OpenSSL required")
	}
	run(openssl, "genpkey", "-algorithm", "ED25519", "-out", privateKey)
	if err := os.Chmod(privateKey, 0600); err != nil {
		t.Fatal(err)
	}
	run(openssl, "pkey", "-in", privateKey, "-pubout", "-out", publicKey)
	run(openssl, "pkeyutl", "-sign", "-rawin", "-inkey", privateKey, "-in", statementPath, "-out", signature)
	run(openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", publicKey, "-in", statementPath, "-sigfile", signature)
	values := make([]map[string]any, 0, len(fixtures))
	for n, fixture := range fixtures {
		session := sessions[n]
		collection := filepath.Join(private, fixture.Name+"-collection")
		arguments := []string{cli, "go-requirement-export-collect", "--config", configPath, "--set-id", session.ID, "--generation", "1", "--output-directory", collection,
			"--chunk-bytes", "65536", "--journal-file", journalPath, "--journal-tenant", admin.Tenant, "--journal-event-sequence", strconv.FormatInt(session.CreatedSequence, 10),
			"--journal-through", strconv.FormatInt(head.Sequence, 10), "--journal-through-hash", head.Hash, "--checkpoint-file", statementPath,
			"--checkpoint-signature-file", signature, "--checkpoint-key-file", publicKey}
		completion := run(arguments...)
		if replay := run(append(slices.Clone(arguments), "--resume")...); !bytes.Equal(completion, replay) {
			t.Fatal("native differential collection replay changed", fixture.Name)
		}
		read := func(name string) []byte {
			t.Helper()
			raw, err := os.ReadFile(filepath.Join(collection, name))
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		parent, err := store.ParseGoRequirementExportManifest(read("manifest.json"))
		if err != nil || parent.Selection.DependencyClosure || parent.Selection.ChecksumAuthority || parent.Selection.CurrentRegistryAdmission {
			t.Fatal("native differential parent changed its original scope", fixture.Name, err)
		}
		proof := read("requirements.json")
		if _, err := store.BindGoRequirementProof(parent, proof); err != nil {
			t.Fatal("logical replacement order no longer binds physical roots", fixture.Name, err)
		}
		originals := map[gomodule.Coordinate][]byte{}
		for ordinal, source := range parent.Sources {
			if _, err := store.BindGoRequirementSourceManifest(parent, ordinal, read(fmt.Sprintf("input.%04d.manifest.json", ordinal))); err != nil {
				t.Fatal(err)
			}
			originals[gomodule.Coordinate{Module: source.Module, Version: source.Version}] = read(fmt.Sprintf("input.%04d.mod", ordinal))
		}
		if !bytes.Equal(read("main.mod"), fixture.Main) || len(originals) != len(fixture.Inputs) {
			t.Fatal("native differential changed original project or metadata input count", fixture.Name)
		}
		for _, input := range fixture.Inputs {
			if !bytes.Equal(originals[input.Source], input.Mod) {
				t.Fatal("native differential changed an original metadata byte", fixture.Name, input.Source)
			}
		}
		graph, err := gomodule.VerifyRequirementProof(ctx, proof, fixture.Main, func(ctx context.Context, c gomodule.Coordinate, maximum int64) ([]byte, error) {
			raw, ok := originals[c]
			if ctx.Err() != nil || !ok || int64(len(raw)) > maximum {
				return nil, gomodule.ErrRequirementProof
			}
			return raw, nil
		}, fixture.Expected)
		if err != nil || !slices.Equal(graph.BuildList, fixture.Expected) {
			t.Fatal("native original metadata disagrees with the explicit differential oracle", fixture.Name, err)
		}
		expected := make([]map[string]string, 0, len(fixture.Expected))
		for _, selected := range fixture.Expected {
			expected = append(expected, map[string]string{"module": selected.Logical.Module, "version": selected.Logical.Version,
				"source_module": selected.Source.Module, "source_version": selected.Source.Version})
		}
		values = append(values, map[string]any{"name": fixture.Name, "set_id": session.ID, "created_sequence": session.CreatedSequence,
			"examined_sources": len(fixture.Inputs), "expected": expected, "main_sha256": crypt.Digest(fixture.Main)})
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatal("owned differential source did not stop", err)
		}
	case <-ctx.Done():
		t.Fatal("owned differential source stop timed out")
	}
	fixture, err := json.Marshal(map[string]any{"cli": cli, "go": filepath.Join(root, ".cache/go/bin/go"), "tenant": admin.Tenant, "through": head, "cases": values})
	if err != nil {
		t.Fatal(err)
	}
	write("differentials.json", fixture)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("native Python required")
	}
	if output := run(python, filepath.Join(root, "scripts/ci/go_requirement_differential_native.py"), private); !bytes.Contains(output, []byte("Requirement native replacement and exclusion differentials passed")) {
		t.Fatal("actual SDK differential helper omitted completion")
	}
}

// Actual candidate CLI over trusted TLS creates and reads the graph profile.
// This case replays original metadata without claiming signed offline collection
// or package/platform closure; those need their complete independent caller.
func TestGoModuleRequirementExportNativeTLSCLICreationReplayAndOriginalGraph(t *testing.T) {
	s, token, _, one := requirementServerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binaries := os.Getenv("CRATECTL_QUALIFICATION_BIN_DIR")
	if binaries == "" {
		t.Fatal("actual candidate CLI directory required")
	}
	if !filepath.IsAbs(binaries) {
		binaries = filepath.Join(root, binaries)
	}
	cli := filepath.Join(binaries, "cratectl")
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(private, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	identity, err := crypt.LocalIdentity("127.0.0.1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ca, cert, key := write("server-ca.pem", []byte(identity.CA)), write("server.pem", []byte(identity.Certificate)), write("server-key.pem", []byte(identity.Key))
	listener, err := net.Listen("tcp4", "127.0.0.1:38443")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	defer server.Close()
	go func() { _ = server.ServeTLS(listener, cert, key) }()
	tokenFile := write("admin.token", []byte(token))
	config, _ := json.Marshal(configfile.Client{Version: 1, URL: "https://127.0.0.1:38443", TokenFile: tokenFile, CAFile: ca})
	configPath := write("client.json", config)
	run := func(arguments ...string) []byte {
		t.Helper()
		args := append([]string{"--config", configPath, "--timeout", "2m", "--response-limit", "16777216", "--raw-response"}, arguments...)
		cmd := exec.CommandContext(ctx, cli, args...)
		cmd.Dir, cmd.Env, cmd.WaitDelay = private, []string{"PATH=" + os.Getenv("PATH"), "HOME=" + private}, 2*time.Second
		out, diagnostic := new(collectionCommandOutput), new(collectionCommandOutput)
		cmd.Stdout, cmd.Stderr = out, diagnostic
		if err := cmd.Run(); err != nil {
			t.Fatalf("owned native requirement CLI: %v; bounded stdout=%q stderr=%q", err, out.Bytes(), diagnostic.Bytes())
		}
		return bytes.Clone(out.Bytes())
	}
	main := []byte("module owned/native-main\ngo 1.27.0\nrequire " + one.Module + " " + one.Version + "\n")
	raw, _ := json.Marshal(goRequirementRequest{Repository: one.Repository, MainGoMod: string(main), LifetimeSeconds: 60, MaxArtifactBytes: 1 << 20})
	request := write("requirement-request.json", raw)
	const endpoint = "/api/v1/go/export-sets/requirements"
	args := []string{"--method", "POST", "--path", endpoint, "--body-file", request, "--idempotency-key", "native-requirement-original"}
	receipt := run(args...)
	var v store.GoRequirementExportSession
	if json.Unmarshal(receipt, &v) != nil || v.Profile != store.GoRequirementExportProfile || v.SourceCount != 1 || v.RootCount != 2 || v.DeliveryVerified {
		t.Fatal("native TLS creation lost the complete graph identity")
	}
	if repeated := run(args...); !bytes.Equal(receipt, repeated) {
		t.Fatal("native TLS CLI replay changed original receipt bytes")
	}
	path := endpoint + "/" + v.ID
	get := func(suffix string) []byte { return run("--path", path+suffix+"?generation=1") }
	parent, err := store.ParseGoRequirementExportManifest(get("/manifest"))
	if err != nil || parent.Selection.DependencyClosure || parent.Selection.ChecksumAuthority || parent.Selection.CurrentRegistryAdmission {
		t.Fatal("native graph parent changed metadata scope", err)
	}
	if _, err := store.BindGoRequirementSourceManifest(parent, 0, get("/inputs/0/manifest")); err != nil {
		t.Fatal("native source reference no longer matches original parent", err)
	}
	proof := get("/proof")
	if _, err := store.BindGoRequirementProof(parent, proof); err != nil {
		t.Fatal("native original index changed source/selection identities", err)
	}
	mainRead, sourceRead := get("/main"), get("/inputs/0/mod")
	if !bytes.Equal(main, mainRead) {
		t.Fatal("native original project bytes changed")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	coordinate := gomodule.Coordinate{Module: one.Module, Version: one.Version}
	dependency, _, _ := requirementDependencyFixture(t)
	graph, err := gomodule.VerifyRequirementProof(ctx, proof, mainRead, func(ctx context.Context, c gomodule.Coordinate, limit int64) ([]byte, error) {
		if ctx.Err() != nil || c != coordinate || int64(len(sourceRead)) > limit {
			return nil, gomodule.ErrRequirementProof
		}
		return sourceRead, nil
	}, []gomodule.GraphSelection{{Logical: coordinate, Source: coordinate}, {Logical: dependency, Source: dependency}})
	if err != nil || len(graph.BuildList) != 2 {
		t.Fatal("original metadata failed independent replay after registry shutdown", err)
	}
}

// Real PostgreSQL/TLS/CLI and an external signer authenticate the production
// creation. The separate helper runs stock Go and refusal controls in observed
// empty command networks after the source listener has stopped.
func TestGoModuleRequirementCollectionNativeSignedCompetingVersionsAndOffline(t *testing.T) {
	s, _, token, admin := schemaServer(t)
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
	binaries := os.Getenv("CRATECTL_QUALIFICATION_BIN_DIR")
	if binaries == "" {
		t.Fatal("actual candidate CLI directory required")
	}
	if !filepath.IsAbs(binaries) {
		binaries = filepath.Join(root, binaries)
	}
	cli := filepath.Join(binaries, "cratectl")
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(private, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	run := func(ok bool, arguments ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
		cmd.Dir, cmd.Env, cmd.WaitDelay = private, []string{"PATH=" + os.Getenv("PATH"), "HOME=" + private}, 2*time.Second
		out, diagnostic := new(collectionCommandOutput), new(collectionCommandOutput)
		cmd.Stdout, cmd.Stderr = out, diagnostic
		err := cmd.Run()
		if (err == nil) != ok || !ok && out.Len() != 0 {
			t.Fatalf("owned requirement command %s: %v; bounded stdout=%q stderr=%q", filepath.Base(arguments[0]), err, out.Bytes(), diagnostic.Bytes())
		}
		return bytes.Clone(out.Bytes())
	}
	mavenRepositories(t, s, admin, store.Repository{Name: "requirements", Format: "go", Access: "restricted", RequireReview: true})
	module, selector := "go.cratectl.invalid/Owned/competing", "go.cratectl.invalid/Owned/selector"
	coordinates := []gomodule.Coordinate{{Module: module, Version: "v1.0.0"}, {Module: module, Version: "v1.1.0"}, {Module: selector, Version: "v1.0.0"}}
	mods := [][]byte{[]byte("module " + module + "\ngo 1.26\n"), []byte("module " + module + "\ngo 1.26\n"), []byte("module " + selector + "\ngo 1.16\nrequire " + module + " v1.1.0\n")}
	var paddedZIP []byte
	for n, c := range coordinates {
		archive := goPublicationFixtureMod(t, c, "owned inert requirement asset", mods[n])
		if n == 1 {
			archive = goPublicationFixturePaddedMod(t, c, "owned inert requirement asset", mods[n])
			paddedZIP = bytes.Clone(archive)
		}
		if response := goHTTP(t, s, token, "PUT", "/go/requirements/"+c.Prefix()+".zip", archive); response.Code != 201 {
			t.Fatal("owned original publication", n, response.Code)
		}
	}
	for _, a := range goInventory(t, s, admin, "requirements") {
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, "requirements", a.Path, a.Digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	mainMod := []byte("module go.cratectl.invalid/owned-consumer\ngo 1.27.0\nrequire (\n" + module + " v1.0.0\n" + selector + " v1.0.0\n)\n")
	request, _ := json.Marshal(goRequirementRequest{Repository: "requirements", MainGoMod: string(mainMod), LifetimeSeconds: 3600, MaxArtifactBytes: 1 << 20})
	created := goHTTP(t, s, token, "POST", "/api/v1/go/export-sets/requirements", request, "Idempotency-Key", "owned-signed-requirement-graph")
	var session store.GoRequirementExportSession
	if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &session) != nil || session.SourceCount != 3 || session.RootCount != 2 {
		t.Fatal("competing versions did not retain all three examined originals", created.Code)
	}
	replay := goHTTP(t, s, token, "POST", "/api/v1/go/export-sets/requirements", request, "Idempotency-Key", "owned-signed-requirement-graph")
	if replay.Code != 201 || !bytes.Equal(created.Body.Bytes(), replay.Body.Bytes()) {
		t.Fatal("signed original creation replay changed")
	}
	planned := goHTTP(t, s, token, "GET", "/api/v1/go/export-sets/requirements/"+session.ID+"/manifest?generation=1", nil)
	planParent, err := store.ParseGoRequirementExportManifest(planned.Body.Bytes())
	if planned.Code != 200 || err != nil || len(paddedZIP) <= 2*65536 || len(planParent.Selection.Entries) != 2 || planParent.Selection.Entries[0].Module != module || planParent.Selection.Entries[0].Version != "v1.1.0" {
		t.Fatal("actual selected ZIP no longer reaches the second-range barrier", planned.Code, err)
	}
	head, err := s.DB.JournalCheckpoint(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	var journal bytes.Buffer
	query := store.JournalRange{Through: head.Sequence, ThroughHash: head.Hash, Limit: 7}
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
	privateKey, publicKey, signature := filepath.Join(private, "external-private.pem"), filepath.Join(private, "independent-public.pem"), filepath.Join(private, "external.sig")
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal("external OpenSSL required")
	}
	run(true, openssl, "genpkey", "-algorithm", "ED25519", "-out", privateKey)
	if err := os.Chmod(privateKey, 0600); err != nil {
		t.Fatal(err)
	}
	run(true, openssl, "pkey", "-in", privateKey, "-pubout", "-out", publicKey)
	run(true, openssl, "pkeyutl", "-sign", "-rawin", "-inkey", privateKey, "-in", statementPath, "-out", signature)
	run(true, openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", publicKey, "-in", statementPath, "-sigfile", signature)
	otherPrivate := filepath.Join(private, "unrelated-private.pem")
	run(true, openssl, "genpkey", "-algorithm", "ED25519", "-out", otherPrivate)
	if err := os.Chmod(otherPrivate, 0600); err != nil {
		t.Fatal(err)
	}
	run(true, openssl, "pkey", "-in", otherPrivate, "-pubout", "-out", filepath.Join(private, "unrelated-public.pem"))
	identity, err := crypt.LocalIdentity("127.0.0.1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ca, cert, key := write("server-ca.pem", []byte(identity.CA)), write("server.pem", []byte(identity.Certificate)), write("server-key.pem", []byte(identity.Key))
	listener, err := net.Listen("tcp4", "127.0.0.1:38443")
	if err != nil {
		t.Fatal(err)
	}
	reached, release := make(chan struct{}), make(chan struct{})
	var reachedOnce, releaseOnce sync.Once
	var barrierActive atomic.Bool
	defer releaseOnce.Do(func() { close(release) })
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if barrierActive.Load() && r.URL.Path == "/api/v1/go/export-sets/"+session.ID+"/roots/0/zip" && r.URL.Query().Get("generation") == "1" && r.Header.Get("Range") == "bytes=65536-131071" {
			reachedOnce.Do(func() { close(reached) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		s.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, cert, key) }()
	config, _ := json.Marshal(configfile.Client{Version: 1, URL: "https://127.0.0.1:38443", TokenFile: write("admin.token", []byte(token)), CAFile: ca})
	configPath := write("client.json", config)
	collection := filepath.Join(private, "collection")
	arguments := []string{cli, "go-requirement-export-collect", "--config", configPath, "--set-id", session.ID, "--generation", "1", "--output-directory", collection, "--chunk-bytes", "65536", "--journal-file", journalPath, "--journal-tenant", admin.Tenant, "--journal-event-sequence", strconv.FormatInt(session.CreatedSequence, 10), "--journal-through", strconv.FormatInt(head.Sequence, 10), "--journal-through-hash", head.Hash, "--checkpoint-file", statementPath, "--checkpoint-signature-file", signature, "--checkpoint-key-file", publicKey}
	barrierActive.Store(true)
	child := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	child.Dir, child.Env, child.WaitDelay = private, []string{"PATH=" + os.Getenv("PATH"), "HOME=" + private}, 2*time.Second
	childOut, childDiagnostic := new(collectionCommandOutput), new(collectionCommandOutput)
	child.Stdout, child.Stderr = childOut, childDiagnostic
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	childDone, reaped := make(chan error, 1), false
	go func() { childDone <- child.Wait() }()
	defer func() {
		if !reaped {
			_ = child.Process.Kill()
			<-childDone
		}
	}()
	select {
	case <-reached:
	case err := <-childDone:
		reaped = true
		t.Fatalf("requirement collector exited before second range: %v; bounded stdout=%q stderr=%q", err, childOut.Bytes(), childDiagnostic.Bytes())
	case <-ctx.Done():
		t.Fatal("owned requirement collector barrier timed out")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = <-childDone
	reaped = true
	if err == nil || childOut.Len() != 0 {
		t.Fatal("killed requirement collector reported completion", err)
	}
	barrierActive.Store(false)
	releaseOnce.Do(func() { close(release) })
	partial := filepath.Join(collection, "root.000.zip")
	prefix, err := os.ReadFile(partial)
	if err != nil || len(prefix) != 65536 || !bytes.Equal(prefix, paddedZIP[:65536]) {
		t.Fatal("owned collector kill lost the exact synced first range", err)
	}
	if _, err := os.Stat(filepath.Join(collection, "receipt.json")); !os.IsNotExist(err) {
		t.Fatal("killed requirement collector published completion")
	}
	renew := store.GoExportChange{Action: "renew", ExpectedGeneration: 1, LifetimeSeconds: 3600, ManifestSHA256: session.SelectionManifest.Digest}
	renewBody, _ := json.Marshal(renew)
	if response := goHTTP(t, s, token, "POST", "/api/v1/go/export-sets/"+session.ID+"/control", renewBody, "Idempotency-Key", "owned-requirement-renew-after-kill"); response.Code != 200 {
		t.Fatal("requirement renewal after actual collector kill", response.Code)
	}
	run(false, append(append([]string{}, arguments...), "--resume")...)
	if saved, err := os.ReadFile(partial); err != nil || !bytes.Equal(saved, prefix) {
		t.Fatal("stale-generation refusal changed retained prefix", err)
	}
	resumed := append(append([]string{}, arguments...), "--generation", "2", "--resume")
	corrupt := bytes.Clone(prefix)
	corrupt[len(corrupt)/2] ^= 1
	if err := os.WriteFile(partial, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	run(false, resumed...)
	if saved, err := os.ReadFile(partial); err != nil || !bytes.Equal(saved, corrupt) {
		t.Fatal("corrupt requirement prefix was extended or repaired", err)
	}
	if _, err := os.Stat(filepath.Join(collection, "receipt.json")); !os.IsNotExist(err) {
		t.Fatal("corrupt requirement prefix published completion")
	}
	// Only this owned test restores the intentionally corrupted original prefix.
	if err := os.WriteFile(partial, prefix, 0600); err != nil {
		t.Fatal(err)
	}
	completion := run(true, resumed...)
	var completionStatus struct {
		Generation int64 `json:"collected_generation"`
		Verified   bool  `json:"bytes_verified"`
		Inputs     bool  `json:"original_inputs_complete"`
		Replayed   bool  `json:"requirements_replayed"`
	}
	if json.Unmarshal(completion, &completionStatus) != nil || completionStatus.Generation != 2 || !completionStatus.Verified || !completionStatus.Inputs || !completionStatus.Replayed {
		t.Fatal("resumed requirement collector lost original completion scope")
	}
	if repeated := run(true, resumed...); !bytes.Equal(completion, repeated) {
		t.Fatal("complete requirement collection replay changed original receipt")
	}
	renew.ExpectedGeneration = 2
	renewBody, _ = json.Marshal(renew)
	if response := goHTTP(t, s, token, "POST", "/api/v1/go/export-sets/"+session.ID+"/control", renewBody, "Idempotency-Key", "owned-requirement-renew-complete"); response.Code != 200 {
		t.Fatal("requirement renewal after complete collection", response.Code)
	}
	currentResume := append(append([]string{}, resumed...), "--generation", "3")
	if repeated := run(true, currentResume...); !bytes.Equal(completion, repeated) {
		t.Fatal("renewed requirement collector rewrote original generation2 completion")
	}
	parentRaw, err := os.ReadFile(filepath.Join(collection, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := store.ParseGoRequirementExportManifest(parentRaw)
	if err != nil || len(parent.Sources) != 3 || len(parent.Selection.Entries) != 2 {
		t.Fatal("complete collection lost original graph", err)
	}
	lowerInput := ""
	for n, source := range parent.Sources {
		if source.Module == module && source.Version == "v1.0.0" {
			lowerInput = fmt.Sprintf("input.%04d.mod", n)
		}
	}
	if lowerInput == "" {
		t.Fatal("unselected original missing from complete collection")
	}
	for _, a := range goInventory(t, s, admin, "requirements") {
		if a.Path != coordinates[0].Prefix()+".mod" {
			continue
		}
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, "requirements", a.Path, a.Digest, "denied")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	run(false, currentResume...)
	if saved, err := os.ReadFile(filepath.Join(collection, "receipt.json")); err != nil || !bytes.Equal(saved, completion) {
		t.Fatal("current denial rewrote retained historical collection")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatal("owned requirement source did not stop", err)
		}
	case <-ctx.Done():
		t.Fatal("owned requirement source stop timed out")
	}
	fixture, _ := json.Marshal(map[string]any{"cli": cli, "go": filepath.Join(root, ".cache/go/bin/go"), "set_id": session.ID, "tenant": admin.Tenant, "created_sequence": session.CreatedSequence, "through": head, "module": module, "selector": selector, "lower_input": lowerInput})
	write("fixture.json", fixture)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("native Python required")
	}
	if output := run(true, python, filepath.Join(root, "scripts/ci/go_requirement_offline_native.py"), private); !bytes.Contains(output, []byte("Requirement offline native competing versions")) {
		t.Fatal("native requirement journey omitted completion")
	}
	writeNativeGoRequirementPortableFixture(t, root, collection, session, head, module, selector, lowerInput)
}

// Real PostgreSQL/common snapshot/TLS collection/external signer, followed by
// actual pinned stock Go inert downloads with the registry listener stopped.
// The child records its empty network namespace before every offline command.
func TestGoModuleCommonSetOfflineNativeGraphAndUncertainAcknowledgement(t *testing.T) {
	s, _, token, admin := schemaServer(t)
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
	binaries := os.Getenv("CRATECTL_QUALIFICATION_BIN_DIR")
	if binaries == "" {
		t.Fatal("actual candidate CLI directory required")
	}
	if !filepath.IsAbs(binaries) {
		binaries = filepath.Join(root, binaries)
	}
	cli := filepath.Join(binaries, "cratectl")
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(private, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	run := func(arguments ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
		cmd.Dir = private
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + private}
		cmd.WaitDelay = 2 * time.Second
		out, diagnostic := new(collectionCommandOutput), new(collectionCommandOutput)
		cmd.Stdout, cmd.Stderr = out, diagnostic
		if err := cmd.Run(); err != nil {
			t.Fatalf("owned native %s: %v; bounded stdout=%q stderr=%q", filepath.Base(arguments[0]), err, out.Bytes(), diagnostic.Bytes())
		}
		return bytes.Clone(out.Bytes())
	}
	mavenRepositories(t, s, admin, store.Repository{Name: "graph", Format: "go", Access: "restricted", RequireReview: true})
	modules := make([]string, 8)
	for n := range modules {
		// Long canonical names make the final completion exceed4096bytes, which
		// provides a deterministic kernel acknowledgement barrier in the child.
		modules[n] = "go.cratectl.invalid/Owned/" + strings.Repeat("a", 100) + "/" + strings.Repeat("b", 100) + "/" + strings.Repeat("c", 100) + fmt.Sprintf("/node%d", n)
	}
	selection := store.GoExportSetRequest{LifetimeSeconds: 3600, MaxArtifactBytes: 32 << 20}
	for n, name := range modules {
		coordinate := gomodule.Coordinate{Module: name, Version: "v1.0.0"}
		archive := nativeCommonGraphZIP(t, modules, n)
		if response := goHTTP(t, s, token, "PUT", "/go/graph/"+coordinate.Prefix()+".zip", archive); response.Code != 201 {
			t.Fatal("owned graph publication", n, response.Code)
		}
	}
	for _, a := range goInventory(t, s, admin, "graph") {
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, "graph", a.Path, a.Digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Derive the selected modules from the actual authorized .mod bytes. The
	// stock SDK below independently downloads exactly this selected set; the
	// complete common snapshot still checks every final ZIP/mod/info and grant.
	// This is metadata graph selection, not package/platform closure admission.
	mainMod := []byte("module go.cratectl.invalid/owned-consumer\n\ngo 1.27.0\nrequire " + modules[0] + " v1.0.0\n")
	graph, err := gomodule.ResolveRequirements(ctx, mainMod, func(ctx context.Context, c gomodule.Coordinate, maximum int64) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		response := goHTTP(t, s, token, "GET", "/go/graph/"+c.Prefix()+".mod", nil)
		if response.Code != 200 || int64(response.Body.Len()) > maximum {
			return nil, errors.New("owned dependency metadata unavailable under current policy or budget")
		}
		return bytes.Clone(response.Body.Bytes()), nil
	}, gomodule.DefaultGraphLimits())
	if err != nil || graph == nil || !graph.Pruned || len(graph.BuildList) != len(modules) || len(graph.Inputs) != 1 {
		t.Fatal("owned automatic graph selection differs from modern requirements", graph, err)
	}
	for n, member := range graph.BuildList {
		if member.Logical != member.Source || member.Logical.Module != modules[n] || member.Logical.Version != "v1.0.0" {
			t.Fatal("automatic selection changed the fixed owned native graph", n)
		}
		selection.Entries = append(selection.Entries, store.GoExportSetEntry{Repository: "graph", Module: member.Source.Module, Version: member.Source.Version})
	}
	body, _ := json.Marshal(selection)
	created := goHTTP(t, s, token, "POST", "/api/v1/go/export-sets", body, "Idempotency-Key", "owned-complete-native-graph")
	var session store.GoExportSetSession
	if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &session) != nil || session.RootCount != 8 {
		t.Fatal("owned common graph creation", created.Code)
	}
	head, err := s.DB.JournalCheckpoint(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	var journal bytes.Buffer
	query := store.JournalRange{Through: head.Sequence, ThroughHash: head.Hash, Limit: 7}
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
	privateKey, publicKey, signature := filepath.Join(private, "external-private.pem"), filepath.Join(private, "independent-public.pem"), filepath.Join(private, "external.sig")
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal("external OpenSSL required")
	}
	run(openssl, "genpkey", "-algorithm", "ED25519", "-out", privateKey)
	if err := os.Chmod(privateKey, 0600); err != nil {
		t.Fatal(err)
	}
	run(openssl, "pkey", "-in", privateKey, "-pubout", "-out", publicKey)
	run(openssl, "pkeyutl", "-sign", "-rawin", "-inkey", privateKey, "-in", statementPath, "-out", signature)
	run(openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", publicKey, "-in", statementPath, "-sigfile", signature)
	identity, err := crypt.LocalIdentity("127.0.0.1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ca, cert, key := write("server-ca.pem", []byte(identity.CA)), write("server.pem", []byte(identity.Certificate)), write("server-key.pem", []byte(identity.Key))
	listener, err := net.Listen("tcp", "127.0.0.1:38443")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, cert, key) }()
	tokenFile := write("admin.token", []byte(token))
	config, _ := json.Marshal(configfile.Client{Version: 1, URL: "https://127.0.0.1:38443", TokenFile: tokenFile, CAFile: ca})
	configPath := write("client.json", config)
	previewRequest, _ := json.Marshal(goRequirementRequest{Repository: "graph", MainGoMod: string(mainMod),
		LifetimeSeconds: selection.LifetimeSeconds, MaxArtifactBytes: selection.MaxArtifactBytes})
	previewRaw := run(cli, "--config", configPath, "--method", "POST", "--path", "/api/v1/go/export-sets/requirements/preview",
		"--body-file", write("requirement-preview-request.json", previewRequest), "--timeout", "2m", "--response-limit", "16777216", "--raw-response")
	var preview struct {
		Selection   store.GoExportSetRequest `json:"selection"`
		Revalidated bool                     `json:"metadata_inputs_revalidated"`
		Closure     bool                     `json:"dependency_closure"`
		Durable     bool                     `json:"durable_session_created"`
	}
	if json.Unmarshal(previewRaw, &preview) != nil || !preview.Revalidated || preview.Closure || preview.Durable {
		t.Fatal("actual TLS CLI requirement preview lost its bounded metadata scope")
	}
	previewSelection, _ := json.Marshal(preview.Selection)
	if !bytes.Equal(previewSelection, body) {
		t.Fatal("actual CLI/API and stock-SDK fixture derived different selections")
	}
	if afterPreview, err := s.DB.JournalCheckpoint(ctx, admin); err != nil || afterPreview != head {
		t.Fatal("actual CLI requirement preview mutated its source journal", err)
	}
	run(cli, "go-export-set-collect", "--config", configPath, "--set-id", session.ID, "--generation", "1", "--output-directory", filepath.Join(private, "collection"), "--journal-file", journalPath, "--journal-tenant", admin.Tenant, "--journal-event-sequence", strconv.FormatInt(session.CreatedSequence, 10), "--journal-through", strconv.FormatInt(head.Sequence, 10), "--journal-through-hash", head.Hash, "--checkpoint-file", statementPath, "--checkpoint-signature-file", signature, "--checkpoint-key-file", publicKey)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatal("owned registry did not close", err)
		}
	case <-ctx.Done():
		t.Fatal("owned registry stop timed out")
	}
	writeNativeGoCommonPortableFixture(t, root, filepath.Join(private, "collection"), session, head, modules[0])
	fixture, _ := json.Marshal(map[string]any{"cli": cli, "go": filepath.Join(root, ".cache/go/bin/go"), "set_id": session.ID, "tenant": admin.Tenant, "created_sequence": session.CreatedSequence, "through": head, "root_module": modules[0]})
	write("fixture.json", fixture)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("native Python required")
	}
	result := run(python, filepath.Join(root, "scripts/ci/go_set_offline_native.py"), private)
	if !bytes.Contains(result, []byte("Common-set offline native graph")) {
		t.Fatal("native graph journey omitted its completion")
	}
}

type collectionCommandOutput struct{ bytes.Buffer }

func (b *collectionCommandOutput) Write(raw []byte) (int, error) {
	if b.Len()+len(raw) > 64<<10 {
		return 0, errors.New("owned collection command output exceeded64KiB")
	}
	return b.Buffer.Write(raw)
}

// Real PG/CAS/TLS/socket/CLI/OpenSSL/stock Go. Owned faults stop the collector
// at a second-range barrier and close one import socket after its real DB commit.
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
	// A second original export is independent historical selection, not a claim
	// of one atomic server snapshot or dependency closure. It uses another owned
	// repository so the original collector/import fixture and assertions remain.
	mavenRepositories(t, s, admin, store.Repository{Name: "index-extra", Format: "go", RequireReview: true, Access: "restricted"})
	indexCoordinate := gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/index-extra", Version: "v1.0.0"}
	indexZIP, _ := goPublicationFixture(t, indexCoordinate, "owned inert index-only asset")
	if response := goHTTP(t, s, token, "PUT", "/go/index-extra/"+indexCoordinate.Prefix()+".zip", indexZIP); response.Code != 201 {
		t.Fatal("second index publication", response.Code)
	}
	for _, a := range goInventory(t, s, admin, "index-extra") {
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, "index-extra", a.Path, a.Digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	indexRequest, _ := json.Marshal(store.GoExportRequest{Repository: "index-extra", Module: indexCoordinate.Module, Version: indexCoordinate.Version, LifetimeSeconds: 3600})
	indexCreated := goHTTP(t, s, token, "POST", "/api/v1/go/exports", indexRequest, "Idempotency-Key", "native-index-extra-export", "Content-Type", "application/json")
	var indexSession store.GoExportSession
	if indexCreated.Code != 201 || json.Unmarshal(indexCreated.Body.Bytes(), &indexSession) != nil {
		t.Fatal("second index export", indexCreated.Code)
	}
	indexManifests := map[string][]byte{}
	for name, v := range map[string]store.GoExportSession{"index-primary-manifest.json": session, "index-extra-manifest.json": indexSession} {
		response := goHTTP(t, s, token, "GET", "/api/v1/go/exports/"+v.ID+"/manifest?generation=1", nil)
		if response.Code != 200 || crypt.Digest(response.Body.Bytes()) != v.Manifest.Digest {
			t.Fatal("actual index manifest", response.Code)
		}
		indexManifests[name] = bytes.Clone(response.Body.Bytes())
		write(name, response.Body.Bytes())
	}

	// A common set is a distinct single fenced transaction over both originals.
	// Existing independent-export collector/index assertions below stay intact.
	setRequest := store.GoExportSetRequest{Entries: []store.GoExportSetEntry{
		{Repository: req.Repository, Module: req.Module, Version: req.Version},
		{Repository: "index-extra", Module: indexCoordinate.Module, Version: indexCoordinate.Version},
	}, LifetimeSeconds: 3600, MaxArtifactBytes: 1 << 30}
	setBody, _ := json.Marshal(setRequest)
	setCreated := goHTTP(t, s, token, "POST", "/api/v1/go/export-sets", setBody, "Idempotency-Key", "native-common-export-set")
	var commonSession store.GoExportSetSession
	if setCreated.Code != 201 || json.Unmarshal(setCreated.Body.Bytes(), &commonSession) != nil || commonSession.RootCount != 2 {
		t.Fatal("actual common-set creation", setCreated.Code)
	}
	commonResponse := goHTTP(t, s, token, "GET", "/api/v1/go/export-sets/"+commonSession.ID+"/manifest?generation=1", nil)
	commonManifest, err := store.ParseGoExportSetManifest(commonResponse.Body.Bytes())
	if commonResponse.Code != 200 || err != nil || crypt.Digest(commonResponse.Body.Bytes()) != commonSession.Manifest.Digest || len(commonManifest.Entries) != 2 {
		t.Fatal("actual complete common manifest", commonResponse.Code, err)
	}
	commonManifestPath := write("common-manifest.json", commonResponse.Body.Bytes())
	head, err := s.DB.JournalCheckpoint(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	var journal bytes.Buffer
	selectedOriginals := make(map[int64]crypt.JournalEvent)
	query := store.JournalRange{Through: head.Sequence, ThroughHash: head.Hash, Limit: 1}
	for {
		page, err := s.DB.JournalPage(ctx, admin, query)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(&journal).Encode(page); err != nil {
			t.Fatal(err)
		}
		for _, event := range page.Items {
			if event.Sequence == 1 || event.Sequence == session.CreatedSequence {
				selectedOriginals[event.Sequence] = event
			}
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

	commonArguments := []string{cli, "go-export-set-verify", "--manifest-file", commonManifestPath, "--set-id", commonSession.ID, "--journal-file", journalPath, "--journal-tenant", admin.Tenant, "--journal-event-sequence", strconv.FormatInt(commonSession.CreatedSequence, 10), "--journal-through", strconv.FormatInt(head.Sequence, 10), "--journal-through-hash", head.Hash, "--checkpoint-file", statementPath, "--checkpoint-signature-file", signature, "--checkpoint-key-file", publicKey}
	commonResult := run(true, nil, commonArguments...)
	var commonReceipt struct {
		Profile               string `json:"profile"`
		SetID                 string `json:"set_id"`
		ManifestSHA256        string `json:"manifest_sha256"`
		ManifestBytes         int    `json:"manifest_bytes"`
		Roots                 int    `json:"roots"`
		DeclaredArtifactBytes int64  `json:"declared_artifact_bytes"`
		Attribution           struct {
			EventSequence       int64                               `json:"event_sequence"`
			CheckpointSignature crypt.JournalCheckpointVerification `json:"checkpoint_signature"`
			Journal             crypt.JournalVerification           `json:"journal"`
		} `json:"attribution"`
		Bound bool `json:"common_snapshot_manifest_bound"`
	}
	if json.Unmarshal(commonResult, &commonReceipt) != nil || commonReceipt.Profile != "cratectl.go.export-set.binding.v1" || commonReceipt.SetID != commonSession.ID || commonReceipt.ManifestSHA256 != commonSession.Manifest.Digest || commonReceipt.ManifestBytes != int(commonSession.Manifest.Size) || commonReceipt.Roots != 2 || commonReceipt.DeclaredArtifactBytes != commonManifest.DeclaredArtifactBytes || !commonReceipt.Bound || commonReceipt.Attribution.EventSequence != commonSession.CreatedSequence || !commonReceipt.Attribution.CheckpointSignature.SignatureVerified || commonReceipt.Attribution.Journal.ExportSHA256 != crypt.Digest(journal.Bytes()) {
		t.Fatal("actual common creation/signer/journal binding failed")
	}
	var commonFields map[string]json.RawMessage
	if json.Unmarshal(commonResult, &commonFields) != nil {
		t.Fatal("common receipt shape")
	}
	for _, name := range []string{"artifact_bytes_verified", "dependency_closure", "checksum_authority_verified", "current_registry_admission"} {
		if !bytes.Equal(commonFields[name], []byte("false")) {
			t.Fatal("common receipt supplied unsupported trust", name)
		}
	}
	if bytes.Contains(commonResult, []byte(private)) || bytes.Contains(commonResult, []byte(`"metadata"`)) {
		t.Fatal("common verification leaked private path/policy")
	}
	run(false, nil, append(commonArguments, "--set-id", strings.Repeat("b", 64))...)
	run(false, nil, append(commonArguments, "--journal-event-sequence", strconv.FormatInt(session.CreatedSequence, 10))...)
	changedCommon, err := store.ParseGoExportSetManifest(commonResponse.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	changedCommon.Entries[1].Artifacts[0].DecisionVersion++
	changedRaw, err := changedCommon.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	changedCommonPath := write("common-changed-late-member.json", changedRaw)
	run(false, nil, append(commonArguments, "--manifest-file", changedCommonPath)...)
	// Retain and independently verify the original complete proof after a late
	// trailing frame; no command may emit a partial successful binding.
	commonTrailing := write("common-trailing-journal.jsonl", append(bytes.Clone(journal.Bytes()), []byte("{}\n")...))
	run(false, nil, append(commonArguments, "--journal-file", commonTrailing)...)
	// Select in reverse history order from the complete, externally signed real
	// journal. Summaries identify exact original payload bytes without printing
	// those tenant payloads; a late trailing frame must discard both selections.
	if session.CreatedSequence <= 1 || len(selectedOriginals) != 2 {
		t.Fatal("owned publication/export journal needs two distinct originals")
	}
	selectionArguments := []string{cli, "journal-verify", "--export-file", journalPath, "--tenant", admin.Tenant, "--through", strconv.FormatInt(head.Sequence, 10), "--through-hash", head.Hash, "--select-event", strconv.FormatInt(session.CreatedSequence, 10), "--select-event", "1", "--checkpoint-file", statementPath, "--checkpoint-signature-file", signature, "--checkpoint-key-file", publicKey}
	selectedReceipt := run(true, nil, selectionArguments...)
	var selection struct {
		crypt.JournalVerification
		CheckpointSignature *crypt.JournalCheckpointVerification `json:"checkpoint_signature"`
		SelectedEvents      []map[string]json.RawMessage         `json:"selected_events"`
	}
	if json.Unmarshal(selectedReceipt, &selection) != nil || !selection.MatchesSuppliedCheckpoint || selection.ExportSHA256 != crypt.Digest(journal.Bytes()) || selection.CheckpointSignature == nil || !selection.CheckpointSignature.SignatureVerified || len(selection.SelectedEvents) != 2 {
		t.Fatal("actual signed multiple-event CLI verification failed")
	}
	for n, sequence := range []int64{session.CreatedSequence, 1} {
		event := selectedOriginals[sequence]
		expected, _ := json.Marshal(map[string]any{"sequence": event.Sequence, "hash": event.Hash, "previous_hash": event.PreviousHash, "payload_bytes": len(event.Payload), "payload_sha256": crypt.Digest([]byte(event.Payload))})
		observed, _ := json.Marshal(selection.SelectedEvents[n])
		if !bytes.Equal(expected, observed) || len(selection.SelectedEvents[n]) != 5 {
			t.Fatal("selected original identity/order changed or payload leaked")
		}
	}
	trailingPath := write("journal-trailing.jsonl", append(bytes.Clone(journal.Bytes()), []byte("{}\n")...))
	run(false, nil, append(selectionArguments, "--export-file", trailingPath)...)
	// Verify both original manifests in reverse creation order after one full
	// signed journal pass. No private paths, policy body or package-byte claim.
	indexEntries := []map[string]any{
		{"repository": "index-extra", "module": indexCoordinate.Module, "version": indexCoordinate.Version, "export_id": indexSession.ID, "event_sequence": indexSession.CreatedSequence, "manifest_file": filepath.Join(private, "index-extra-manifest.json")},
		{"repository": req.Repository, "module": req.Module, "version": req.Version, "export_id": session.ID, "event_sequence": session.CreatedSequence, "manifest_file": filepath.Join(private, "index-primary-manifest.json")},
	}
	encodeIndex := func(entries []map[string]any) []byte {
		// Use exact typed-field order; map order is not the canonical CLI profile.
		type member struct {
			Repository    string `json:"repository"`
			Module        string `json:"module"`
			Version       string `json:"version"`
			ExportID      string `json:"export_id"`
			EventSequence int64  `json:"event_sequence"`
			ManifestFile  string `json:"manifest_file"`
		}
		index := struct {
			Profile string   `json:"profile"`
			Entries []member `json:"entries"`
		}{Profile: "cratectl.go.export.index.v1"}
		for _, entry := range entries {
			index.Entries = append(index.Entries, member{entry["repository"].(string), entry["module"].(string), entry["version"].(string), entry["export_id"].(string), entry["event_sequence"].(int64), entry["manifest_file"].(string)})
		}
		raw, err := json.Marshal(index)
		if err != nil {
			t.Fatal(err)
		}
		return append(raw, '\n')
	}
	indexPath := write("export-index.json", encodeIndex(indexEntries))
	indexArguments := []string{cli, "go-export-index-verify", "--index-file", indexPath, "--journal-file", journalPath, "--journal-tenant", admin.Tenant, "--journal-through", strconv.FormatInt(head.Sequence, 10), "--journal-through-hash", head.Hash, "--checkpoint-file", statementPath, "--checkpoint-signature-file", signature, "--checkpoint-key-file", publicKey}
	indexResult := run(true, nil, indexArguments...)
	var indexReceipt struct {
		Profile     string                               `json:"profile"`
		IndexSHA256 string                               `json:"index_sha256"`
		Journal     crypt.JournalVerification            `json:"journal"`
		Signature   *crypt.JournalCheckpointVerification `json:"checkpoint_signature"`
		Bindings    []struct {
			ExportID       string `json:"export_id"`
			EventSequence  int64  `json:"event_sequence"`
			ManifestSHA256 string `json:"manifest_sha256"`
		} `json:"bindings"`
		DeclaredArtifactBytes int64 `json:"declared_artifact_bytes"`
	}
	if json.Unmarshal(indexResult, &indexReceipt) != nil || indexReceipt.Profile != "cratectl.go.export.index.v1" || indexReceipt.IndexSHA256 != crypt.Digest(encodeIndex(indexEntries)) || !indexReceipt.Journal.MatchesSuppliedCheckpoint || indexReceipt.Journal.ExportSHA256 != crypt.Digest(journal.Bytes()) || indexReceipt.Signature == nil || !indexReceipt.Signature.SignatureVerified || len(indexReceipt.Bindings) != 2 || indexReceipt.DeclaredArtifactBytes < 1 {
		t.Fatal("actual index receipt missing")
	}
	for n, v := range []store.GoExportSession{indexSession, session} {
		if indexReceipt.Bindings[n].ExportID != v.ID || indexReceipt.Bindings[n].EventSequence != v.CreatedSequence || indexReceipt.Bindings[n].ManifestSHA256 != v.Manifest.Digest {
			t.Fatal("index original order/binding changed")
		}
	}
	var indexFields map[string]json.RawMessage
	if json.Unmarshal(indexResult, &indexFields) != nil {
		t.Fatal("index receipt JSON")
	}
	for _, name := range []string{"artifact_bytes_verified", "dependency_closure", "consistent_server_snapshot", "current_registry_admission", "checksum_authority_verified"} {
		if !bytes.Equal(indexFields[name], []byte("false")) {
			t.Fatal("index supplied unsupported trust", name)
		}
	}
	if bytes.Contains(indexResult, []byte(private)) || bytes.Contains(indexResult, []byte(`"metadata"`)) {
		t.Fatal("index leaked private source path/policy")
	}
	run(false, nil, append(indexArguments, "--journal-file", trailingPath)...)
	run(false, nil, append(indexArguments, "--max-artifact-bytes", strconv.FormatInt(indexReceipt.DeclaredArtifactBytes-1, 10))...)
	changedLast := make([]map[string]any, 2)
	for n, row := range indexEntries {
		changedLast[n] = map[string]any{}
		for key, value := range row {
			changedLast[n][key] = value
		}
	}
	changedLast[1]["manifest_file"] = write("index-changed-last.json", append(bytes.Clone(indexManifests["index-primary-manifest.json"]), []byte("{}")...))
	run(false, nil, append(indexArguments, "--index-file", write("index-changed.json", encodeIndex(changedLast)))...)
	commonReached, commonRelease := make(chan struct{}), make(chan struct{})
	commonLateReached, commonLateRelease := make(chan struct{}), make(chan struct{})
	var commonTransferBarrier, commonLateBarrier sync.Once
	var commonTransferActive, commonLateActive atomic.Bool
	reached, release := make(chan struct{}), make(chan struct{})
	var barrier, lostImportResponse sync.Once
	var applicationRequests atomic.Int64
	listener, err := net.Listen("tcp4", "127.0.0.1:38443")
	if err != nil {
		t.Fatal("owned collector loopback port", err)
	}
	defer listener.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applicationRequests.Add(1)
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
		if commonTransferActive.Load() && r.URL.Path == "/api/v1/go/export-sets/"+commonSession.ID+"/roots/0/zip" && r.URL.Query().Get("generation") == "1" && r.Header.Get("Range") == "bytes=65536-131071" {
			commonTransferBarrier.Do(func() { close(commonReached) })
			select {
			case <-commonRelease:
			case <-r.Context().Done():
				return
			}
		}
		if commonLateActive.Load() && r.URL.Path == "/api/v1/go/export-sets/"+commonSession.ID+"/roots/1/zip" && r.Method == "GET" {
			commonLateBarrier.Do(func() { close(commonLateReached) })
			select {
			case <-commonLateRelease:
			case <-r.Context().Done():
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/go/exports/") && strings.HasSuffix(r.URL.Path, "/zip") && r.URL.Query().Get("generation") == "1" && r.Header.Get("Range") == "bytes=65536-131071" {
			barrier.Do(func() { close(reached) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		s.ServeHTTP(w, r)
	})
	localTLS, err := crypt.LocalIdentity("127.0.0.1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	caPath := write("collector-ca.pem", []byte(localTLS.CA))
	certPath := write("collector-server.pem", []byte(localTLS.Certificate))
	keyPath := write("collector-server-key.pem", []byte(localTLS.Key))
	// HTTP/1.1 is deliberate for the owned post-commit Hijack/close fault.
	// HTTP/2 qualification is a separate case, not inferred from this fixture.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, Protocols: protocols}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ServeTLS(listener, certPath, keyPath) }()
	defer func() {
		server.Close()
		select {
		case err := <-serverDone:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Error("owned TLS server stopped unexpectedly", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("owned TLS server did not stop")
		}
	}()
	serverURL := "https://127.0.0.1:38443"
	tokenPath := write("admin.token", []byte(token))
	configRaw, _ := json.Marshal(configfile.Client{Version: 1, URL: serverURL, TokenFile: tokenPath, CAFile: caPath})
	configPath := write("client.json", configRaw)

	// Collect all original common roots under one exact signed binding. Faults
	// use separate channels from the original single-export journey below.
	commonOutput := filepath.Join(private, "common collected package")
	commonJournalArguments := []string{"--journal-file", journalPath, "--journal-tenant", admin.Tenant, "--journal-event-sequence", strconv.FormatInt(commonSession.CreatedSequence, 10), "--journal-through", strconv.FormatInt(head.Sequence, 10), "--journal-through-hash", head.Hash, "--checkpoint-file", statementPath, "--checkpoint-signature-file", signature, "--checkpoint-key-file", publicKey}
	commonCollectArguments := append([]string{cli, "go-export-set-collect", "--config", configPath, "--set-id", commonSession.ID, "--generation", "1", "--output-directory", commonOutput, "--chunk-bytes", "65536"}, commonJournalArguments...)
	commonTransferActive.Store(true)
	commonChild, commonOut, commonDiagnostic := command(commonCollectArguments, nil)
	if err := commonChild.Start(); err != nil {
		t.Fatal(err)
	}
	commonDone := make(chan error, 1)
	go func() { commonDone <- commonChild.Wait() }()
	select {
	case <-commonReached:
	case err := <-commonDone:
		t.Fatalf("common collector exited before second range: %v; bounded diagnostic=%q", err, commonDiagnostic.Bytes())
	case <-ctx.Done():
		t.Fatal("common transfer barrier timeout")
	}
	if err := commonChild.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := <-commonDone; err == nil || commonOut.Len() != 0 {
		t.Fatal("killed common collector emitted completion", err)
	}
	commonTransferActive.Store(false)
	close(commonRelease)
	prefix, err := os.ReadFile(filepath.Join(commonOutput, "root.000.zip"))
	if err != nil || len(prefix) != 65536 || !bytes.Equal(prefix, zip[:65536]) {
		t.Fatal("common kill lost exact synced prefix", err, len(prefix))
	}
	if _, err := os.Stat(filepath.Join(commonOutput, "receipt.json")); !os.IsNotExist(err) {
		t.Fatal("partial common collection published receipt")
	}
	commonRenew := store.GoExportChange{Action: "renew", ExpectedGeneration: 1, LifetimeSeconds: 3600, ManifestSHA256: commonSession.Manifest.Digest}
	changeBody, _ := json.Marshal(commonRenew)
	if response := goHTTP(t, s, token, "POST", "/api/v1/go/export-sets/"+commonSession.ID+"/control", changeBody, "Idempotency-Key", "native-common-collector-renew"); response.Code != 200 {
		t.Fatal("common explicit renewal", response.Code)
	}
	commonResumedArguments := append(append([]string{}, commonCollectArguments...), "--generation", "2", "--resume")
	commonCollected := run(true, nil, commonResumedArguments...)
	var collectedCommon struct {
		Binding struct {
			Profile string `json:"profile"`
			SetID   string `json:"set_id"`
			Members []struct {
				Name   string      `json:"name"`
				Object blob.Object `json:"object"`
			} `json:"members"`
		} `json:"binding"`
		CollectedGeneration int64 `json:"collected_generation"`
		BytesVerified       bool  `json:"bytes_verified"`
		CurrentAdmission    bool  `json:"current_registry_admission"`
		Authority           bool  `json:"checksum_authority_verified"`
		Closure             bool  `json:"dependency_closure"`
		Delivery            bool  `json:"delivery_verified"`
	}
	if json.Unmarshal(commonCollected, &collectedCommon) != nil || collectedCommon.Binding.Profile != "cratectl.go.hosted.set-collection.v1" || collectedCommon.Binding.SetID != commonSession.ID || len(collectedCommon.Binding.Members) != 11 || collectedCommon.CollectedGeneration != 2 || !collectedCommon.BytesVerified || collectedCommon.CurrentAdmission || collectedCommon.Authority || collectedCommon.Closure || collectedCommon.Delivery {
		t.Fatal("complete common collection receipt/bounds changed")
	}
	for _, member := range collectedCommon.Binding.Members {
		raw, err := os.ReadFile(filepath.Join(commonOutput, member.Name))
		if err != nil || crypt.Digest(raw) != member.Object.Digest || int64(len(raw)) != member.Object.Size {
			t.Fatal("retained original common member", member.Name, err)
		}
	}
	commonRenew.ExpectedGeneration = 2
	changeBody, _ = json.Marshal(commonRenew)
	if response := goHTTP(t, s, token, "POST", "/api/v1/go/export-sets/"+commonSession.ID+"/control", changeBody, "Idempotency-Key", "native-common-collector-renew-again"); response.Code != 200 {
		t.Fatal("second common renewal", response.Code)
	}
	if replay := run(true, nil, append(commonResumedArguments, "--generation", "3")...); !bytes.Equal(replay, commonCollected) {
		t.Fatal("renewed common replay rewrote original completion receipt")
	}
	// A current late-root policy denial happens after the first root has been
	// collected. Preserve those bytes, but emit neither receipt nor stdout.
	lateOutput := filepath.Join(private, "common denied late member")
	lateArguments := append(append([]string{}, commonCollectArguments...), "--generation", "3", "--output-directory", lateOutput)
	commonLateActive.Store(true)
	lateChild, lateOut, lateDiagnostic := command(lateArguments, nil)
	if err := lateChild.Start(); err != nil {
		t.Fatal(err)
	}
	lateDone := make(chan error, 1)
	go func() { lateDone <- lateChild.Wait() }()
	select {
	case <-commonLateReached:
	case err := <-lateDone:
		t.Fatalf("common collector exited before late root: %v; bounded diagnostic=%q", err, lateDiagnostic.Bytes())
	case <-ctx.Done():
		t.Fatal("common late-root barrier timeout")
	}
	lateArtifact := commonManifest.Entries[1].Artifacts[0]
	if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, err := store.Decide(ctx, tx, admin, "index-extra", lateArtifact.Path, lateArtifact.Digest, "denied")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	commonLateActive.Store(false)
	close(commonLateRelease)
	if err := <-lateDone; err == nil || lateOut.Len() != 0 {
		t.Fatal("late denied common member emitted completion", err)
	}
	firstRetained, err := os.ReadFile(filepath.Join(lateOutput, "root.000.zip"))
	if err != nil || crypt.Digest(firstRetained) != commonManifest.Entries[0].Artifacts[0].Digest {
		t.Fatal("late failure lost retained first original", err)
	}
	if _, err := os.Stat(filepath.Join(lateOutput, "receipt.json")); !os.IsNotExist(err) {
		t.Fatal("late denied member published partial common receipt")
	}
	if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, err := store.Decide(ctx, tx, admin, "index-extra", lateArtifact.Path, lateArtifact.Digest, "allowed")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	run(true, nil, append(lateArguments, "--resume")...)
	originalInfo, err := os.ReadFile(filepath.Join(commonOutput, "root.001.info"))
	if err != nil {
		t.Fatal(err)
	}
	corruptInfo := bytes.Clone(originalInfo)
	corruptInfo[len(corruptInfo)/2] ^= 1
	if err := os.WriteFile(filepath.Join(commonOutput, "root.001.info"), corruptInfo, 0600); err != nil {
		t.Fatal(err)
	}
	run(false, nil, append(commonResumedArguments, "--generation", "3")...)
	originalCommonReceipt, err := os.ReadFile(filepath.Join(commonOutput, "receipt.json"))
	if err != nil || !bytes.Equal(originalCommonReceipt, commonCollected) {
		t.Fatal("corrupt resumed member rewrote historical receipt", err)
	}
	output := filepath.Join(private, "collected package")
	journalArguments := []string{"--journal-file", journalPath, "--journal-tenant", admin.Tenant, "--journal-event-sequence", strconv.FormatInt(session.CreatedSequence, 10), "--journal-through", strconv.FormatInt(head.Sequence, 10), "--journal-through-hash", head.Hash, "--checkpoint-file", statementPath, "--checkpoint-signature-file", signature, "--checkpoint-key-file", publicKey}
	args := []string{cli, "go-export-collect", "--config", configPath, "--export-id", session.ID, "--generation", "1", "--repository", req.Repository, "--module", req.Module, "--version", req.Version, "--output-directory", output, "--chunk-bytes", "65536"}
	args = append(args, journalArguments...)
	unrelatedTLS, err := crypt.LocalIdentity("127.0.0.1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	unrelatedCA := write("unrelated-ca.pem", []byte(unrelatedTLS.CA))
	untrustedConfig, _ := json.Marshal(configfile.Client{Version: 1, URL: serverURL, TokenFile: tokenPath, CAFile: unrelatedCA})
	untrustedConfigPath := write("untrusted-client.json", untrustedConfig)
	untrustedOutput := filepath.Join(private, "untrusted-collection")
	untrustedArgs := append(append([]string{}, args...), "--config", untrustedConfigPath, "--output-directory", untrustedOutput)
	beforeUntrusted := applicationRequests.Load()
	run(false, nil, untrustedArgs...)
	if applicationRequests.Load() != beforeUntrusted {
		t.Fatal("wrong-CA collector reached the application handler")
	}
	if _, err := os.Stat(untrustedOutput); !os.IsNotExist(err) {
		t.Fatal("wrong-CA collector created collection output")
	}
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
	otherConfig, _ := json.Marshal(configfile.Client{Version: 1, URL: serverURL, TokenFile: otherTokenPath, CAFile: caPath})
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
	if err := store.Provision(ctx, d.OwnerDSN, admin.Tenant, "export-importer", "writer", importToken, time.Now().Add(time.Hour)); err != nil {
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
	importTokenPath := write("import.token", []byte(importToken))
	importConfig, _ := json.Marshal(configfile.Client{Version: 1, URL: serverURL, TokenFile: importTokenPath, CAFile: caPath})
	importConfigPath := write("import-client.json", importConfig)
	importArgs := append([]string{cli, "go-export-import"}, offlineArgs[2:]...)
	importArgs = append(importArgs, "--config", importConfigPath, "--destination-repository", "imported", "--idempotency-key", "native-signed-import-v1")
	attempt := func(name string) []string {
		return append(append([]string{}, importArgs...), "--output-directory", filepath.Join(private, name))
	}
	untrustedImportConfig, _ := json.Marshal(configfile.Client{Version: 1, URL: serverURL, TokenFile: importTokenPath, CAFile: unrelatedCA})
	untrustedImportPath := write("untrusted-import-client.json", untrustedImportConfig)
	beforeUntrusted = applicationRequests.Load()
	run(false, nil, append(attempt("import-untrusted-tls"), "--config", untrustedImportPath)...)
	if applicationRequests.Load() != beforeUntrusted {
		t.Fatal("wrong-CA importer reached the application handler")
	}
	if _, err := os.Stat(filepath.Join(private, "import-untrusted-tls", "import-intent.json")); err != nil {
		t.Fatal("wrong-CA import lost its nonsecret intent", err)
	}
	if _, err := os.Stat(filepath.Join(private, "import-untrusted-tls", "import-receipt.json")); !os.IsNotExist(err) {
		t.Fatal("wrong-CA import claimed publication")
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
	// Each network consumer gets fresh private caches. A prior downloaded copy
	// cannot be recalled, so warm-cache reuse cannot test current serving denial.
	netrcPath := write("destination.netrc", []byte("machine 127.0.0.1:38443 login token password "+importToken+"\n"))
	sdkDestination := func(name, trust string, allowed bool) {
		t.Helper()
		directory := filepath.Join(private, name)
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "go.mod"), []byte("module owned.invalid/destination-consumer\n\ngo 1.27.0\n"), 0600); err != nil {
			t.Fatal(err)
		}
		moduleCache := filepath.Join(directory, "modcache")
		env := []string{"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOTOOLCHAIN=local", "GOTELEMETRY=off", "GOINSECURE=", "GOPROXY=" + serverURL + "/go/imported/", "GOPRIVATE=go.cratectl.invalid", "GONOPROXY=none", "GONOSUMDB=go.cratectl.invalid", "GOSUMDB=sum.golang.org", "GOVCS=*:off", "GOAUTH=netrc", "NETRC=" + netrcPath, "SSL_CERT_FILE=" + trust, "GOMODCACHE=" + moduleCache, "GOPATH=" + filepath.Join(directory, "gopath"), "GOCACHE=" + filepath.Join(directory, "buildcache")}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(cleanup, goBinary, "clean", "-modcache")
			cmd.Dir, cmd.Env, cmd.WaitDelay = directory, append(append([]string{}, environment...), env...), 2*time.Second
			if err := cmd.Run(); err != nil {
				t.Error("owned destination SDK cache cleanup failed")
			}
		})
		cmd, stdout, _ := command([]string{goBinary, "mod", "download", "-json", req.Module + "@" + req.Version}, env)
		cmd.Dir = directory
		err := cmd.Run()
		if (err == nil) != allowed {
			// The NETRC is private. Do not print arbitrary authenticated output.
			t.Fatalf("owned destination SDK %s expected success=%t: %v", name, allowed, err)
		}
		var result struct{ Dir, Sum, GoModSum string }
		parsed := json.Unmarshal(stdout.Bytes(), &result) == nil
		escapedModule, escapedVersion, ok := strings.Cut(coordinate.Prefix(), "/@v/")
		if !ok {
			t.Fatal("owned module cache coordinate is invalid")
		}
		extractedPath := filepath.Join(moduleCache, filepath.FromSlash(escapedModule+"@"+escapedVersion), "assets", "owned.txt")
		if !allowed {
			if result.Dir != "" || result.Sum != "" || result.GoModSum != "" {
				t.Fatal("denied destination SDK retained a success identity")
			}
			if _, err := os.Stat(extractedPath); !os.IsNotExist(err) {
				t.Fatal("denied destination SDK extracted inert bytes")
			}
			if sums, err := os.ReadFile(filepath.Join(directory, "go.sum")); err == nil && (bytes.Contains(sums, []byte(prepared.ZIPHash)) || bytes.Contains(sums, []byte(prepared.ModHash))) {
				t.Fatal("denied destination SDK recorded the original package sums")
			}
			return
		}
		if !parsed || result.Dir == "" || result.Sum != prepared.ZIPHash || result.GoModSum != prepared.ModHash {
			t.Fatal("admitted destination SDK changed original h1 identities")
		}
		body, err := os.ReadFile(extractedPath)
		if err != nil || !bytes.Equal(body, asset.Bytes()) {
			t.Fatal("admitted destination SDK extracted different inert bytes", err)
		}
	}
	sdkDestination("destination-unassessed", caPath, false)
	manualDecision := func(a store.Artifact, decision, key string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"path": a.Path, "digest": a.Digest, "decision": decision})
		bodyPath := write(key+".json", body)
		run(true, nil, cli, "--config", configPath, "--method", "PUT", "--path", "/api/v1/repositories/imported/decisions", "--body-file", bodyPath, "--idempotency-key", key)
	}
	var destinationZIP store.Artifact
	for n, a := range imported {
		manualDecision(a, "allowed", fmt.Sprintf("native-destination-review-%d", n))
		if strings.HasSuffix(a.Path, ".zip") {
			destinationZIP = a
		}
	}
	if destinationZIP.Digest == "" {
		t.Fatal("owned destination ZIP reference missing")
	}
	sdkDestination("destination-reviewed", caPath, true)
	beforeUntrusted = applicationRequests.Load()
	sdkDestination("destination-untrusted-ca", unrelatedCA, false)
	if applicationRequests.Load() != beforeUntrusted {
		t.Fatal("wrong-CA SDK reached the destination handler")
	}
	manualDecision(destinationZIP, "denied", "native-destination-deny")
	sdkDestination("destination-policy-denied", caPath, false)
	manualDecision(destinationZIP, "allowed", "native-destination-reopen")
	grantBody := write("destination-read-revoked.json", []byte(`{"actor":"export-importer","read":false,"write":false}`))
	run(true, nil, cli, "--config", configPath, "--method", "PUT", "--path", "/api/v1/repositories/imported/grants", "--body-file", grantBody, "--idempotency-key", "native-destination-read-revoked")
	sdkDestination("destination-read-revoked", caPath, false)
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
