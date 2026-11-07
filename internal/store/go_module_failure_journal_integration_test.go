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
	"strconv"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

func TestGoModuleChecksumFailureBindsOriginalEvidenceToCompleteJournalRange(t *testing.T) {
	f, log := publishGoFailureFixture(t)
	ctx := context.Background()
	lease, err := f.s.AcquireRetrieval(ctx, f.i, "owned", f.lease.Path, "journal-failure", true)
	if err != nil || !lease.Acquired {
		t.Fatal(err)
	}
	report := checksumFailureReport(t, log, log.Fork, log.One)
	if err := f.s.CompleteRetrieval(ctx, f.i, lease, RetrievalResult{Failure: "upstream_checksum_fork", GoChecksumFailure: &GoChecksumFailure{ExpectedCheckpointRevision: 2, Report: report}}); err != nil {
		t.Fatal(err)
	}
	raw, digest, err := f.s.GoChecksumFailureEvidence(ctx, f.i, "owned", lease.Path, 0, lease.Generation)
	if err != nil {
		t.Fatal(err)
	}
	record, err := VerifyGoChecksumFailureEvidence(ctx, raw, log.Key)
	if err != nil || record.Classification != "fork" {
		t.Fatal(err)
	}
	items, more, err := f.s.GoChecksumFailurePage(ctx, f.i, "owned", 0, 100)
	if err != nil || more || len(items) != 1 {
		t.Fatal("missing exact original failure identity", err)
	}
	sequence := items[0].Sequence
	// A later original event ensures a selected verified prefix cannot escape
	// when the export subsequently loses or corrupts its terminal page.
	if err := f.s.Tx(ctx, f.i, true, func(tx pgx.Tx) error {
		return appendEventIntent(ctx, tx, f.i, "owned.after.failure", map[string]string{"scope": "later event is not delivery proof"}, false)
	}); err != nil {
		t.Fatal(err)
	}
	head, err := f.s.JournalCheckpoint(ctx, f.i)
	if err != nil || head.Sequence <= sequence {
		t.Fatal("later head not retained", err)
	}
	input := JournalRange{Through: head.Sequence, ThroughHash: head.Hash, Limit: 1}
	var export bytes.Buffer
	for {
		page, err := f.s.JournalPage(ctx, f.i, input)
		if err != nil || json.NewEncoder(&export).Encode(page) != nil {
			t.Fatal("real forced-RLS export", err)
		}
		if !page.More {
			break
		}
		input.After, input.AfterHash = page.NextAfter, page.NextHash
	}
	start := crypt.JournalAnchor{Tenant: f.i.Tenant}
	receipt, event, err := crypt.VerifyJournalExportEvent(ctx, bytes.NewReader(export.Bytes()), start, head, 1<<20, sequence)
	if err != nil || !receipt.MatchesSuppliedCheckpoint || event.Sequence != sequence {
		t.Fatal("actual original failure not selected after full EOF", err)
	}
	if bound, err := BindGoChecksumFailureJournalEvent(raw, record, event); err != nil || bound != digest {
		t.Fatal("stored record and original journal digest detached", err)
	}
	verifyNativeGoJournalCLI(t, raw, log.Key, export.Bytes(), head, sequence, digest)
	changed := record
	changed.Generation++
	changedRaw, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if bound, err := BindGoChecksumFailureJournalEvent(changedRaw, changed, event); err == nil || bound != "" {
		t.Fatal("different canonical generation borrowed attribution")
	}
	truncated := export.Bytes()[:bytes.LastIndexByte(export.Bytes()[:export.Len()-1], '\n')+1]
	if result, selected, err := crypt.VerifyJournalExportEvent(ctx, bytes.NewReader(truncated), start, head, 1<<20, sequence); err == nil || result.MatchesSuppliedCheckpoint || selected.Sequence != 0 || selected.Payload != "" {
		t.Fatal("valid failure prefix escaped without terminal range")
	}
	other := Identity{Tenant: "other-journal-binding", Actor: "operator", Role: "admin"}
	if _, err := f.s.JournalPage(ctx, other, JournalRange{Through: head.Sequence, ThroughHash: head.Hash, Limit: 2}); err == nil {
		t.Fatal("another tenant borrowed original checkpoint")
	}
}

type goJournalCommandOutput struct{ bytes.Buffer }

func (out *goJournalCommandOutput) Write(p []byte) (int, error) {
	if len(p) > 1<<20-out.Len() {
		return 0, errors.New("owned command output exceeded1MiB")
	}
	return out.Buffer.Write(p)
}

// This is an actual native fixture journey, not a product signing process.
// Disposable private signer bytes never leave this test's private directory.
func verifyNativeGoJournalCLI(t *testing.T, evidence []byte, authority string, journal []byte, head crypt.JournalAnchor, sequence int64, digest string) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	directory := os.Getenv("CRATECTL_QUALIFICATION_BIN_DIR")
	if directory == "" {
		t.Fatal("CRATECTL_QUALIFICATION_BIN_DIR required; build the owned candidate before native journal CLI qualification")
	}
	if !filepath.IsAbs(directory) {
		directory = filepath.Join(root, directory)
	}
	cli := filepath.Join(directory, "cratectl")
	if info, err := os.Stat(cli); err != nil || !info.Mode().IsRegular() {
		t.Fatal("owned native candidate CLI is required")
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal("actual OpenSSL3 or4 required for external checkpoint fixture")
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(ok bool, argv ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, argv[0], argv[1:]...)
		command.Dir = root
		command.WaitDelay = 2 * time.Second
		for _, entry := range os.Environ() {
			name, _, _ := strings.Cut(entry, "=")
			if name != "CRATECTL_DSN" && name != "CRATECTL_OWNER_DSN" && name != "GITHUB_TOKEN" && name != "GH_TOKEN" {
				command.Env = append(command.Env, entry)
			}
		}
		var stdout, stderr goJournalCommandOutput
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		if ctx.Err() != nil || ok && err != nil || !ok && err == nil {
			t.Fatalf("owned native %s outcome mismatch; expected success=%t: %v", filepath.Base(argv[0]), ok, err)
		}
		return stdout.Bytes()
	}
	version := strings.Fields(string(run(true, openssl, "version")))
	if len(version) < 2 || version[0] != "OpenSSL" || !strings.HasPrefix(version[1], "3.") && !strings.HasPrefix(version[1], "4.") {
		t.Fatal("unsupported actual external signer version")
	}
	binary, err := os.Open(openssl)
	if err != nil {
		t.Fatal(err)
	}
	hash := crypt.SHA256()
	count, err := io.Copy(hash, io.LimitReader(binary, 128<<20+1))
	binary.Close()
	if err != nil || count > 128<<20 {
		t.Fatal("external tool binary exceeds fixture identity budget")
	}
	t.Logf("Owned external checkpoint tool OpenSSL%s binary_sha256=%x", version[1], hash.Sum(nil))
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(private, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	evidenceFile := write("cratectl-failure.json", evidence)
	authorityFile := write("cratectl-authority.key", []byte(authority))
	journalFile := write("cratectl-journal.jsonl", journal)
	statement, err := crypt.JournalCheckpointBytes(head)
	if err != nil {
		t.Fatal(err)
	}
	statementFile := write("cratectl-checkpoint.json", statement)
	privateKey, publicKey, signature := filepath.Join(private, "cratectl-signer-private.pem"), filepath.Join(private, "cratectl-signer-public.pem"), filepath.Join(private, "cratectl-checkpoint.sig")
	run(true, openssl, "genpkey", "-algorithm", "ED25519", "-out", privateKey)
	if err := os.Chmod(privateKey, 0600); err != nil {
		t.Fatal(err)
	}
	run(true, openssl, "pkey", "-in", privateKey, "-pubout", "-out", publicKey)
	run(true, openssl, "pkeyutl", "-sign", "-rawin", "-inkey", privateKey, "-in", statementFile, "-out", signature)
	run(true, openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", publicKey, "-in", statementFile, "-sigfile", signature)
	args := []string{cli, "go-checksum-verify", "--evidence-file", evidenceFile, "--key-file", authorityFile, "--journal-file", journalFile, "--journal-tenant", head.Tenant, "--journal-event-sequence", strconv.FormatInt(sequence, 10), "--journal-through", strconv.FormatInt(head.Sequence, 10), "--journal-through-hash", head.Hash, "--checkpoint-file", statementFile, "--checkpoint-signature-file", signature, "--checkpoint-key-file", publicKey}
	var receipt struct {
		Classification   string
		Digest           string `json:"evidence_sha256"`
		PackageAdmission bool   `json:"package_admission"`
		Attribution      struct {
			Journal             crypt.JournalVerification           `json:"journal"`
			EventSequence       int64                               `json:"event_sequence"`
			CheckpointSignature crypt.JournalCheckpointVerification `json:"checkpoint_signature"`
		} `json:"journal_attribution"`
	}
	if raw := run(true, args...); json.Unmarshal(raw, &receipt) != nil || receipt.Classification != "fork" || receipt.Digest != digest || receipt.PackageAdmission || receipt.Attribution.EventSequence != sequence || !receipt.Attribution.Journal.MatchesSuppliedCheckpoint || receipt.Attribution.Journal.ExportSHA256 != crypt.Digest(journal) || !receipt.Attribution.CheckpointSignature.SignatureVerified {
		t.Fatal("actual native CLI did not bind original PostgreSQL failure to external signature and complete range")
	}
	changed := append([]string(nil), args...)
	changed = append(changed, "--expected-sha256", strings.Repeat("0", 64))
	if len(run(false, changed...)) != 0 {
		t.Fatal("conflicting digest emitted native partial attribution")
	}
}
