// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
	"github.com/jackc/pgx/v5"
)

var ErrGoChecksumAuthorityBlocked = errors.New("Go checksum authority has authenticated conflicting history")

const GoChecksumFailureProfile = "go-checksum-failure-v1"
const GoChecksumFailureEvidenceProfile = "go-checksum-failure-evidence-v1"
const MaxGoChecksumFailureEvidence = 2 << 20

// Attempts are original bounded observations, not approved proof responses.
// Only complete successful responses can participate in independent replay.
// Codes are fixed classifications, never arbitrary transport/error text.
type GoChecksumFailureAttempt struct {
	Path                string `json:"path"`
	Status              int    `json:"status"`
	Code                string `json:"code"`
	Body                []byte `json:"body"`
	Omitted             bool   `json:"omitted,omitempty"`
	OmittedPrefixSHA256 string `json:"omitted_prefix_sha256,omitempty"`
	OmittedPrefixBytes  int    `json:"omitted_prefix_bytes,omitempty"`
}

type GoChecksumFailureReport struct {
	Profile     string                     `json:"profile"`
	Module      string                     `json:"module"`
	Version     string                     `json:"version"`
	ZIPHash     string                     `json:"zip_h1"`
	ModHash     string                     `json:"mod_h1"`
	VerifierKey string                     `json:"verifier_key"`
	Checkpoint  []byte                     `json:"checkpoint"`
	Attempts    []GoChecksumFailureAttempt `json:"attempts"`
}

type GoChecksumFailure struct {
	ExpectedCheckpointRevision int64
	Report                     GoChecksumFailureReport
}

// A known observation is not a durable block until its transaction commits.
// A coordinator may retry this exact evidence under the normal current fences;
// the fixed error string never exposes the captured response bytes.
type PendingGoChecksumFailure struct {
	failure GoChecksumFailure
	cause   error
}

func (e *PendingGoChecksumFailure) Error() string {
	return "Go checksum failure evidence was not durably recorded"
}
func (e *PendingGoChecksumFailure) Unwrap() error                  { return e.cause }
func (e *PendingGoChecksumFailure) Observation() GoChecksumFailure { return e.failure }

// Store-supplied bindings preserve both independently retained trust pins and
// the exact failed attempt. The journal hashes these canonical immutable bytes.
// Neither this record nor its classification is a package admission token.
type GoChecksumFailureRecord struct {
	Profile                    string                  `json:"profile"`
	Tenant                     string                  `json:"tenant"`
	Repository                 string                  `json:"repository"`
	RootPath                   string                  `json:"root_path"`
	SourceRevision             int64                   `json:"source_revision"`
	Generation                 int64                   `json:"generation"`
	KeyDigest                  string                  `json:"key_digest"`
	ExpectedCheckpointRevision int64                   `json:"expected_checkpoint_revision"`
	CurrentCheckpointRevision  int64                   `json:"current_checkpoint_revision"`
	CurrentCheckpoint          []byte                  `json:"current_checkpoint"`
	Classification             string                  `json:"classification"`
	Report                     GoChecksumFailureReport `json:"report"`
}

func validateGoChecksumFailureReport(r GoChecksumFailureReport) error {
	if _, err := gomodule.Canonical(r.Module, r.Version); err != nil || r.Profile != GoChecksumFailureProfile || len(r.ZIPHash) != 47 || len(r.ModHash) != 47 || len(r.VerifierKey) > 4096 || len(r.Checkpoint) == 0 || len(r.Checkpoint) > 16<<10 || len(r.Attempts) > 128 {
		return ErrGoModuleUnvalidated
	}
	remaining := 1<<20 - len(r.VerifierKey) - len(r.Checkpoint) - len(r.Module) - len(r.Version)
	for _, a := range r.Attempts {
		if len(a.Path) == 0 || len(a.Path) > 2048 || !utf8.ValidString(a.Path) || strings.ContainsFunc(a.Path, unicode.IsControl) || len(a.Body) > 64<<10+1 || len(a.Path)+len(a.Body) > remaining || a.Status < 0 || a.Status > 599 || a.Status > 0 && a.Status < 100 {
			return ErrGoModuleUnvalidated
		}
		switch a.Code {
		case "ok":
			if a.Status != 200 || len(a.Body) > 64<<10 {
				return ErrGoModuleUnvalidated
			}
		case "cache_policy":
			if !a.Omitted || len(a.Body) != 0 || a.OmittedPrefixBytes < 0 || a.OmittedPrefixBytes > 64<<10+1 || (IntegrityTarget{Repository: "failure", Path: "evidence", Digest: a.OmittedPrefixSHA256, Size: int64(a.OmittedPrefixBytes)}).Validate() != nil {
				return ErrGoModuleUnvalidated
			}
		case "credential":
			if !a.Omitted || len(a.Body) != 0 || a.OmittedPrefixSHA256 != "" || a.OmittedPrefixBytes < 0 || a.OmittedPrefixBytes > 64<<10+1 {
				return ErrGoModuleUnvalidated
			}
		case "transport", "status", "length", "encoding", "range", "read", "overflow":
		default:
			return ErrGoModuleUnvalidated
		}
		if a.Code != "cache_policy" && a.Code != "credential" && (a.Omitted || a.OmittedPrefixSHA256 != "" || a.OmittedPrefixBytes != 0) {
			return ErrGoModuleUnvalidated
		}
		cost := len(a.Path) + len(a.Body) + a.OmittedPrefixBytes
		if cost > remaining {
			return ErrGoModuleUnvalidated
		}
		remaining -= cost
	}
	return nil
}

// Failure classification is a fresh offline verification against independently
// retained pins. Caller labels and a report-selected checkpoint confer no trust.
func classifyGoChecksumFailure(ctx context.Context, r GoChecksumFailureReport, key string, expected, current []byte) (string, error) {
	if err := validateGoChecksumFailureReport(r); err != nil {
		return "", err
	}
	if r.VerifierKey != key || !bytes.Equal(r.Checkpoint, expected) {
		return "", ErrGoModuleUnvalidated
	}
	responses := map[string][]byte{}
	for _, a := range r.Attempts {
		if a.Code != "ok" {
			continue
		}
		if old, exists := responses[a.Path]; exists && !bytes.Equal(old, a.Body) {
			return "unverified", nil
		}
		responses[a.Path] = a.Body
	}
	for _, pin := range [][]byte{expected, current} {
		_, err := crypt.VerifyGoSumDB(ctx, r.Module, r.Version, r.ZIPHash, r.ModHash, crypt.GoSumDBSnapshot{VerifierKey: key, Checkpoint: pin, Responses: responses})
		if errors.Is(err, crypt.ErrGoChecksumFork) {
			return "fork", nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
	return "unverified", nil
}

func goChecksumAuthorityUsable(ctx context.Context, tx pgx.Tx, digest string) error {
	var blocked bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.go_checksum_forks WHERE key_digest=$1)`, digest).Scan(&blocked); err != nil {
		return err
	}
	if blocked {
		return ErrGoChecksumAuthorityBlocked
	}
	return nil
}

func goChecksumRepositoryUsable(ctx context.Context, tx pgx.Tx, repo Repository) error {
	a := repo.Settings.GoChecksumAuthority
	if repo.Format != "go" || repo.Mode != "proxy" || a == nil {
		return nil
	}
	if err := a.Validate(); err != nil {
		return err
	}
	initial, err := crypt.ParseGoSumDBCheckpoint(a.VerifierKey, a.InitialCheckpoint)
	if err != nil {
		return err
	}
	return goChecksumAuthorityUsable(ctx, tx, initial.KeyDigest)
}

// Detect authenticated forks before bundle/reference writes. This lets common
// completion record its fail-stop result atomically under the same tenant lock,
// while still returning a rejected-publication error to a positive caller.
func proposedGoChecksumFork(ctx context.Context, tx pgx.Tx, repo Repository, p *GoModuleChecksumPublication) (*GoChecksumFailure, error) {
	a := repo.Settings.GoChecksumAuthority
	if a == nil || a.Validate() != nil {
		return nil, ErrGoModuleUnvalidated
	}
	initial, err := crypt.ParseGoSumDBCheckpoint(a.VerifierKey, a.InitialCheckpoint)
	if err != nil {
		return nil, err
	}
	if err := goChecksumAuthorityUsable(ctx, tx, initial.KeyDigest); err != nil {
		return nil, err
	}
	current, err := currentGoChecksumCheckpoint(ctx, tx, a.VerifierKey, initial.KeyDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		current = GoChecksumCheckpoint{Checkpoint: a.InitialCheckpoint}
	} else if err != nil {
		return nil, err
	}
	if p.ExpectedCheckpointRevision > current.Revision {
		return nil, nil
	}
	expected := a.InitialCheckpoint
	if p.ExpectedCheckpointRevision > 0 {
		retained, err := retainedGoChecksumCheckpoint(ctx, tx, a.VerifierKey, initial.KeyDigest, p.ExpectedCheckpointRevision)
		if err != nil {
			return nil, err
		}
		expected = retained.Checkpoint
	}
	_, err = rebaseGoChecksumProof(ctx, *p, gomodule.Coordinate{Module: p.Proof.Module, Version: p.Proof.Version}, a.VerifierKey, expected, current.Checkpoint)
	if !errors.Is(err, crypt.ErrGoChecksumFork) {
		return nil, nil
	}
	report := GoChecksumFailureReport{Profile: GoChecksumFailureProfile, Module: p.Proof.Module, Version: p.Proof.Version, ZIPHash: p.ZIPHash, ModHash: p.ModHash, VerifierKey: p.Proof.Snapshot.VerifierKey, Checkpoint: p.Proof.Snapshot.Checkpoint}
	paths := make([]string, 0, len(p.Proof.Snapshot.Responses))
	for path := range p.Proof.Snapshot.Responses {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		report.Attempts = append(report.Attempts, GoChecksumFailureAttempt{Path: path, Status: 200, Code: "ok", Body: p.Proof.Snapshot.Responses[path]})
	}
	return &GoChecksumFailure{ExpectedCheckpointRevision: p.ExpectedCheckpointRevision, Report: report}, nil
}

// Inline evidence has no external reference that could precede durable bytes.
// It commits with failed state, first key block and journal under the live lease.
func completeGoChecksumFailure(ctx context.Context, tx pgx.Tx, i Identity, repo Repository, lease Retrieval, failure GoChecksumFailure, sequence int64) (classification, digest string, err error) {
	a := repo.Settings.GoChecksumAuthority
	if repo.Format != "go" || a == nil || a.Validate() != nil || failure.ExpectedCheckpointRevision < 0 {
		return "", "", ErrGoModuleUnvalidated
	}
	r := failure.Report
	c, err := gomodule.Canonical(r.Module, r.Version)
	if err != nil || lease.Path != c.Prefix()+".zip" {
		return "", "", ErrGoModuleUnvalidated
	}
	initial, err := crypt.ParseGoSumDBCheckpoint(a.VerifierKey, a.InitialCheckpoint)
	if err != nil {
		return "", "", err
	}
	current, err := currentGoChecksumCheckpoint(ctx, tx, a.VerifierKey, initial.KeyDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		current = GoChecksumCheckpoint{Checkpoint: a.InitialCheckpoint}
	} else if err != nil {
		return "", "", err
	}
	expected := a.InitialCheckpoint
	if failure.ExpectedCheckpointRevision > current.Revision {
		return "", "", ErrGoChecksumCheckpointChanged
	}
	if failure.ExpectedCheckpointRevision > 0 {
		retained, e := retainedGoChecksumCheckpoint(ctx, tx, a.VerifierKey, initial.KeyDigest, failure.ExpectedCheckpointRevision)
		if e != nil {
			return "", "", e
		}
		expected = retained.Checkpoint
	}
	classification, err = classifyGoChecksumFailure(ctx, r, a.VerifierKey, expected, current.Checkpoint)
	if err != nil {
		return "", "", err
	}
	record := GoChecksumFailureRecord{Profile: GoChecksumFailureEvidenceProfile, Tenant: i.Tenant, Repository: repo.Name, RootPath: lease.Path, SourceRevision: lease.SourceRevision, Generation: lease.Generation, KeyDigest: initial.KeyDigest, ExpectedCheckpointRevision: failure.ExpectedCheckpointRevision, CurrentCheckpointRevision: current.Revision, CurrentCheckpoint: current.Checkpoint, Classification: classification, Report: r}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > MaxGoChecksumFailureEvidence {
		return "", "", ErrMetadataLimit
	}
	digest = crypt.Digest(raw)
	_, err = tx.Exec(ctx, `INSERT INTO cratectl.go_checksum_failures(tenant,repository,root_path,source_revision,generation,key_digest,expected_checkpoint_revision,classification,evidence,evidence_digest,change_sequence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, i.Tenant, repo.Name, lease.Path, lease.SourceRevision, lease.Generation, initial.KeyDigest, failure.ExpectedCheckpointRevision, classification, raw, digest, sequence)
	if err == nil && classification == "fork" {
		_, err = tx.Exec(ctx, `INSERT INTO cratectl.go_checksum_forks(tenant,key_digest,repository,root_path,source_revision,generation,change_sequence) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant,key_digest) DO NOTHING`, i.Tenant, initial.KeyDigest, repo.Name, lease.Path, lease.SourceRevision, lease.Generation, sequence)
	}
	return classification, digest, err
}
