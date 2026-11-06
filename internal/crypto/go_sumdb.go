// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

var ErrGoChecksumAuthority = errors.New("Go checksum authority evidence is missing, invalid or inconsistent")

const maxGoSumDBBytes = 1 << 20
const maxGoSumDBResponses = 128

// GoSumDBSnapshot contains original, untrusted lookup and hash-tile responses.
// VerifierKey and Checkpoint must come from the operator's current trust policy
// and retained timeline, separately from the responses. An empty checkpoint is
// refused: initial trust must explicitly supply a signed checkpoint, including
// a signed empty tree when bootstrapping. Callers must not mutate during a call.
type GoSumDBSnapshot struct {
	VerifierKey string            `json:"verifier_key"`
	Checkpoint  []byte            `json:"checkpoint"`
	Responses   map[string][]byte `json:"responses"`
}

type GoSumDBVerification struct {
	Authority, Module, Version string
	ZIPHash, GoModHash         string
	Checkpoint                 []byte
}

type GoSumDBCheckpoint struct {
	Authority, KeyDigest, RootHash string
	TreeSize                       int64
}

// ParseGoSumDBCheckpoint validates operator-supplied trust before any remote
// read. The exact canonical verifier key defines authority identity, even when
// another key uses the same name. The signed tree does not establish freshness.
func ParseGoSumDBCheckpoint(key string, checkpoint []byte) (GoSumDBCheckpoint, error) {
	if len(key) > 4096 || len(checkpoint) == 0 || len(checkpoint) > 16<<10 {
		return GoSumDBCheckpoint{}, ErrGoChecksumAuthority
	}
	verifier, err := note.NewVerifier(key)
	if err != nil || len(verifier.Name()) > 255 {
		return GoSumDBCheckpoint{}, ErrGoChecksumAuthority
	}
	parts := strings.SplitN(key, "+", 3)
	if len(parts) != 3 || parts[0] != verifier.Name() || parts[1] != fmt.Sprintf("%08x", verifier.KeyHash()) {
		return GoSumDBCheckpoint{}, ErrGoChecksumAuthority
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != parts[2] {
		return GoSumDBCheckpoint{}, ErrGoChecksumAuthority
	}
	pinned, err := note.Open(checkpoint, note.VerifierList(verifier))
	if err != nil {
		return GoSumDBCheckpoint{}, ErrGoChecksumAuthority
	}
	tree, err := tlog.ParseTree([]byte(pinned.Text))
	if err != nil {
		return GoSumDBCheckpoint{}, ErrGoChecksumAuthority
	}
	return GoSumDBCheckpoint{Authority: verifier.Name(), KeyDigest: Digest([]byte(key)), RootHash: tree.Hash.String(), TreeSize: tree.N}, nil
}

// GoSumDBReader must honor cancellation and bound body allocation/consumption
// to limit+1 bytes (the last byte detects overflow). Paths are canonical lookup
// or hash tiles, never destinations. It may be called concurrently at most twice.
type GoSumDBReader func(ctx context.Context, path string, limit int64) ([]byte, error)

// CollectGoSumDB drives the same authenticated client through an explicitly
// supplied reader, retaining original successful responses for offline replay.
// trust must contain only the separately configured key and retained checkpoint.
// Neither returned value is durable publication or current-policy admission.
func CollectGoSumDB(ctx context.Context, mod, version, zipHash, modHash string, trust GoSumDBSnapshot, read GoSumDBReader) (GoSumDBVerification, GoSumDBSnapshot, error) {
	if len(trust.Responses) != 0 || read == nil {
		return GoSumDBVerification{}, GoSumDBSnapshot{}, ErrGoChecksumAuthority
	}
	ops, err := prepareGoSumDB(ctx, mod, version, zipHash, modHash, trust)
	if err != nil {
		return GoSumDBVerification{}, GoSumDBSnapshot{}, err
	}
	ops.remote, ops.slots = read, make(chan struct{}, 2)
	verified, err := verifyGoSumDB(ops, mod, version, zipHash, modHash)
	if err != nil {
		return GoSumDBVerification{}, GoSumDBSnapshot{}, err
	}
	proof := GoSumDBSnapshot{VerifierKey: trust.VerifierKey, Checkpoint: bytes.Clone(trust.Checkpoint), Responses: map[string][]byte{}}
	ops.mu.Lock()
	for path, data := range ops.responses {
		proof.Responses[path] = bytes.Clone(data)
	}
	ops.mu.Unlock()
	return verified, proof, nil
}

// VerifyGoSumDB verifies BOTH standard h1 entries, the signed tree, record
// inclusion and consistency with the supplied checkpoint, using Go's standard
// sumdb client. It performs no network or filesystem operations. Its returned
// checkpoint is a proposal: a caller must atomically fence the current authority
// and prior checkpoint with artifact publication before trusting it durably.
// It does not establish freshness, publisher identity or package policy approval.
func VerifyGoSumDB(ctx context.Context, mod, version, zipHash, modHash string, input GoSumDBSnapshot) (GoSumDBVerification, error) {
	if len(input.Responses) == 0 || len(input.Responses) > maxGoSumDBResponses {
		return GoSumDBVerification{}, ErrGoChecksumAuthority
	}
	ops, err := prepareGoSumDB(ctx, mod, version, zipHash, modHash, input)
	if err != nil {
		return GoSumDBVerification{}, err
	}
	for path, data := range input.Responses {
		if !ops.validResponse(path, data) || len(path)+len(data) > ops.remaining {
			return GoSumDBVerification{}, ErrGoChecksumAuthority
		}
		ops.remaining -= len(path) + len(data)
		ops.responses[path] = bytes.Clone(data)
	}
	return verifyGoSumDB(ops, mod, version, zipHash, modHash)
}

func prepareGoSumDB(ctx context.Context, mod, version, zipHash, modHash string, input GoSumDBSnapshot) (*goSumDBOps, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(mod) > 512 || len(version) > 128 || module.Check(mod, version) != nil || module.CanonicalVersion(version) != version || !validGoH1(zipHash) || !validGoH1(modHash) {
		return nil, ErrGoChecksumAuthority
	}
	if module.IsPseudoVersion(version) {
		if _, err := module.PseudoVersionTime(version); err != nil {
			return nil, ErrGoChecksumAuthority
		}
	}
	checkpoint, err := ParseGoSumDBCheckpoint(input.VerifierKey, input.Checkpoint)
	if err != nil {
		return nil, err
	}
	escapedModule, _ := module.EscapePath(mod)
	escapedVersion, _ := module.EscapeVersion(version)
	return &goSumDBOps{ctx: ctx, key: input.VerifierKey, name: checkpoint.Authority, lookup: "/lookup/" + escapedModule + "@" + escapedVersion, checkpoint: bytes.Clone(input.Checkpoint), responses: map[string][]byte{}, remaining: maxGoSumDBBytes - len(input.Checkpoint) - len(input.VerifierKey)}, nil
}

func verifyGoSumDB(ops *goSumDBOps, mod, version, zipHash, modHash string) (GoSumDBVerification, error) {
	ctx := ops.ctx
	client := sumdb.NewClient(ops)
	for _, entry := range []struct{ version, hash string }{{version, zipHash}, {version + "/go.mod", modHash}} {
		lines, err := client.Lookup(mod, entry.version)
		if err != nil || len(lines) != 1 || lines[0] != mod+" "+entry.version+" "+entry.hash {
			if err := ctx.Err(); err != nil {
				return GoSumDBVerification{}, err
			}
			return GoSumDBVerification{}, ErrGoChecksumAuthority
		}
	}
	if err := ctx.Err(); err != nil {
		return GoSumDBVerification{}, err
	}
	ops.mu.Lock()
	defer ops.mu.Unlock()
	if ops.securityError {
		return GoSumDBVerification{}, ErrGoChecksumAuthority
	}
	return GoSumDBVerification{Authority: ops.name, Module: mod, Version: version, ZIPHash: zipHash, GoModHash: modHash, Checkpoint: bytes.Clone(ops.checkpoint)}, nil
}

func validGoH1(value string) bool {
	if len(value) != 47 || !strings.HasPrefix(value, "h1:") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(value[3:])
	return err == nil && len(decoded) == 32 && base64.StdEncoding.EncodeToString(decoded) == value[3:]
}

// The standard client fetches tiles concurrently. Bound every read, including
// missing full tiles followed by partial-tile fallbacks, under one locked budget.
type goSumDBOps struct {
	ctx           context.Context
	key, name     string
	lookup        string
	mu            sync.Mutex
	checkpoint    []byte
	responses     map[string][]byte
	reads, bytes  int
	remaining     int
	remote        GoSumDBReader
	slots         chan struct{}
	securityError bool
}

func (o *goSumDBOps) ReadRemote(path string) ([]byte, error) {
	if err := o.ctx.Err(); err != nil {
		return nil, err
	}
	o.mu.Lock()
	o.reads++
	data := o.responses[path]
	limit := o.responseLimit(path)
	if o.reads > maxGoSumDBResponses*2 || limit == 0 || len(data) > maxGoSumDBBytes-o.bytes {
		o.mu.Unlock()
		return nil, ErrGoChecksumAuthority
	}
	if len(data) != 0 {
		o.bytes += len(data)
		o.mu.Unlock()
		return bytes.Clone(data), nil
	}
	o.mu.Unlock()
	if o.remote == nil {
		return nil, ErrGoChecksumAuthority
	}
	select {
	case o.slots <- struct{}{}:
		defer func() { <-o.slots }()
	case <-o.ctx.Done():
		return nil, o.ctx.Err()
	}
	if err := o.ctx.Err(); err != nil {
		return nil, err
	}
	data, err := o.remote(o.ctx, path, limit)
	if err != nil || !o.validResponse(path, data) {
		return nil, ErrGoChecksumAuthority
	}
	if err := o.ctx.Err(); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(data) > maxGoSumDBBytes-o.bytes {
		return nil, ErrGoChecksumAuthority
	}
	o.bytes += len(data)
	if previous := o.responses[path]; previous != nil {
		if !bytes.Equal(previous, data) {
			return nil, ErrGoChecksumAuthority
		}
	} else {
		if len(o.responses) >= maxGoSumDBResponses || len(path)+len(data) > o.remaining {
			return nil, ErrGoChecksumAuthority
		}
		o.remaining -= len(path) + len(data)
		o.responses[path] = bytes.Clone(data)
	}
	return bytes.Clone(data), nil
}

func (o *goSumDBOps) responseLimit(path string) int64 {
	if len(path) > 2048 {
		return 0
	}
	if path == o.lookup {
		return 64 << 10
	}
	tile, err := tlog.ParseTilePath(strings.TrimPrefix(path, "/"))
	if !strings.HasPrefix(path, "/tile/") || err != nil || tile.H != 8 || tile.L < 0 || "/"+tile.Path() != path {
		return 0
	}
	return int64(tile.W * 32)
}

func (o *goSumDBOps) validResponse(path string, data []byte) bool {
	limit := o.responseLimit(path)
	return limit > 0 && len(data) > 0 && int64(len(data)) <= limit && (path == o.lookup || int64(len(data)) == limit)
}

func (o *goSumDBOps) ReadConfig(path string) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	switch path {
	case "key":
		return []byte(o.key), nil
	case o.name + "/latest":
		return bytes.Clone(o.checkpoint), nil
	}
	return nil, ErrGoChecksumAuthority
}

func (o *goSumDBOps) WriteConfig(path string, old, next []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if path != o.name+"/latest" || len(next) == 0 || len(next) > 16<<10 {
		return ErrGoChecksumAuthority
	}
	if !bytes.Equal(old, o.checkpoint) {
		return sumdb.ErrWriteConflict
	}
	o.checkpoint = bytes.Clone(next)
	return nil
}

func (o *goSumDBOps) ReadCache(string) ([]byte, error) { return nil, ErrGoChecksumAuthority }
func (o *goSumDBOps) WriteCache(string, []byte)        {}
func (o *goSumDBOps) Log(string)                       {}
func (o *goSumDBOps) SecurityError(string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.securityError = true
}
