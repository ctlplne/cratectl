// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
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
	VerifierKey string
	Checkpoint  []byte
	Responses   map[string][]byte
}

type GoSumDBVerification struct {
	Authority, Module, Version string
	ZIPHash, GoModHash         string
	Checkpoint                 []byte
}

// VerifyGoSumDB verifies BOTH standard h1 entries, the signed tree, record
// inclusion and consistency with the supplied checkpoint, using Go's standard
// sumdb client. It performs no network or filesystem operations. Its returned
// checkpoint is a proposal: a caller must atomically fence the current authority
// and prior checkpoint with artifact publication before trusting it durably.
// It does not establish freshness, publisher identity or package policy approval.
func VerifyGoSumDB(ctx context.Context, mod, version, zipHash, modHash string, input GoSumDBSnapshot) (GoSumDBVerification, error) {
	if err := ctx.Err(); err != nil {
		return GoSumDBVerification{}, err
	}
	if len(mod) > 512 || len(version) > 128 || module.Check(mod, version) != nil || module.CanonicalVersion(version) != version || !validGoH1(zipHash) || !validGoH1(modHash) || len(input.VerifierKey) > 4096 || len(input.Checkpoint) == 0 || len(input.Checkpoint) > 16<<10 || len(input.Responses) == 0 || len(input.Responses) > maxGoSumDBResponses {
		return GoSumDBVerification{}, ErrGoChecksumAuthority
	}
	if module.IsPseudoVersion(version) {
		if _, err := module.PseudoVersionTime(version); err != nil {
			return GoSumDBVerification{}, ErrGoChecksumAuthority
		}
	}
	verifier, err := note.NewVerifier(input.VerifierKey)
	if err != nil || len(verifier.Name()) > 255 {
		return GoSumDBVerification{}, ErrGoChecksumAuthority
	}
	pinned, err := note.Open(input.Checkpoint, note.VerifierList(verifier))
	if err != nil {
		return GoSumDBVerification{}, ErrGoChecksumAuthority
	}
	if _, err = tlog.ParseTree([]byte(pinned.Text)); err != nil {
		return GoSumDBVerification{}, ErrGoChecksumAuthority
	}
	escapedModule, _ := module.EscapePath(mod)
	escapedVersion, _ := module.EscapeVersion(version)
	lookup := "/lookup/" + escapedModule + "@" + escapedVersion
	ops := &goSumDBOps{ctx: ctx, key: input.VerifierKey, name: verifier.Name(), checkpoint: bytes.Clone(input.Checkpoint), responses: map[string][]byte{}}
	remaining := maxGoSumDBBytes - len(input.Checkpoint) - len(input.VerifierKey)
	for path, data := range input.Responses {
		if len(path) > 2048 || len(data) == 0 || len(data) > 64<<10 || len(path)+len(data) > remaining {
			return GoSumDBVerification{}, ErrGoChecksumAuthority
		}
		if path != lookup {
			tile, err := tlog.ParseTilePath(strings.TrimPrefix(path, "/"))
			if !strings.HasPrefix(path, "/tile/") || err != nil || tile.H != 8 || tile.L < 0 || len(data) != tile.W*32 {
				return GoSumDBVerification{}, ErrGoChecksumAuthority
			}
		}
		remaining -= len(path) + len(data)
		ops.responses[path] = bytes.Clone(data)
	}
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
	return GoSumDBVerification{Authority: verifier.Name(), Module: mod, Version: version, ZIPHash: zipHash, GoModHash: modHash, Checkpoint: bytes.Clone(ops.checkpoint)}, nil
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
	mu            sync.Mutex
	checkpoint    []byte
	responses     map[string][]byte
	reads, bytes  int
	securityError bool
}

func (o *goSumDBOps) ReadRemote(path string) ([]byte, error) {
	if err := o.ctx.Err(); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.reads++
	data := o.responses[path]
	if o.reads > maxGoSumDBResponses*2 || len(data) == 0 || len(data) > maxGoSumDBBytes-o.bytes {
		return nil, ErrGoChecksumAuthority
	}
	o.bytes += len(data)
	return bytes.Clone(data), nil
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
