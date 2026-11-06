// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const checksumTestModule = "go.cratectl.invalid/Owned/module"
const checksumTestVersion = "v1.2.3"

type checksumLogFixture struct {
	key, signer, zipHash, modHash string
	ops                           *sumdb.TestServer
	empty                         []byte
}

func checksumLog(t testing.TB, signer, key, record string) checksumLogFixture {
	t.Helper()
	var err error
	if signer == "" {
		signer, key, err = note.GenerateKey(rand.Reader, "cratectl-checksums.invalid")
		if err != nil {
			t.Fatal(err)
		}
	}
	zipHash, _ := GoModHash([]byte("owned logical ZIP contents"))
	modHash, _ := GoModHash([]byte("module " + checksumTestModule + "\n"))
	if record == "" {
		record = checksumTestModule + " " + checksumTestVersion + " " + zipHash + "\n" + checksumTestModule + " " + checksumTestVersion + "/go.mod " + modHash + "\n"
	}
	ops := sumdb.NewTestServer(signer, func(path, vers string) ([]byte, error) {
		if path == checksumTestModule && vers == checksumTestVersion {
			return []byte(record), nil
		}
		return []byte(path + " " + vers + " " + zipHash + "\n" + path + " " + vers + "/go.mod " + modHash + "\n"), nil
	})
	empty, err := ops.Signed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return checksumLogFixture{key: key, signer: signer, zipHash: zipHash, modHash: modHash, ops: ops, empty: empty}
}

func (f checksumLogFixture) snapshot(t testing.TB, pinned []byte, records int) GoSumDBSnapshot {
	t.Helper()
	m, _ := module.EscapePath(checksumTestModule)
	path := "/lookup/" + m + "@" + checksumTestVersion
	response := httptest.NewRecorder()
	sumdb.NewServer(f.ops).ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusOK {
		t.Fatal("in-memory external checksum fixture failed", response.Code)
	}
	responses := map[string][]byte{path: bytes.Clone(response.Body.Bytes())}
	for width := 1; width <= records; width++ {
		tile := tlog.Tile{H: 8, L: 0, N: 0, W: width}
		data, err := f.ops.ReadTileData(context.Background(), tile)
		if err != nil {
			t.Fatal(err)
		}
		responses["/"+tile.Path()] = data
	}
	return GoSumDBSnapshot{VerifierKey: f.key, Checkpoint: bytes.Clone(pinned), Responses: responses}
}

func verifyChecksumFixture(f checksumLogFixture, snapshot GoSumDBSnapshot) (GoSumDBVerification, error) {
	return VerifyGoSumDB(context.Background(), checksumTestModule, checksumTestVersion, f.zipHash, f.modHash, snapshot)
}

func TestGoChecksumOfflineProofChecksBothHashesAndAdvancesConsistentTimeline(t *testing.T) {
	f := checksumLog(t, "", "", "")
	first := f.snapshot(t, f.empty, 1)
	got, err := verifyChecksumFixture(f, first)
	if err != nil || got.Authority != "cratectl-checksums.invalid" || got.Module != checksumTestModule || got.Version != checksumTestVersion || got.ZIPHash != f.zipHash || got.GoModHash != f.modHash || bytes.Equal(got.Checkpoint, first.Checkpoint) {
		t.Fatal("offline proof did not bind both hashes and advance checkpoint", err)
	}
	one := bytes.Clone(got.Checkpoint)
	if _, err := f.ops.Lookup(context.Background(), module.Version{Path: checksumTestModule, Version: "v1.2.4"}); err != nil {
		t.Fatal(err)
	}
	second := f.snapshot(t, one, 2)
	got, err = verifyChecksumFixture(f, second)
	if err != nil || bytes.Equal(got.Checkpoint, one) {
		t.Fatal("consistent extension rejected", err)
	}
	two := bytes.Clone(got.Checkpoint)
	// Immutable older lookup bytes remain valid if their tree is proven to be
	// on the retained newer timeline. This is not a freshness claim.
	for path, response := range first.Responses {
		if strings.HasPrefix(path, "/lookup/") {
			second.Responses[path] = response
		}
	}
	second.Checkpoint = two
	got, err = verifyChecksumFixture(f, second)
	if err != nil || !bytes.Equal(got.Checkpoint, two) {
		t.Fatal("retained timeline rolled back or valid old proof rejected", err)
	}
	got.Checkpoint[0] ^= 1
	if !bytes.Equal(second.Checkpoint, two) {
		t.Fatal("verification result aliases caller checkpoint")
	}
}

func TestGoChecksumOfflineProofRejectsForgeryMissingEvidenceAndWrongIdentity(t *testing.T) {
	for _, scenario := range []string{"lookup-forgery", "tile-forgery", "missing-tile", "missing-mod", "duplicate-zip", "wrong-zip", "wrong-mod", "wrong-key", "unsigned-checkpoint", "empty-checkpoint", "malformed-checkpoint", "noncanonical-hash", "wrong-coordinate"} {
		t.Run(scenario, func(t *testing.T) {
			f := checksumLog(t, "", "", "")
			if scenario == "missing-mod" || scenario == "duplicate-zip" {
				line := checksumTestModule + " " + checksumTestVersion + " " + f.zipHash + "\n"
				if scenario == "duplicate-zip" {
					line += line + checksumTestModule + " " + checksumTestVersion + "/go.mod " + f.modHash + "\n"
				}
				f = checksumLog(t, f.signer, f.key, line)
			}
			snapshot := f.snapshot(t, f.empty, 1)
			mod, version, zipHash, modHash := checksumTestModule, checksumTestVersion, f.zipHash, f.modHash
			switch scenario {
			case "lookup-forgery":
				for path, data := range snapshot.Responses {
					if strings.HasPrefix(path, "/lookup/") {
						snapshot.Responses[path] = bytes.Replace(data, []byte(f.zipHash), []byte(f.modHash), 1)
					}
				}
			case "tile-forgery", "missing-tile":
				for path, data := range snapshot.Responses {
					if strings.HasPrefix(path, "/tile/") {
						if scenario == "missing-tile" {
							delete(snapshot.Responses, path)
						} else {
							data[0] ^= 1
						}
					}
				}
			case "wrong-zip":
				zipHash = f.modHash
			case "wrong-mod":
				modHash = f.zipHash
			case "wrong-key":
				snapshot.VerifierKey = checksumLog(t, "", "", "").key
			case "unsigned-checkpoint":
				snapshot.Checkpoint = []byte("go.sum database tree\n0\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
			case "empty-checkpoint":
				snapshot.Checkpoint = nil
			case "malformed-checkpoint":
				snapshot.Checkpoint[0] ^= 1
			case "noncanonical-hash":
				zipHash = strings.TrimSuffix(f.zipHash, "=")
			case "wrong-coordinate":
				version = "v1.2.4"
			}
			got, err := VerifyGoSumDB(context.Background(), mod, version, zipHash, modHash, snapshot)
			if !errors.Is(err, ErrGoChecksumAuthority) || !reflect.DeepEqual(got, GoSumDBVerification{}) || strings.Contains(err.Error(), f.key) {
				t.Fatal("invalid proof returned success, partial trust or untrusted detail", err)
			}
		})
	}
}

func TestGoChecksumOfflineProofRejectsSignedForkWithoutExiting(t *testing.T) {
	a := checksumLog(t, "", "", "")
	if _, err := verifyChecksumFixture(a, a.snapshot(t, a.empty, 1)); err != nil {
		t.Fatal(err)
	}
	pinned, err := a.ops.Signed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	changed := checksumTestModule + " " + checksumTestVersion + " " + a.modHash + "\n" + checksumTestModule + " " + checksumTestVersion + "/go.mod " + a.modHash + "\n"
	b := checksumLog(t, a.signer, a.key, changed)
	got, err := VerifyGoSumDB(context.Background(), checksumTestModule, checksumTestVersion, a.modHash, a.modHash, b.snapshot(t, pinned, 1))
	if !errors.Is(err, ErrGoChecksumAuthority) || !errors.Is(err, ErrGoChecksumFork) || !reflect.DeepEqual(got, GoSumDBVerification{}) {
		t.Fatal("same-key signed fork accepted", err)
	}
}

func TestGoChecksumOfflineProofBoundsBeforeParsingAndHonorsCancellation(t *testing.T) {
	f := checksumLog(t, "", "", "")
	for _, scenario := range []string{"record-bytes", "tile-bytes", "tile-height", "data-tile", "other-lookup", "path-alias", "response-count", "total-bytes", "key-bytes", "checkpoint-bytes"} {
		t.Run(scenario, func(t *testing.T) {
			snapshot := f.snapshot(t, f.empty, 1)
			switch scenario {
			case "record-bytes":
				for path := range snapshot.Responses {
					if strings.HasPrefix(path, "/lookup/") {
						snapshot.Responses[path] = bytes.Repeat([]byte{'x'}, 64<<10+1)
					}
				}
			case "tile-bytes":
				snapshot.Responses["/tile/8/0/000.p/1"] = []byte{1}
			case "tile-height":
				snapshot.Responses["/tile/7/0/000.p/1"] = make([]byte, 32)
			case "data-tile":
				snapshot.Responses["/tile/8/data/000.p/1"] = make([]byte, 32)
			case "other-lookup":
				snapshot.Responses["/lookup/other.invalid/module@v1.2.3"] = []byte("untrusted")
			case "path-alias":
				snapshot.Responses["//tile/8/0/000.p/1"] = make([]byte, 32)
			case "response-count":
				for n := 0; n < 129; n++ {
					snapshot.Responses[fmt.Sprint("/invalid/", n)] = []byte("x")
				}
			case "total-bytes":
				snapshot.Responses = map[string][]byte{}
				for n := int64(0); n < 128; n++ {
					tile := tlog.Tile{H: 8, L: 0, N: n, W: 256}
					snapshot.Responses["/"+tile.Path()] = make([]byte, 8192)
				}
			case "key-bytes":
				snapshot.VerifierKey = strings.Repeat("x", 4097)
			case "checkpoint-bytes":
				snapshot.Checkpoint = bytes.Repeat([]byte{'x'}, 16<<10+1)
			}
			got, err := verifyChecksumFixture(f, snapshot)
			if !errors.Is(err, ErrGoChecksumAuthority) || !reflect.DeepEqual(got, GoSumDBVerification{}) {
				t.Fatal("proof escaped budget or authority path", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := VerifyGoSumDB(ctx, checksumTestModule, checksumTestVersion, f.zipHash, f.modHash, f.snapshot(t, f.empty, 1))
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, GoSumDBVerification{}) {
		t.Fatal("cancellation returned partial verification", err)
	}
}

func checksumFuzzLog(t testing.TB) checksumLogFixture {
	t.Helper()
	// Public synthetic seed, solely for this in-memory fuzz fixture. Every
	// coordinator/worker must derive identical signed baseline bytes. No test
	// signing key is used by cratectl or by any external service.
	signer, key, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)), "cratectl-checksums.invalid")
	if err != nil {
		t.Fatal(err)
	}
	return checksumLog(t, signer, key, "")
}

func TestGoChecksumFuzzFixtureIsStableAcrossWorkerInitialization(t *testing.T) {
	a, b := checksumFuzzLog(t), checksumFuzzLog(t)
	first, second := a.snapshot(t, a.empty, 1), b.snapshot(t, b.empty, 1)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("coordinator and worker initialization produce different signed fuzz seeds")
	}
	if _, err := verifyChecksumFixture(b, first); err != nil {
		t.Fatal("coordinator seed cannot replay through an independently initialized worker", err)
	}
}

func FuzzGoChecksumOfflineLookup(f *testing.F) {
	fixture := checksumFuzzLog(f)
	snapshot := fixture.snapshot(f, fixture.empty, 1)
	lookup := ""
	for path, data := range snapshot.Responses {
		if strings.HasPrefix(path, "/lookup/") {
			lookup = path
			f.Add(data)
		}
	}
	f.Add([]byte("malformed record\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		responses := make(map[string][]byte, len(snapshot.Responses))
		for path, original := range snapshot.Responses {
			responses[path] = original
		}
		responses[lookup] = data
		input := GoSumDBSnapshot{VerifierKey: snapshot.VerifierKey, Checkpoint: snapshot.Checkpoint, Responses: responses}
		got, err := verifyChecksumFixture(fixture, input)
		if bytes.Equal(data, snapshot.Responses[lookup]) && err != nil {
			t.Fatal("valid coordinator seed lost its authenticated worker path", err)
		}
		if err != nil {
			if !errors.Is(err, ErrGoChecksumAuthority) || !reflect.DeepEqual(got, GoSumDBVerification{}) {
				t.Fatal("invalid proof returned partial trust or unbounded error detail", err)
			}
			return
		}
		if got.Module != checksumTestModule || got.Version != checksumTestVersion || got.ZIPHash != fixture.zipHash || got.GoModHash != fixture.modHash || len(got.Checkpoint) == 0 || len(data) > 64<<10 {
			t.Fatal("accepted proof escaped identity or byte bounds")
		}
	})
}
