// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb"
)

func TestGoChecksumCheckpointBindsCanonicalKeyAndOriginalSignedTree(t *testing.T) {
	f := checksumFuzzLog(t)
	got, err := ParseGoSumDBCheckpoint(f.key, f.empty)
	if err != nil || got.Authority != "cratectl-checksums.invalid" || got.KeyDigest != Digest([]byte(f.key)) || got.TreeSize != 0 || got.RootHash == "" {
		t.Fatal("configured signed checkpoint lost its key/tree binding", err)
	}
	other := checksumLog(t, "", "", "")
	parts := strings.SplitN(f.key, "+", 3)
	if !strings.Contains(parts[2], "+") {
		t.Fatal("fixture must cover base64 plus without treating it as another key separator")
	}
	parts[1] = strings.ToUpper(parts[1])
	if strings.Join(parts, "+") == f.key {
		parts[1] = "0" + parts[1]
	}
	for _, input := range []struct {
		key  string
		head []byte
	}{
		{strings.Join(parts, "+"), f.empty}, {other.key, f.empty}, {f.key, nil},
		{f.key, []byte("unsigned")}, {strings.Repeat("x", 4097), f.empty}, {f.key, bytes.Repeat([]byte{'x'}, 16<<10+1)},
	} {
		if out, err := ParseGoSumDBCheckpoint(input.key, input.head); !errors.Is(err, ErrGoChecksumAuthority) || out != (GoSumDBCheckpoint{}) {
			t.Fatal("checkpoint returned partial or ambiguous trust", err)
		}
	}
}

func TestGoChecksumCollectionCapturesOriginalProofAndReplaysOffline(t *testing.T) {
	f := checksumFuzzLog(t)
	// Cross a tile boundary so the actual standard client requests multiple
	// authenticated tiles. This is an in-memory external log, never a service.
	for n := 0; n < 260; n++ {
		if _, err := f.ops.Lookup(context.Background(), module.Version{Path: checksumTestModule, Version: fmt.Sprint("v1.3.", n)}); err != nil {
			t.Fatal(err)
		}
	}
	server := sumdbServer(f)
	var calls atomic.Int32
	read := func(ctx context.Context, path string, limit int64) ([]byte, error) {
		calls.Add(1)
		if !strings.HasPrefix(path, "/lookup/") && !strings.HasPrefix(path, "/tile/") || limit < 1 || limit > 64<<10 {
			t.Error("collector requested an unauthorized path or unbounded body")
			return nil, errors.New("invalid fixture request")
		}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil))
		if response.Code != 200 {
			return nil, errors.New("fixture has no such tile")
		}
		if int64(response.Body.Len()) > limit {
			return nil, errors.New("fixture exceeded read bound")
		}
		return bytes.Clone(response.Body.Bytes()), nil
	}
	trust := GoSumDBSnapshot{VerifierKey: f.key, Checkpoint: f.empty}
	verified, proof, err := CollectGoSumDB(context.Background(), checksumTestModule, checksumTestVersion, f.zipHash, f.modHash, trust, read)
	if err != nil || calls.Load() < 3 || len(proof.Responses) < 3 || !bytes.Equal(proof.Checkpoint, f.empty) || bytes.Equal(verified.Checkpoint, f.empty) {
		t.Fatal("collection failed to bind and retain an original multi-tile proof", calls.Load(), err)
	}
	offline, err := verifyChecksumFixture(f, proof)
	if err != nil || !reflect.DeepEqual(offline, verified) {
		t.Fatal("captured proof did not independently replay without its reader", err)
	}
	proof.Checkpoint[0] ^= 1
	if !bytes.Equal(trust.Checkpoint, f.empty) {
		t.Fatal("captured proof aliases caller trust")
	}
}

func sumdbServer(f checksumLogFixture) http.Handler { return sumdb.NewServer(f.ops) }

func TestGoChecksumCollectionRejectsPartialOversizedAndUntrustedReads(t *testing.T) {
	f := checksumFuzzLog(t)
	fixture := f.snapshot(t, f.empty, 1)
	for _, scenario := range []string{"nil-reader", "mixed-proof", "bad-trust", "oversized", "missing-tile", "reader-error", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			trust := GoSumDBSnapshot{VerifierKey: f.key, Checkpoint: f.empty}
			calls := 0
			var read GoSumDBReader = func(ctx context.Context, path string, limit int64) ([]byte, error) {
				calls++
				if scenario == "oversized" {
					return make([]byte, limit+1), nil
				}
				if scenario == "reader-error" {
					return nil, errors.New("private provider failure detail")
				}
				if scenario == "cancelled" {
					cancel()
					return nil, ctx.Err()
				}
				if scenario == "missing-tile" && strings.HasPrefix(path, "/tile/") {
					return nil, errors.New("missing")
				}
				return bytes.Clone(fixture.Responses[path]), nil
			}
			switch scenario {
			case "nil-reader":
				read = nil
			case "mixed-proof":
				trust.Responses = fixture.Responses
			case "bad-trust":
				trust.Checkpoint = nil
			}
			verified, proof, err := CollectGoSumDB(ctx, checksumTestModule, checksumTestVersion, f.zipHash, f.modHash, trust, read)
			want := ErrGoChecksumAuthority
			if scenario == "cancelled" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || !reflect.DeepEqual(verified, GoSumDBVerification{}) || !reflect.DeepEqual(proof, GoSumDBSnapshot{}) || strings.Contains(err.Error(), "private provider") {
				t.Fatal("failed collection returned partial trust/proof or private error detail", err)
			}
			if (scenario == "nil-reader" || scenario == "mixed-proof" || scenario == "bad-trust") && calls != 0 {
				t.Fatal("invalid configuration contacted its reader")
			}
		})
	}
}

func TestGoChecksumCollectionBoundsConcurrentReadersAndCancelsWaiters(t *testing.T) {
	f := checksumFuzzLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ops, err := prepareGoSumDB(ctx, checksumTestModule, checksumTestVersion, f.zipHash, f.modHash, GoSumDBSnapshot{VerifierKey: f.key, Checkpoint: f.empty})
	if err != nil {
		t.Fatal(err)
	}
	ops.slots = make(chan struct{}, 2)
	entered := make(chan struct{}, 10)
	var active, peak, calls atomic.Int32
	ops.remote = func(ctx context.Context, _ string, limit int64) ([]byte, error) {
		calls.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var workers sync.WaitGroup
	for n := 0; n < 10; n++ {
		workers.Add(1)
		go func(n int) { defer workers.Done(); _, _ = ops.ReadRemote(fmt.Sprintf("/tile/8/0/%03d.p/1", n)) }(n)
	}
	for n := 0; n < 2; n++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("bounded reader slots did not start")
		}
	}
	cancel()
	workers.Wait()
	if peak.Load() > 2 || active.Load() != 0 || calls.Load() != 2 {
		t.Fatal("reader concurrency escaped its bound or cancellation", peak.Load(), active.Load())
	}
}

func FuzzGoChecksumCollectedProof(f *testing.F) {
	fixture := checksumFuzzLog(f)
	snapshot := fixture.snapshot(f, fixture.empty, 1)
	lookup, tile := "", ""
	for path, data := range snapshot.Responses {
		isLookup := strings.HasPrefix(path, "/lookup/")
		if isLookup {
			lookup = path
		} else {
			tile = path
		}
		f.Add(isLookup, data)
	}
	f.Add(true, []byte("malformed lookup\n"))
	f.Add(false, []byte("malformed tile"))
	f.Fuzz(func(t *testing.T, isLookup bool, data []byte) {
		target := tile
		if isLookup {
			target = lookup
		}
		read := func(_ context.Context, path string, limit int64) ([]byte, error) {
			body := snapshot.Responses[path]
			if path == target {
				body = data
			}
			if int64(len(body)) > limit || len(body) == 0 {
				return nil, ErrGoChecksumAuthority
			}
			return body, nil
		}
		verified, proof, err := CollectGoSumDB(context.Background(), checksumTestModule, checksumTestVersion, fixture.zipHash, fixture.modHash, GoSumDBSnapshot{VerifierKey: snapshot.VerifierKey, Checkpoint: snapshot.Checkpoint}, read)
		if bytes.Equal(data, snapshot.Responses[target]) && err != nil {
			t.Fatal("valid worker seed lost its authenticated collection path", err)
		}
		if err != nil {
			if !errors.Is(err, ErrGoChecksumAuthority) || !reflect.DeepEqual(verified, GoSumDBVerification{}) || !reflect.DeepEqual(proof, GoSumDBSnapshot{}) {
				t.Fatal("failed collection returned partial trust or proof", err)
			}
			return
		}
		offline, err := verifyChecksumFixture(fixture, proof)
		if err != nil || !reflect.DeepEqual(offline, verified) {
			t.Fatal("accepted collected proof cannot replay independently offline", err)
		}
	})
}
