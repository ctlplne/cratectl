// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"ctlplne.dev/cratectl/internal/store"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
)

func collectionUnitRoot(t *testing.T) (*os.Root, string) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "collection")
	root, dir, err := openCollectionDirectory(path, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close(); root.Close() })
	return root, path
}
func collectionResponse(object blob.Object, generation, start, end int64, payload []byte) *http.Response {
	h := http.Header{}
	h.Set("ETag", `"sha256:`+object.Digest+`"`)
	h.Set("X-Checksum-Sha256", object.Digest)
	h.Set("X-Cratectl-Export-Generation", strconv.FormatInt(generation, 10))
	h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, object.Size))
	return &http.Response{StatusCode: 206, Header: h, ContentLength: end - start + 1, Body: io.NopCloser(bytes.NewReader(payload))}
}
func TestCollectionInterruptedRangeResumesOnlyExactVerifiedPrivateBytes(t *testing.T) {
	root, path := collectionUnitRoot(t)
	payload := bytes.Repeat([]byte("owned inert bytes/"), 10000)
	object := blob.Object{Digest: crypt.Digest(payload), Size: int64(len(payload))}
	calls := 0
	c := collectionHTTP{base: "https://cratectl.invalid", token: "owned-standin", id: strings.Repeat("a", 64), generation: 1, chunk: 64 << 10}
	c.client = &http.Client{Transport: journalTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer owned-standin" || r.Header.Get("Accept-Encoding") != "identity" || r.URL.Query().Get("generation") != "1" {
			t.Fatal("authority or current generation changed")
		}
		var start, end int64
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
			t.Fatal(err)
		}
		part := payload[start : end+1]
		if calls == 2 {
			part = part[:17]
		}
		return collectionResponse(object, 1, start, end, part), nil
	})}
	if err := c.download(context.Background(), root, "original.zip", "zip", object); err == nil {
		t.Fatal("partial body reported completion")
	}
	before, err := os.ReadFile(filepath.Join(path, "original.zip"))
	if err != nil || len(before) != (64<<10)+17 || !bytes.Equal(before, payload[:len(before)]) {
		t.Fatal("partial checkpoint was lost", err, len(before))
	}
	c.generation = 2
	c.client = &http.Client{Transport: journalTransport(func(r *http.Request) (*http.Response, error) {
		var start, end int64
		fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end)
		if r.URL.Query().Get("generation") != "2" || start < int64(len(before)) {
			t.Fatal("resume restarted or retained stale generation")
		}
		return collectionResponse(object, 2, start, end, payload[start:end+1]), nil
	})}
	if err := c.download(context.Background(), root, "original.zip", "zip", object); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(path, "original.zip"))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("resumed bytes changed", err)
	}
}
func TestCollectionRejectsChangedRangeAndCurrentIdentityWithoutSuccess(t *testing.T) {
	for _, scenario := range []string{"status", "range", "length", "digest", "etag", "generation", "duplicate", "body", "excess", "overflow-existing", "tampered-prefix", "request-budget", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			root, path := collectionUnitRoot(t)
			payload := []byte("exact owned bytes")
			object := blob.Object{Digest: crypt.Digest(payload), Size: int64(len(payload))}
			if scenario == "overflow-existing" || scenario == "tampered-prefix" {
				b := []byte("bad")
				if scenario == "overflow-existing" {
					b = bytes.Repeat([]byte("x"), len(payload)+1)
				}
				if err := os.WriteFile(filepath.Join(path, "original.zip"), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			c := collectionHTTP{base: "https://cratectl.invalid", id: strings.Repeat("b", 64), generation: 1, chunk: 64 << 10}
			c.client = &http.Client{Transport: journalTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				var start, end int64
				fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end)
				response := collectionResponse(object, 1, start, end, payload[start:end+1])
				switch scenario {
				case "status":
					response.StatusCode = 200
				case "range":
					response.Header.Set("Content-Range", "bytes 1-2/3")
				case "length":
					response.ContentLength++
				case "digest":
					response.Header.Set("X-Checksum-Sha256", strings.Repeat("c", 64))
				case "etag":
					response.Header.Set("ETag", `W/"changed"`)
				case "generation":
					response.Header.Set("X-Cratectl-Export-Generation", "2")
				case "duplicate":
					response.Header.Add("ETag", response.Header.Get("ETag"))
				case "body":
					response.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", int(end-start+1))))
				case "excess":
					response.Body = io.NopCloser(bytes.NewReader(append(bytes.Clone(payload), 1)))
				}
				return response, nil
			})}
			ctx := context.Background()
			if scenario == "request-budget" {
				c.requests = 16384
			}
			if scenario == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := c.download(ctx, root, "original.zip", "zip", object); err == nil {
				t.Fatal("changed or incomplete transfer accepted")
			}
			if (scenario == "overflow-existing" || scenario == "request-budget" || scenario == "cancelled") && calls != 0 {
				t.Fatal("unsafe or exhausted transfer contacted server")
			}
			if _, err := os.Stat(filepath.Join(path, "receipt.json")); !os.IsNotExist(err) {
				t.Fatal("failed range exposed a receipt")
			}
		})
	}
}
func TestCollectionCopiesAndRehashesResumedLocalProof(t *testing.T) {
	root, path := collectionUnitRoot(t)
	payload := []byte("owned complete original journal and proof")
	object := blob.Object{Digest: crypt.Digest(payload), Size: int64(len(payload))}
	if err := os.WriteFile(filepath.Join(path, "journal.jsonl"), payload[:9], 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyCollectionLocal(context.Background(), root, "journal.jsonl", bytes.NewReader(payload), object, 7); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(path, "journal.jsonl"))
	if !bytes.Equal(got, payload) {
		t.Fatal("local resume overwrote its prefix")
	}
	if err := os.WriteFile(filepath.Join(path, "journal.jsonl"), []byte("wrong"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyCollectionLocal(context.Background(), root, "journal.jsonl", bytes.NewReader(payload), object, 7); err == nil {
		t.Fatal("changed local prefix accepted")
	}
}
func TestCollectionDirectoryLockBindingsAndFileOwnership(t *testing.T) {
	root, path := collectionUnitRoot(t)
	if _, _, err := openCollectionDirectory(path, false); err == nil {
		t.Fatal("existing collection overwritten")
	}
	if other, dir, err := openCollectionDirectory(path, true); err == nil {
		dir.Close()
		other.Close()
		t.Fatal("two collectors admitted")
	}
	binding := collectionBinding{Profile: goCollectionProfile, Authority: "https://cratectl.invalid", ExportID: strings.Repeat("a", 64)}
	if err := bindCollection(root, binding, false); err != nil {
		t.Fatal(err)
	}
	if err := bindCollection(root, binding, true); err != nil {
		t.Fatal(err)
	}
	changed := binding
	changed.Authority = "https://other.invalid"
	if err := bindCollection(root, changed, true); err == nil {
		t.Fatal("resume authority changed")
	}
	outside := filepath.Join(filepath.Dir(path), "outside")
	if err := os.WriteFile(outside, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"symlink", "hardlink", "public"} {
		target := filepath.Join(path, "original.zip")
		switch kind {
		case "symlink":
			if err := os.Symlink(outside, target); err != nil {
				t.Fatal(err)
			}
		case "hardlink":
			if err := os.Link(outside, target); err != nil {
				t.Fatal(err)
			}
		case "public":
			if err := os.WriteFile(target, []byte("public"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		if f, err := openCollectionMember(root, "original.zip"); err == nil {
			f.Close()
			t.Fatal("unsafe file admitted", kind)
		}
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := os.ReadFile(outside)
	if string(got) != "retained" {
		t.Fatal("outside file changed")
	}
}
func TestCollectionRejectsUntrustedJournalBeforeConfigurationOrOutput(t *testing.T) {
	dir := t.TempDir()
	args := []string{"--config", filepath.Join(dir, "absent-config"), "--export-id", strings.Repeat("a", 64), "--generation", "1", "--repository", "owned", "--module", "go.cratectl.invalid/Owned/app", "--version", "v1.0.0", "--journal-file", filepath.Join(dir, "absent-journal"), "--output-directory", filepath.Join(dir, "out")}
	var out bytes.Buffer
	if err := runGoExportCollect(args, &out); err == nil || out.Len() != 0 {
		t.Fatal("missing independent proof admitted")
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Fatal("untrusted proof created output")
	}
	for _, bad := range [][]string{nil, append(cloneCollectionArgs(args), "--generation", "0"), append(cloneCollectionArgs(args), "--chunk-bytes", "1"), append(cloneCollectionArgs(args), "--max-bytes", "0")} {
		if err := runGoExportCollect(bad, &out); err == nil || out.Len() != 0 {
			t.Fatal("invalid collect arguments admitted")
		}
	}
}
func cloneCollectionArgs(v []string) []string { return append([]string(nil), v...) }
func TestCollectionClientRejectsCredentialURLsAndUnsafeTokens(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("owned-standin"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"https://user:secret@cratectl.invalid", "https://cratectl.invalid/path", "https://cratectl.invalid?token=owned", "http://localhost:38443", "http://192.0.2.1:38443", "https://cratectl.invalid#fragment"} {
		raw, _ := json.Marshal(map[string]any{"version": 1, "url": target, "token_file": token, "ca_file": ""})
		path := filepath.Join(dir, "client.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, close, err := collectionClient(path); err == nil {
			close()
			t.Fatal("unsafe authority admitted")
		}
	}
}
func FuzzCollectionIdentityHeaders(f *testing.F) {
	f.Add("abc", "1", false)
	f.Add(strings.Repeat("a", 64), "1", false)
	f.Add(strings.Repeat("a", 64), "1", true)
	f.Add(strings.Repeat("a", 64), "01", false)
	f.Fuzz(func(t *testing.T, digest, generation string, duplicate bool) {
		if len(digest) > 1024 || len(generation) > 1024 {
			return
		}
		expected := blob.Object{Digest: strings.Repeat("a", 64), Size: 7}
		response := collectionResponse(expected, 1, 0, 6, []byte("fixture"))
		response.Header.Set("X-Checksum-Sha256", digest)
		response.Header.Set("X-Cratectl-Export-Generation", generation)
		if duplicate {
			response.Header.Add("ETag", response.Header.Get("ETag"))
		}
		accepted := collectionHeaders(response, expected, 1)
		if accepted != (digest == expected.Digest && generation == "1" && !duplicate) {
			t.Fatal("ambiguous serving identity accepted")
		}
		n, ok := receiptPendingGeneration("receipt." + generation + ".pending")
		want, err := strconv.ParseInt(generation, 10, 64)
		canonical := err == nil && want > 0 && strconv.FormatInt(want, 10) == generation
		if ok != canonical || ok && n != want {
			t.Fatal("ambiguous pending generation accepted")
		}

	})
}

func TestCollectionCurrentSessionCanonicalAndLargeGenerationBinding(t *testing.T) {
	now := time.Now().UTC()
	object := blob.Object{Digest: strings.Repeat("a", 64), Size: 123}
	m := store.GoExportManifest{Repository: "owned", Module: "go.cratectl.invalid/Owned/app", Version: "v1.0.0", SourceRevision: 3}
	c := collectionHTTP{base: "https://cratectl.invalid", id: strings.Repeat("b", 64), generation: 9007199254740993}
	valid := store.GoExportSession{ID: c.id, Generation: c.generation, Manifest: object, Repository: m.Repository, Module: m.Module, Version: m.Version, SourceRevision: 3, CreatedSequence: 9, State: "open", ServerTime: now, ExpiresAt: now.Add(time.Hour)}
	for _, scenario := range []string{"valid", "precision", "duplicate", "case", "null", "expired", "cancelled", "identity", "oversize", "unknown", "missing-newline"} {
		t.Run(scenario, func(t *testing.T) {
			session := valid
			switch scenario {
			case "precision":
				session.Generation--
			case "expired":
				session.ExpiresAt = now
			case "cancelled":
				session.State = "cancelled"
			case "identity":
				session.ID = strings.Repeat("c", 64)
			}
			raw := collectionJSON(session)
			switch scenario {
			case "duplicate":
				raw = append([]byte(`{"id":"`+c.id+`",`), raw[1:]...)
			case "case":
				raw = bytes.Replace(raw, []byte(`"id":`), []byte(`"ID":`), 1)
			case "null":
				raw = bytes.Replace(raw, []byte(`"generation":9007199254740993`), []byte(`"generation":null`), 1)
			case "oversize":
				raw = bytes.Repeat([]byte("x"), 8193)
			case "unknown":
				raw = append([]byte(`{"unexpected":true,`), raw[1:]...)
			case "missing-newline":
				raw = bytes.TrimSuffix(raw, []byte("\n"))
			}
			c.client = &http.Client{Transport: journalTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
			})}
			err := c.checkCurrent(context.Background(), m, object, 9)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("current session binding", scenario, err)
			}
		})
	}
}

func TestCollectionPendingBindingAndReceiptResumeAcrossRenewal(t *testing.T) {
	root, path := collectionUnitRoot(t)
	binding := collectionBinding{Profile: goCollectionProfile, Authority: "https://cratectl.invalid", ExportID: strings.Repeat("a", 64)}
	expectedBinding := collectionJSON(binding)
	if err := os.WriteFile(filepath.Join(path, collectionBindingPending), expectedBinding[:128], 0600); err != nil {
		t.Fatal(err)
	}
	if err := bindCollection(root, binding, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(path, "bindings.json")); !bytes.Equal(got, expectedBinding) {
		t.Fatal("pending binding changed")
	}
	if _, err := os.Stat(filepath.Join(path, collectionBindingPending)); !os.IsNotExist(err) {
		t.Fatal("binding alias was retained")
	}
	original := collectionJSON(goCollectionReceipt{Binding: binding, CollectedGeneration: 1, BytesVerified: true})
	if err := os.WriteFile(filepath.Join(path, "receipt.1.pending"), original[:128], 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := publishCollectionReceipt(root, binding, 2, true)
	if err != nil || !bytes.Equal(actual, original) {
		t.Fatal("renewed generation changed earlier completion intent", err)
	}
	if got, _ := os.ReadFile(filepath.Join(path, "receipt.json")); !bytes.Equal(got, original) {
		t.Fatal("completed receipt bytes changed")
	}
	if _, err := os.Stat(filepath.Join(path, "receipt.1.pending")); !os.IsNotExist(err) {
		t.Fatal("receipt alias retained")
	}
}
func TestCollectionPostLinkRecoveryRequiresOnlyItsExactTwoNames(t *testing.T) {
	for _, scenario := range []string{"own-two-links", "outside-link", "wrong-alias", "extra-link", "corrupt-complete"} {
		t.Run(scenario, func(t *testing.T) {
			root, path := collectionUnitRoot(t)
			binding := collectionBinding{Profile: goCollectionProfile, Authority: "https://cratectl.invalid", ExportID: strings.Repeat("b", 64)}
			expected := collectionJSON(binding)
			if err := os.WriteFile(filepath.Join(path, "bindings.json"), expected, 0600); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(filepath.Dir(path), "unrelated")
			switch scenario {
			case "own-two-links":
				if err := os.Link(filepath.Join(path, "bindings.json"), filepath.Join(path, collectionBindingPending)); err != nil {
					t.Fatal(err)
				}
			case "outside-link":
				if err := os.Link(filepath.Join(path, "bindings.json"), outside); err != nil {
					t.Fatal(err)
				}
			case "wrong-alias":
				if err := os.WriteFile(filepath.Join(path, collectionBindingPending), expected, 0600); err != nil {
					t.Fatal(err)
				}
			case "extra-link":
				for _, name := range []string{filepath.Join(path, collectionBindingPending), outside} {
					if err := os.Link(filepath.Join(path, "bindings.json"), name); err != nil {
						t.Fatal(err)
					}
				}
			case "corrupt-complete":
				if err := os.WriteFile(filepath.Join(path, "bindings.json"), []byte("incomplete final"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := bindCollection(root, binding, true)
			if (err == nil) != (scenario == "own-two-links") {
				t.Fatal("publication recovery admitted unrelated/corrupt state", scenario, err)
			}
			if scenario == "own-two-links" {
				if _, err := os.Stat(filepath.Join(path, collectionBindingPending)); !os.IsNotExist(err) {
					t.Fatal("valid alias not removed")
				}
				info, err := os.Stat(filepath.Join(path, "bindings.json"))
				if err != nil || collectionFileLinks(info) != 1 {
					t.Fatal("published metadata still shared")
				}
			}
			if scenario == "outside-link" || scenario == "extra-link" {
				if got, _ := os.ReadFile(outside); !bytes.Equal(got, expected) {
					t.Fatal("unrelated alias modified")
				}
			}
		})
	}
}
func TestCollectionCorruptFutureOrMultiplePendingIntentIsPreserved(t *testing.T) {
	for _, scenario := range []string{"bad-prefix", "future", "leading-zero", "multiple", "unbound-data", "receipt-mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			root, path := collectionUnitRoot(t)
			binding := collectionBinding{Profile: goCollectionProfile, Authority: "https://cratectl.invalid", ExportID: strings.Repeat("c", 64)}
			if scenario == "unbound-data" {
				if err := os.WriteFile(filepath.Join(path, "original.zip"), []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := bindCollection(root, binding, true); err == nil {
					t.Fatal("unbound payload acquired a new identity")
				}
				return
			}
			if err := bindCollection(root, binding, false); err != nil {
				t.Fatal(err)
			}
			pending := "receipt.1.pending"
			body := []byte("corrupt prefix")
			switch scenario {
			case "future":
				pending = "receipt.3.pending"
			case "leading-zero":
				pending = "receipt.01.pending"
			case "multiple":
				if err := os.WriteFile(filepath.Join(path, "receipt.2.pending"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "receipt-mismatch":
				if err := os.WriteFile(filepath.Join(path, "receipt.json"), collectionJSON(goCollectionReceipt{Binding: binding, CollectedGeneration: 2, BytesVerified: true}), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(path, pending), body, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := publishCollectionReceipt(root, binding, 2, true); err == nil {
				t.Fatal("invalid pending state accepted")
			}
			if got, _ := os.ReadFile(filepath.Join(path, pending)); !bytes.Equal(got, body) {
				t.Fatal("invalid pending state was overwritten")
			}
		})
	}
}
