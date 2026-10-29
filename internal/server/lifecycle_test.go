// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func TestRestoreDistinguishesOperationWordsInsideImageNames(t *testing.T) {
	b, e := blob.New(t.TempDir(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	s := New(nil, b, "")
	i := store.Identity{Tenant: "restore-test", Actor: "operator", Role: "admin"}
	for _, image := range []string{"team/manifests", "team/blobs", "team/manifests/blobs"} {
		for _, kind := range []string{"blobs", "manifests"} {
			t.Run(image+"/"+kind, func(t *testing.T) {
				data := []byte("opaque retained bytes")
				media := "application/octet-stream"
				var metadata []byte
				if kind == "manifests" {
					data = []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
					media = testOCIIndex
					m, e := parseOCIManifest(data, media)
					if e != nil {
						t.Fatal(e)
					}
					metadata, e = json.Marshal(m.metadata(image))
					if e != nil {
						t.Fatal(e)
					}
				}
				digest := crypt.Digest(data)
				if _, e := b.Put(context.Background(), i.Tenant, bytes.NewReader(data), digest, int64(len(data))); e != nil {
					t.Fatal(e)
				}
				a := store.Artifact{Path: image + "/" + kind + "/sha256:" + digest, Digest: digest, Size: int64(len(data)), MediaType: media, Metadata: metadata}
				if e := s.verifyRestoration(httptest.NewRequest("PUT", "/api/v1/lifecycle", nil), i, []store.Artifact{a}); e != nil {
					t.Fatal("operation word in image changed object kind", e)
				}
			})
		}
	}
}
