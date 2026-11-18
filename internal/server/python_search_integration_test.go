//go:build integration

// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"strings"
	"testing"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestPythonHostedSearchReadsCurrentValidatedPackages(t *testing.T) {
	s, db, token, admin := schemaServer(t)
	ctx := t.Context()
	const name, repo = "cratectl-probe", "cratectl-python-search"
	mavenRepositories(t, s, admin, store.Repository{Name: repo, Format: "pypi", Access: "restricted", RequireReview: true})
	reader, err := crypt.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(ctx, db.OwnerDSN, admin.Tenant, "cratectl-search-reader", "reader", reader, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	publish := func(version, summary string) store.Artifact {
		t.Helper()
		filename := "cratectl_probe-" + version + "-py3-none-any.whl"
		raw := "Metadata-Version: 2.4\nName: cratectl-probe\nVersion: " + version + "\nSummary: " + summary + "\n\n"
		object, err := s.Blobs.Put(ctx, admin.Tenant, strings.NewReader(raw), "", int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		meta, err := json.Marshal(store.PythonFile{
			Name: name, Filename: filename, Version: version, CoreMetadata: raw, CoreSHA256: crypt.Digest([]byte(raw)),
			CoreAvailable: true, Validated: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		artifact := store.Artifact{Path: filename, Digest: object.Digest, Size: object.Size, MediaType: "application/octet-stream", Metadata: meta}
		if err := s.DB.PublishPython(ctx, admin, repo, artifact); err != nil {
			t.Fatal(err)
		}
		return artifact
	}
	old := publish("2.0", "Alpha useful & documented")
	latest := publish("10.0", "Beta useful & documented")
	approve := func(a store.Artifact) {
		t.Helper()
		if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
			_, err := store.Decide(ctx, tx, admin, repo, a.Path, a.Digest, "allowed")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	path := "/pypi/" + repo + "/search"
	search := func(who, query string, want int, version, summary string) {
		t.Helper()
		w := mavenHTTP(t, s, who, http.MethodPost, path, stockPythonSearchXML(query), "Content-Type", "text/xml")
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
		if want != http.StatusOK {
			return
		}
		var reply pythonSearchReply
		if err := xml.Unmarshal(w.Body.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		if version == "" {
			if len(reply.Data.Values) != 0 {
				t.Fatal("unexpected search result", w.Body.String())
			}
			return
		}
		if len(reply.Data.Values) != 1 || len(reply.Data.Values[0].Fields) != 3 ||
			reply.Data.Values[0].Fields[0] != (pythonSearchField{Name: "name", Value: name}) ||
			reply.Data.Values[0].Fields[1] != (pythonSearchField{Name: "version", Value: version}) ||
			reply.Data.Values[0].Fields[2] != (pythonSearchField{Name: "summary", Value: summary}) {
			t.Fatal("wrong result", w.Body.String())
		}
	}
	search(token, "useful", 200, "", "")
	search(reader, "useful", 403, "", "")
	grant := func(read bool, key string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"actor": "cratectl-search-reader", "read": read, "write": false})
		w := mavenHTTP(t, s, token, http.MethodPut, "/api/v1/repositories/"+repo+"/grants", string(body), "Idempotency-Key", key)
		if w.Code != http.StatusOK {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	grant(true, "cratectl-python-search-grant")
	approve(old)
	search(reader, "Cratectl.Probe", 200, "2.0", "Alpha useful & documented")
	approve(latest)
	search(reader, "USEFUL", 200, "10.0", "Beta useful & documented")
	if err := s.DB.Tx(ctx, admin, true, func(tx pgx.Tx) error {
		_, err := store.SetPythonYank(ctx, tx, admin, repo, latest.Path, true, "Prefer the maintained version")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	search(reader, "useful", 200, "2.0", "Alpha useful & documented")
	if w := mavenHTTP(t, s, reader, http.MethodPost, "/pypi/"+repo+"/", "", "Content-Type", "text/xml"); w.Code != http.StatusForbidden {
		t.Fatal("search reader gained publication access", w.Code)
	}
	grant(false, "cratectl-python-search-revoke")
	search(reader, "useful", 403, "", "")
}
