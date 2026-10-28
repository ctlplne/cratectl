// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

var ociImage = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
var ociDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var ociTag = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

func (s *Server) oci(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, p string) {
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	image, operation, ref := parseOCIPath(p)
	if !ociImage.MatchString(image) || len(image) > 255 {
		fail(w, 400, "NAME_INVALID", "Use a valid OCI image name within the tenant repository.")
		return
	}
	ctx := r.Context()
	switch operation {
	case "blobs/uploads":
		if r.Method == "POST" && ref == "" {
			id, e := crypt.Token()
			if e != nil {
				respondErr(w, e)
				return
			}
			_, e = s.DB.MutateRepository(ctx, i, repo.Name, "", "", "oci.upload.created", func(tx pgx.Tx) (any, int, error) {
				var n int
				if e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.uploads WHERE state='active' AND expires_at>now()`).Scan(&n); e != nil {
					return nil, 0, e
				}
				if n >= 32 {
					return nil, 0, errors.New("upload queue full")
				}
				_, e := tx.Exec(ctx, `INSERT INTO cratectl.uploads(tenant,repository,image,id) VALUES($1,$2,$3,$4)`, i.Tenant, repo.Name, image, id)
				return map[string]string{"upload_id": id, "repository": repo.Name, "image": image}, 202, e
			})
			if e != nil {
				respondErr(w, e)
				return
			}
			w.Header().Set("Location", s.url("/v2/"+repo.Name+"/"+image+"/blobs/uploads/"+id))
			w.Header().Set("Docker-Upload-UUID", id)
			w.Header().Set("Range", "0-0")
			w.WriteHeader(202)
			return
		}
		if ref == "" || (r.Method != "PATCH" && r.Method != "PUT" && r.Method != "GET") {
			fail(w, 405, "UNSUPPORTED", "Use POST to begin, PATCH to append, PUT with digest to finish.")
			return
		}
		digest := r.URL.Query().Get("digest")
		if r.Method == "PUT" && !ociDigest.MatchString(digest) {
			fail(w, 400, "DIGEST_INVALID", "Supply the SHA-256 of the complete blob.")
			return
		}
		var offset int64
		if r.Method == "GET" {
			e := s.DB.Tx(ctx, i, false, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT offset_bytes FROM cratectl.uploads WHERE id=$1 AND repository=$2 AND image=$3 AND state='active' AND expires_at>now()`, ref, repo.Name, image).Scan(&offset)
			})
			if e != nil {
				respondErr(w, store.ErrNotFound)
				return
			}
			w.Header().Set("Range", fmt.Sprintf("0-%d", max(0, offset-1)))
			w.WriteHeader(204)
			return
		}
		_, e := s.DB.MutateRepository(ctx, i, repo.Name, "", "", "oci.upload.progress", func(tx pgx.Tx) (any, int, error) {
			e := tx.QueryRow(ctx, `SELECT offset_bytes FROM cratectl.uploads WHERE id=$1 AND repository=$2 AND image=$3 AND state='active' AND expires_at>now() FOR UPDATE`, ref, repo.Name, image).Scan(&offset)
			if errors.Is(e, pgx.ErrNoRows) {
				return nil, 0, store.ErrNotFound
			}
			if e != nil {
				return nil, 0, e
			}
			if cr := r.Header.Get("Content-Range"); cr != "" {
				parts := strings.Split(strings.TrimPrefix(cr, "bytes "), "-")
				if len(parts) != 2 {
					return nil, 0, store.ErrConflict
				}
				start, e := strconv.ParseInt(parts[0], 10, 64)
				if e != nil || start != offset {
					return nil, 0, store.ErrConflict
				}
			}
			offset, e = s.Blobs.AppendUpload(ctx, i.Tenant, ref, offset, r.Body)
			if e != nil {
				return nil, 0, e
			}
			state := "active"
			if r.Method == "PUT" {
				obj, e := s.Blobs.FinishUpload(ctx, i.Tenant, ref, strings.TrimPrefix(digest, "sha256:"), offset)
				if e != nil {
					return nil, 0, e
				}
				if e = store.InsertArtifacts(ctx, tx, i, repo.Name, []store.Artifact{{Path: image + "/blobs/" + digest, Digest: obj.Digest, Size: obj.Size, MediaType: "application/octet-stream"}}); e != nil {
					return nil, 0, e
				}
				state = "complete"
			}
			_, e = tx.Exec(ctx, `UPDATE cratectl.uploads SET offset_bytes=$1,state=$2 WHERE id=$3`, offset, state, ref)
			return map[string]any{"upload_id": ref, "offset": offset, "state": state}, 202, e
		})
		if e != nil {
			respondErr(w, e)
			return
		}
		location := "/v2/" + repo.Name + "/" + image + "/blobs/uploads/" + ref
		status := 202
		if r.Method == "PUT" {
			location = "/v2/" + repo.Name + "/" + image + "/blobs/" + digest
			status = 201
			w.Header().Set("Docker-Content-Digest", digest)
		}
		w.Header().Set("Location", s.url(location))
		w.Header().Set("Range", fmt.Sprintf("0-%d", max(0, offset-1)))
		w.Header().Set("Docker-Upload-UUID", ref)
		w.WriteHeader(status)
	case "blobs":
		if !ociDigest.MatchString(ref) {
			fail(w, 400, "DIGEST_INVALID", "Use a SHA-256 digest.")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, 405, "UNSUPPORTED", "Use the upload workflow.")
			return
		}
		resolved, e := s.resolveOCI(ctx, i, repo, image, "blobs", ref, forceRefresh(r))
		if e != nil {
			respondErr(w, e)
			return
		}
		s.serveResolvedArtifact(w, r, i, resolved)
	case "manifests":
		if !ociDigest.MatchString(ref) && !ociTag.MatchString(ref) {
			fail(w, 400, "TAG_INVALID", "Use a valid tag or SHA-256 digest.")
			return
		}
		if r.Method == "GET" || r.Method == "HEAD" {
			resolved, e := s.resolveOCI(ctx, i, repo, image, "manifests", ref, forceRefresh(r))
			if e != nil {
				respondErr(w, e)
				return
			}
			s.serveResolvedArtifact(w, r, i, resolved)
			return
		}
		if r.Method != "PUT" {
			fail(w, 405, "UNSUPPORTED", "Publish a manifest with PUT.")
			return
		}
		data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, ociManifestBytes))
		if e != nil {
			fail(w, 413, "MANIFEST_INVALID", "Limit a manifest to 4 MiB.")
			return
		}
		manifest, e := parseOCIManifest(data, r.Header.Get("Content-Type"))
		if e != nil {
			fail(w, 400, "MANIFEST_INVALID", "Use an unambiguous OCI/Docker schema v2 manifest or index with complete descriptors and matching content type.")
			return
		}
		metadata := manifest.metadata(image)

		digest := "sha256:" + crypt.Digest(data)
		if ociDigest.MatchString(ref) && digest != ref {
			fail(w, 400, "DIGEST_INVALID", "Manifest bytes differ from the requested digest.")
			return
		}
		obj, e := s.Blobs.Put(ctx, i.Tenant, bytes.NewReader(data), strings.TrimPrefix(digest, "sha256:"), int64(len(data)))
		if e != nil {
			respondErr(w, e)
			return
		}
		_, e = s.DB.MutateRepository(ctx, i, repo.Name, "", "", "oci.manifest.published", func(tx pgx.Tx) (any, int, error) {
			a := store.Artifact{Path: image + "/manifests/" + digest, Digest: obj.Digest, Size: obj.Size, MediaType: manifest.MediaType}
			tag := ""
			if !ociDigest.MatchString(ref) {
				tag = ref
			}
			if e := store.PublishOCI(ctx, tx, i, repo.Name, image, tag, a, metadata); e != nil {
				return nil, 0, e
			}
			return map[string]string{"repository": repo.Name, "image": image, "reference": ref, "digest": digest}, 201, nil
		})
		if e != nil {
			respondErr(w, e)
			return
		}
		if manifest.Subject != nil {
			w.Header().Set("OCI-Subject", manifest.Subject.Digest)
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Location", s.url("/v2/"+repo.Name+"/"+image+"/manifests/"+digest))
		w.WriteHeader(201)
	case "referrers":
		if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, 405, "UNSUPPORTED", "Discover referrers with GET or HEAD.")
			return
		}
		kind := r.URL.Query().Get("artifactType")
		if !ociDigest.MatchString(ref) || (kind != "" && !ociMedia.MatchString(kind)) || len(r.URL.Query()["artifactType"]) > 1 {
			fail(w, 400, "DIGEST_INVALID", "Choose a SHA-256 subject and an optional artifact media type.")
			return
		}
		if e := s.refreshOCIDiscovery(ctx, i, repo, image, "referrers", ref, forceRefresh(r)); e != nil {
			respondErr(w, e)
			return
		}
		_, referrers, e := s.DB.OCIDiscovery(ctx, i, repo.Name, image, "referrers", ref, kind, s.NativeVersionLimit, s.NativeMetadataBytes)
		if e != nil {
			respondErr(w, e)
			return
		}
		if kind != "" {
			w.Header().Set("OCI-Filters-Applied", "artifactType")
		}
		data, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": referrers})
		if int64(len(data)) > s.NativeMetadataBytes {
			respondErr(w, store.ErrMetadataLimit)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		w.Header().Set("ETag", `"sha256:`+crypt.Digest(data)+`"`)
		http.ServeContent(w, r, "referrers.json", time.Time{}, bytes.NewReader(data))
	case "tags/list":
		if r.Method != "GET" {
			fail(w, 405, "UNSUPPORTED", "List tags with GET.")
			return
		}
		if e := s.refreshOCIDiscovery(ctx, i, repo, image, "tags/list", "", forceRefresh(r)); e != nil {
			respondErr(w, e)
			return
		}
		tags, _, e := s.DB.OCIDiscovery(ctx, i, repo.Name, image, "tags/list", "", "", s.NativeTagLimit, s.NativeMetadataBytes)
		if e != nil {
			respondErr(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"name": repo.Name + "/" + image, "tags": tags})
	default:
		fail(w, 404, "UNSUPPORTED", "This OCI operation is not implemented; see the format ledger.")
	}
}
