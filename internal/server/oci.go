// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"

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
		s.ociUpload(w, r, i, repo, image, ref)
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
		s.serveOCIDiscoveryPage(w, r, repo, image, "referrers", ref, kind, i)
	case "tags/list":
		if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, 405, "UNSUPPORTED", "List tags with GET or HEAD.")
			return
		}
		s.serveOCIDiscoveryPage(w, r, repo, image, "tags/list", "", "", i)
	default:
		fail(w, 404, "UNSUPPORTED", "This OCI operation is not implemented; see the format ledger.")
	}
}
