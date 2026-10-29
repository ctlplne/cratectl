// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ctlplne.dev/cratectl/internal/blob"
	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
	"github.com/jackc/pgx/v5"
)

func (s *Server) ConfigureUploads(limit, parts int, metadata int64, lease, ttl time.Duration) error {
	if limit < 1 || limit > 1000000 || parts < 1 || parts > 1000000 || metadata < 128 || metadata > 1<<30 || lease < time.Second || lease > 5*time.Minute || ttl < lease || ttl > 24*time.Hour {
		return store.ErrConflict
	}
	s.UploadLimit, s.UploadPartLimit, s.UploadMetadataBytes, s.UploadLease, s.UploadTTL = limit, parts, metadata, lease, ttl
	return nil
}

// Native clients may omit Content-Range. When present both bounds must describe
// exactly the supplied chunk; the committed offset is still authoritative.
func uploadRange(value string) (start, length int64, err error) {
	if value == "" {
		return -1, -1, nil
	}
	pieces := strings.Split(strings.TrimPrefix(value, "bytes "), "-")
	if len(pieces) != 2 {
		return 0, 0, store.ErrConflict
	}
	first, e := strconv.ParseInt(pieces[0], 10, 64)
	if e != nil || first < 0 || strconv.FormatInt(first, 10) != pieces[0] {
		return 0, 0, store.ErrConflict
	}
	last, e := strconv.ParseInt(pieces[1], 10, 64)
	if e != nil || last < first || last >= 1<<62 || strconv.FormatInt(last, 10) != pieces[1] {
		return 0, 0, store.ErrConflict
	}
	return first, last - first + 1, nil
}
func (s *Server) ociUpload(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, image, id string) {
	ctx := r.Context()
	if r.Method == "POST" && id == "" {
		next, e := crypt.Token()
		if e == nil {
			_, e = s.DB.MutateRepository(ctx, i, repo.Name, "", "", "oci.upload.created", func(tx pgx.Tx) (any, int, error) {
				e := store.CreateUpload(ctx, tx, i, repo.Name, image, next, s.UploadLimit, s.UploadTTL)
				return map[string]string{"upload_id": next, "repository": repo.Name, "image": image}, 202, e
			})
		}
		if e != nil {
			respondErr(w, e)
			return
		}
		s.uploadHeaders(w, repo.Name, image, next, 0)
		w.WriteHeader(202)
		return
	}
	if id == "" {
		fail(w, 405, "UNSUPPORTED", "Use POST to begin, PATCH to append, PUT with digest to finish, or DELETE to cancel.")
		return
	}
	switch r.Method {
	case "GET":
		u, e := s.DB.Upload(ctx, i, repo.Name, image, id)
		if e != nil {
			respondErr(w, e)
			return
		}
		s.uploadHeaders(w, repo.Name, image, id, u.Offset)
		w.WriteHeader(204)
		return
	case "DELETE":
		if e := s.DB.CancelUpload(ctx, i, repo.Name, image, id); e != nil {
			respondErr(w, e)
			return
		}
		w.WriteHeader(204)
		return
	case "PATCH", "PUT":
	default:
		fail(w, 405, "UNSUPPORTED", "Use GET, PATCH, PUT or DELETE for an upload session.")
		return
	}
	digest := r.URL.Query().Get("digest")
	if r.Method == "PUT" && !ociDigest.MatchString(digest) {
		fail(w, 400, "DIGEST_INVALID", "Supply the SHA-256 of the complete blob.")
		return
	}
	offset, e := s.receiveUpload(w, r, i, repo, image, id, digest)
	if e != nil {
		respondErr(w, e)
		return
	}
	s.uploadHeaders(w, repo.Name, image, id, offset)
	if r.Method == "PUT" {
		w.Header().Set("Location", s.url("/v2/"+repo.Name+"/"+image+"/blobs/"+digest))
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(201)
	} else {
		w.WriteHeader(202)
	}
}
func (s *Server) uploadHeaders(w http.ResponseWriter, repo, image, id string, offset int64) {
	w.Header().Set("Location", s.url("/v2/"+repo+"/"+image+"/blobs/uploads/"+id))
	w.Header().Set("Docker-Upload-UUID", id)
	w.Header().Set("Range", fmt.Sprintf("0-%d", max(0, offset-1)))
}
func (s *Server) receiveUpload(w http.ResponseWriter, r *http.Request, i store.Identity, repo store.Repository, image, id, digest string) (int64, error) {
	expected, length, e := uploadRange(r.Header.Get("Content-Range"))
	if e != nil {
		return 0, e
	}
	if length >= 0 && r.ContentLength >= 0 && length != r.ContentLength {
		return 0, blob.ErrLength
	}
	token, e := crypt.Token()
	if e != nil {
		return 0, e
	}
	u, e := s.DB.ClaimUpload(r.Context(), i, repo.Name, image, id, token, expected, s.UploadLease, s.UploadTTL)
	if e != nil {
		return 0, e
	}
	accepted := false
	defer func() {
		if !accepted {
			cleanup, done := context.WithTimeout(context.Background(), min(s.UploadLease, 5*time.Second))
			defer done()
			// Current authorization and exact generation/token are required even for cleanup.
			s.DB.ReleaseUpload(cleanup, i, u)
		}
	}()
	ctx, stop, closeLease := keepLease(r.Context(), s.UploadLease, func(ctx context.Context) error { return s.DB.RenewUpload(ctx, i, u, s.UploadLease, s.UploadTTL) }, func() {
		// Deadlines unblock a real HTTP body before Close takes its read mutex.
		http.NewResponseController(w).SetReadDeadline(time.Now())
		r.Body.Close()
	})
	defer closeLease()
	parts, e := s.DB.UploadParts(ctx, i, u, s.UploadPartLimit, s.UploadMetadataBytes)
	if e != nil {
		return 0, e
	}
	objects := make([]blob.Object, 0, len(parts)+2)
	for _, part := range parts {
		objects = append(objects, blob.Object{Digest: part.Digest, Size: part.Size})
	}
	prefix := store.UploadPart{}
	if u.PartsVersion == 0 && u.Offset > 0 {
		obj, e := s.Blobs.ImportUploadPrefix(ctx, i.Tenant, id, u.Offset)
		if e != nil {
			return 0, e
		}
		prefix = store.UploadPart{Digest: obj.Digest, Size: obj.Size}
		objects = append(objects, obj)
	}
	if length < 0 {
		length = r.ContentLength
	}
	obj, e := s.Blobs.StageUpload(ctx, i.Tenant, u.Offset, r.Body, length)
	if e != nil {
		if cause := stop(); cause != nil {
			return 0, cause
		}
		return 0, e
	}
	chunk := store.UploadPart{Digest: obj.Digest, Size: obj.Size, Offset: u.Offset}
	if obj.Size > 0 {
		objects = append(objects, obj)
	}
	if len(objects) > s.UploadPartLimit || int64(len(objects))*128 > s.UploadMetadataBytes {
		return 0, store.ErrMetadataLimit
	}
	var artifact *store.Artifact
	if r.Method == "PUT" {
		obj, e = s.Blobs.AssembleUpload(ctx, i.Tenant, objects, strings.TrimPrefix(digest, "sha256:"))
		if e != nil {
			return 0, e
		}
		artifact = &store.Artifact{Path: image + "/blobs/" + digest, Digest: obj.Digest, Size: obj.Size, MediaType: "application/octet-stream"}
	}
	if e = stop(); e != nil {
		return 0, e
	}
	var offset int64
	_, e = s.DB.MutateRepository(ctx, i, repo.Name, "", "", "oci.upload.progress", func(tx pgx.Tx) (any, int, error) {
		var e error
		offset, e = store.AcceptUpload(ctx, tx, i, u, prefix, chunk, artifact, s.UploadPartLimit, s.UploadTTL)
		return map[string]any{"repository": repo.Name, "upload_id": id, "offset": offset, "complete": artifact != nil}, 202, e
	})
	accepted = e == nil
	return offset, e
}
