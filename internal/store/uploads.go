// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"math"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrUploadBusy = errors.New("upload operation in progress")
var ErrUploadLeaseLost = errors.New("upload lease expired or was superseded")
var uploadIdentifier = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var uploadDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Upload struct {
	ID             string    `json:"upload_id"`
	Repository     string    `json:"repository"`
	Image          string    `json:"image"`
	Offset         int64     `json:"offset"`
	Generation     int64     `json:"generation"`
	ExpiresAt      time.Time `json:"expires_at"`
	OperationUntil time.Time `json:"operation_until"`
	PartsVersion   int       `json:"parts_version"`
	Token          string    `json:"-"`
}
type UploadPart struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Offset int64  `json:"offset"`
}

const uploadColumns = `id,repository,image,offset_bytes,generation,expires_at,operation_until,parts_version,operation_token`

func scanUpload(row pgx.Row, u *Upload) error {
	return row.Scan(&u.ID, &u.Repository, &u.Image, &u.Offset, &u.Generation, &u.ExpiresAt, &u.OperationUntil, &u.PartsVersion, &u.Token)
}
func CreateUpload(ctx context.Context, tx pgx.Tx, i Identity, repo, image, id string, limit int, ttl time.Duration) error {
	r, e := repositoryInTx(ctx, tx, i, repo, "write")
	if e != nil {
		return e
	}
	if r.Format != "oci" || r.Mode != "hosted" || limit < 1 || ttl < time.Second || ttl > 24*time.Hour || !uploadIdentifier.MatchString(id) || image == "" || len(image) > 255 {
		return ErrConflict
	}
	var n int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.uploads WHERE state='active' AND expires_at>clock_timestamp()`).Scan(&n); e != nil {
		return e
	}
	if n >= limit {
		return ErrUploadBusy
	}
	_, e = tx.Exec(ctx, `INSERT INTO cratectl.uploads(tenant,repository,image,id,parts_version,expires_at) VALUES($1,$2,$3,$4,1,clock_timestamp()+make_interval(secs=>$5))`, i.Tenant, repo, image, id, ttl.Seconds())
	return e
}
func (s *Store) Upload(ctx context.Context, i Identity, repo, image, id string) (Upload, error) {
	var u Upload
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, e := repositoryInTx(ctx, tx, i, repo, "write"); e != nil {
			return e
		}
		return scanUpload(tx.QueryRow(ctx, `SELECT `+uploadColumns+` FROM cratectl.uploads WHERE repository=$1 AND image=$2 AND id=$3 AND state='active' AND expires_at>clock_timestamp()`, repo, image, id), &u)
	})
	if errors.Is(e, pgx.ErrNoRows) {
		e = ErrNotFound
	}
	return u, e
}
func (s *Store) ClaimUpload(ctx context.Context, i Identity, repo, image, id, token string, expected int64, lease, ttl time.Duration) (Upload, error) {
	var u Upload
	if lease < time.Second || lease > 5*time.Minute || ttl < lease || ttl > 24*time.Hour || expected < -1 || !uploadIdentifier.MatchString(token) {
		return u, ErrConflict
	}
	e := s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "write")
		if e != nil {
			return e
		}
		if r.Mode != "hosted" || r.Format != "oci" {
			return ErrDenied
		}
		var live bool
		e = tx.QueryRow(ctx, `SELECT operation_token<>'' AND operation_until>clock_timestamp() FROM cratectl.uploads WHERE repository=$1 AND image=$2 AND id=$3 AND state='active' AND expires_at>clock_timestamp() FOR UPDATE`, repo, image, id).Scan(&live)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if live {
			return ErrUploadBusy
		}
		e = scanUpload(tx.QueryRow(ctx, `UPDATE cratectl.uploads SET generation=generation+1,operation_token=$1,operation_until=clock_timestamp()+make_interval(secs=>$2),expires_at=clock_timestamp()+make_interval(secs=>$3) WHERE repository=$4 AND image=$5 AND id=$6 RETURNING `+uploadColumns, token, lease.Seconds(), ttl.Seconds(), repo, image, id), &u)
		if e != nil {
			return e
		}
		if expected >= 0 && u.Offset != expected {
			return ErrConflict
		}
		return appendEventIntent(ctx, tx, i, "oci.upload.operation.started", map[string]any{"repository": repo, "image": image, "upload_id": id, "generation": u.Generation, "offset": u.Offset}, false)
	})
	return u, e
}
func uploadFence(ctx context.Context, tx pgx.Tx, u Upload) error {
	var live bool
	e := tx.QueryRow(ctx, `SELECT state='active' AND generation=$1 AND operation_token=$2 AND operation_until>clock_timestamp() AND expires_at>clock_timestamp() AND offset_bytes=$3 FROM cratectl.uploads WHERE repository=$4 AND image=$5 AND id=$6 FOR UPDATE`, u.Generation, u.Token, u.Offset, u.Repository, u.Image, u.ID).Scan(&live)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrUploadLeaseLost
	}
	if e != nil {
		return e
	}
	if !live {
		return ErrUploadLeaseLost
	}
	return nil
}
func (s *Store) RenewUpload(ctx context.Context, i Identity, u Upload, lease, ttl time.Duration) error {
	if lease < time.Second || lease > 5*time.Minute || ttl < lease || ttl > 24*time.Hour {
		return ErrConflict
	}
	return s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		if _, e := repositoryInTx(ctx, tx, i, u.Repository, "write"); e != nil {
			return e
		}
		if e := uploadFence(ctx, tx, u); e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE cratectl.uploads SET operation_until=clock_timestamp()+make_interval(secs=>$1),expires_at=clock_timestamp()+make_interval(secs=>$2) WHERE id=$3 AND operation_until>clock_timestamp() AND expires_at>clock_timestamp()`, lease.Seconds(), ttl.Seconds(), u.ID)
		if e == nil && tag.RowsAffected() != 1 {
			return ErrUploadLeaseLost
		}
		return e
	})
}
func (s *Store) UploadParts(ctx context.Context, i Identity, u Upload, limit int, byteLimit int64) ([]UploadPart, error) {
	parts := []UploadPart{}
	if limit < 1 || limit > 1000000 || byteLimit < 1 {
		return parts, ErrConflict
	}
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if _, e := repositoryInTx(ctx, tx, i, u.Repository, "write"); e != nil {
			return e
		}
		// Read-only fence; the owner and generation are rechecked at acceptance.
		var current bool
		if e := tx.QueryRow(ctx, `SELECT state='active' AND generation=$1 AND operation_token=$2 AND operation_until>clock_timestamp() AND expires_at>clock_timestamp() FROM cratectl.uploads WHERE id=$3`, u.Generation, u.Token, u.ID).Scan(&current); e != nil {
			return e
		}
		if !current {
			return ErrUploadLeaseLost
		}
		rows, e := tx.Query(ctx, `SELECT digest,size,offset_bytes FROM cratectl.upload_parts WHERE upload_id=$1 ORDER BY offset_bytes LIMIT $2`, u.ID, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		var offset, used int64
		for rows.Next() {
			var p UploadPart
			if e = rows.Scan(&p.Digest, &p.Size, &p.Offset); e != nil {
				return e
			}
			used += 128
			if len(parts) >= limit || used > byteLimit {
				return ErrMetadataLimit
			}
			if p.Offset != offset || p.Size <= 0 || p.Size > math.MaxInt64-offset {
				return ErrConflict
			}
			offset += p.Size
			parts = append(parts, p)
		}
		if e = rows.Err(); e != nil {
			return e
		}
		if u.PartsVersion == 1 && offset != u.Offset || u.PartsVersion == 0 && len(parts) != 0 || u.PartsVersion < 0 || u.PartsVersion > 1 {
			return ErrConflict
		}
		return nil
	})
	return parts, e
}
func AcceptUpload(ctx context.Context, tx pgx.Tx, i Identity, u Upload, prefix, chunk UploadPart, object *Artifact, limit int, ttl time.Duration) (int64, error) {
	if limit < 1 || limit > 1000000 || ttl < time.Second || ttl > 24*time.Hour || u.Offset < 0 || chunk.Size < 0 || chunk.Size > math.MaxInt64-u.Offset || chunk.Size > 0 && (!uploadDigest.MatchString(chunk.Digest) || chunk.Offset != u.Offset) {
		return 0, ErrConflict
	}
	if _, e := repositoryInTx(ctx, tx, i, u.Repository, "write"); e != nil {
		return 0, e
	}
	if e := uploadFence(ctx, tx, u); e != nil {
		return 0, e
	}
	var count int
	if e := tx.QueryRow(ctx, `SELECT count(*) FROM cratectl.upload_parts WHERE upload_id=$1`, u.ID).Scan(&count); e != nil {
		return 0, e
	}
	if u.PartsVersion == 0 && u.Offset > 0 {
		if prefix.Size != u.Offset || prefix.Offset != 0 || count != 0 || !uploadDigest.MatchString(prefix.Digest) {
			return 0, ErrConflict
		}
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.upload_parts(tenant,upload_id,offset_bytes,digest,size) VALUES($1,$2,0,$3,$4)`, i.Tenant, u.ID, prefix.Digest, prefix.Size); e != nil {
			return 0, e
		}
		count++
	}
	if count > limit {
		return 0, ErrMetadataLimit
	}
	if chunk.Size > 0 {
		if chunk.Offset != u.Offset || count >= limit {
			return 0, ErrMetadataLimit
		}
		if _, e := tx.Exec(ctx, `INSERT INTO cratectl.upload_parts(tenant,upload_id,offset_bytes,digest,size) VALUES($1,$2,$3,$4,$5)`, i.Tenant, u.ID, chunk.Offset, chunk.Digest, chunk.Size); e != nil {
			return 0, e
		}
	}
	offset := u.Offset + chunk.Size
	state := "active"
	if object != nil {
		if object.Size != offset || object.Path != u.Image+"/blobs/sha256:"+object.Digest {
			return 0, ErrConflict
		}
		if e := InsertArtifacts(ctx, tx, i, u.Repository, []Artifact{*object}); e != nil {
			return 0, e
		}
		state = "complete"
	}
	tag, e := tx.Exec(ctx, `UPDATE cratectl.uploads SET offset_bytes=$1,state=$2,parts_version=1,operation_token='',operation_until='epoch',expires_at=clock_timestamp()+make_interval(secs=>$3) WHERE id=$4 AND generation=$5 AND operation_token=$6 AND operation_until>clock_timestamp() AND expires_at>clock_timestamp()`, offset, state, ttl.Seconds(), u.ID, u.Generation, u.Token)
	if e != nil {
		return 0, e
	}
	if tag.RowsAffected() != 1 {
		return 0, ErrUploadLeaseLost
	}
	return offset, nil
}
func (s *Store) ReleaseUpload(ctx context.Context, i Identity, u Upload) error {
	return s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		if _, e := repositoryInTx(ctx, tx, i, u.Repository, "write"); e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE cratectl.uploads SET operation_token='',operation_until='epoch' WHERE id=$1 AND repository=$2 AND generation=$3 AND operation_token=$4 AND state='active'`, u.ID, u.Repository, u.Generation, u.Token)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return ErrUploadLeaseLost
		}
		return appendEventIntent(ctx, tx, i, "oci.upload.operation.released", map[string]any{"repository": u.Repository, "upload_id": u.ID, "generation": u.Generation}, false)
	})
}
func (s *Store) CancelUpload(ctx context.Context, i Identity, repo, image, id string) error {
	_, e := s.mutateIntent(ctx, i, "", "", "oci.upload.cancelled", false, func(tx pgx.Tx) (any, int, error) {
		if _, e := repositoryInTx(ctx, tx, i, repo, "write"); e != nil {
			return nil, 0, e
		}
		tag, e := tx.Exec(ctx, `UPDATE cratectl.uploads SET state='cancelled',generation=generation+1,operation_token='',operation_until='epoch' WHERE repository=$1 AND image=$2 AND id=$3 AND state='active'`, repo, image, id)
		if e != nil {
			return nil, 0, e
		}
		if tag.RowsAffected() == 0 {
			return nil, 0, ErrNotFound
		}
		return map[string]any{"repository": repo, "upload_id": id, "state": "cancelled"}, 204, nil
	})
	return e
}
