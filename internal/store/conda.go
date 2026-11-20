// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json/v2"
	"regexp"
	"strings"

	"ctlplne.dev/cratectl/internal/conda"
	"github.com/jackc/pgx/v5"
)

const CondaMedia = "application/x-bzip2"
const condaMetadataLimit = 2 * conda.MaxIndexBytes

var condaMD5 = regexp.MustCompile(`^[a-f0-9]{32}$`)

type CondaPackage struct {
	Package   conda.Package `json:"package"`
	MD5       string        `json:"md5"`
	Validated bool          `json:"archive_validated"`
}

func ValidateCondaArtifact(a Artifact) (CondaPackage, error) {
	coordinate, ok := conda.ParsePath(a.Path)
	var metadata CondaPackage
	if !ok || a.MediaType != CondaMedia || a.Size < 1 || a.Size > conda.MaxArchiveBytes ||
		!uploadDigest.MatchString(a.Digest) || len(a.Metadata) > condaMetadataLimit ||
		json.Unmarshal(a.Metadata, &metadata) != nil || !metadata.Validated ||
		!condaMD5.MatchString(metadata.MD5) || !metadata.Package.ValidFor(coordinate) {
		return CondaPackage{}, ErrConflict
	}
	return metadata, nil
}

func (s *Store) PublishConda(ctx context.Context, i Identity, repo string, a Artifact) error {
	if _, err := ValidateCondaArtifact(a); err != nil {
		return err
	}
	_, err := s.MutateRepository(ctx, i, repo, "", "", "conda.package.published", func(tx pgx.Tx) (any, int, error) {
		r, err := repositoryInTx(ctx, tx, i, repo, "write")
		if err != nil {
			return nil, 0, err
		}
		if r.Format != "conda" || r.Mode != "hosted" {
			return nil, 0, ErrConflict
		}
		if err := InsertArtifacts(ctx, tx, i, repo, []Artifact{a}); err != nil {
			return nil, 0, err
		}
		return map[string]any{"repository": repo, "path": a.Path, "digest": a.Digest, "size": a.Size}, 201, nil
	})
	return err
}

type condaIndexRecord struct {
	conda.Package `json:",inline"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
	MD5           string `json:"md5"`
}

type condaIndex struct {
	body       strings.Builder
	byteLimit  int64
	suffix     string
	hasRecords bool
}

func newCondaIndex(subdir, baseURL string, byteLimit int64) (*condaIndex, error) {
	version, location := "1", ""
	if baseURL != "" {
		encoded, err := json.Marshal(baseURL)
		if err != nil {
			return nil, err
		}
		version, location = "2", `,"base_url":`+string(encoded)
	}
	prefix := `{"info":{"subdir":"` + subdir + `"` + location + `},"packages":{`
	suffix := `},"packages.conda":{},"removed":[],"repodata_version":` + version + `}`
	byteLimit = min(byteLimit, 8<<20)
	if int64(len(prefix)+len(suffix)) > byteLimit {
		return nil, ErrMetadataLimit
	}
	index := &condaIndex{byteLimit: byteLimit, suffix: suffix}
	index.body.WriteString(prefix)
	return index, nil
}

func (index *condaIndex) add(a Artifact) error {
	metadata, err := ValidateCondaArtifact(a)
	if err != nil {
		return err
	}
	record, err := json.Marshal(condaIndexRecord{Package: metadata.Package, Size: a.Size, SHA256: a.Digest, MD5: metadata.MD5})
	if err != nil {
		return err
	}
	_, file, _ := strings.Cut(a.Path, "/")
	if int64(index.body.Len()+len(file)+len(record)+len(index.suffix)+4) > index.byteLimit {
		return ErrMetadataLimit
	}
	if index.hasRecords {
		index.body.WriteByte(',')
	}
	index.hasRecords = true
	index.body.WriteByte('"')
	index.body.WriteString(file)
	index.body.WriteString(`":`)
	index.body.Write(record)
	return nil
}

func (index *condaIndex) finish() string {
	index.body.WriteString(index.suffix)
	return index.body.String()
}

// CondaRepodata emits a complete bounded view of one platform under its
// current authorization, review decisions and retained reference lifecycle.
func (s *Store) CondaRepodata(ctx context.Context, i Identity, repo, subdir string, limit int, byteLimit int64) (string, error) {
	if !conda.ValidSubdir(subdir) {
		return "", ErrNotFound
	}
	limit = min(limit, 10000)
	if limit < 1 {
		return "", ErrMetadataLimit
	}
	index, err := newCondaIndex(subdir, "", byteLimit)
	if err != nil {
		return "", err
	}
	err = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, err := repositoryInTx(ctx, tx, i, repo, "read")
		if err != nil {
			return err
		}
		if r.Format != "conda" || r.Mode != "hosted" {
			return ErrConflict
		}
		rows, err := tx.Query(ctx, `SELECT left(a.path,321),left(a.digest,65),a.size,
CASE WHEN octet_length(a.metadata::text)<=$6 THEN a.metadata ELSE NULL END
FROM cratectl.artifacts a `+decisionJoin+nativeLifecycleJoin+`
WHERE a.repository=$1 AND starts_with(a.path,$2) AND a.media_type=$3 AND NOT COALESCE(nl.deleted,false)
 AND COALESCE(d.decision,a.decision)<>'denied' AND (NOT $4::boolean OR COALESCE(d.decision,a.decision)='allowed')
ORDER BY a.path COLLATE "C" LIMIT $5`, repo, subdir+"/", CondaMedia, r.RequireReview, limit+1, condaMetadataLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for count := 0; rows.Next(); count++ {
			if count == limit {
				return ErrMetadataLimit
			}
			a := Artifact{MediaType: CondaMedia}
			if err := rows.Scan(&a.Path, &a.Digest, &a.Size, &a.Metadata); err != nil {
				return err
			}
			if err := index.add(a); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	if err != nil {
		return "", err
	}
	return index.finish(), nil
}
