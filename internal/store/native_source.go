// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// NativeSource is an immutable, format-scoped binding. A catalog transaction
// commits its descriptors and current reference under the same retrieval fence.
type NativeSource struct {
	Key        string          `json:"key"`
	Format     string          `json:"format"`
	Name       string          `json:"name"`
	Coordinate string          `json:"coordinate"`
	Version    string          `json:"version"`
	URL        string          `json:"url"`
	Integrity  string          `json:"integrity"`
	Metadata   json.RawMessage `json:"metadata"`
}
type NativeCatalogPublication struct {
	Name    string
	Entries map[string]string
	Sources []NativeSource
}

func nativeSource(ctx context.Context, tx pgx.Tx, repo, key, format string) (NativeSource, error) {
	var source NativeSource
	e := tx.QueryRow(ctx, `SELECT key,format,package,coordinate,version,url,integrity,metadata FROM cratectl.native_sources WHERE repository=$1 AND key=$2 AND format=$3`, repo, key, format).Scan(&source.Key, &source.Format, &source.Name, &source.Coordinate, &source.Version, &source.URL, &source.Integrity, &source.Metadata)
	if errors.Is(e, pgx.ErrNoRows) {
		e = ErrNotFound
	}
	return source, e
}
func (s *Store) NativeSource(ctx context.Context, i Identity, repo, key, format string) (NativeSource, error) {
	var source NativeSource
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		r, e := repositoryInTx(ctx, tx, i, repo, "read")
		if e != nil {
			return e
		}
		if r.Format != format || r.Mode != "proxy" {
			return ErrConflict
		}
		source, e = nativeSource(ctx, tx, repo, key, format)
		return e
	})
	return source, e
}
func nativeCatalogArtifact(ctx context.Context, tx pgx.Tx, i Identity, repo, name, format, media string) (Artifact, error) {
	r, e := repositoryInTx(ctx, tx, i, repo, "read")
	if e != nil {
		return Artifact{}, e
	}
	if r.Format != format || r.Mode != "proxy" {
		return Artifact{}, ErrConflict
	}
	a, e := readArtifact(ctx, tx, repo, format+"-catalog/"+name, false, newGraphBudget())
	if e == nil && a.MediaType != media {
		return a, ErrConflict
	}
	return a, e
}
func (s *Store) NativeCatalogArtifact(ctx context.Context, i Identity, repo, name, format, media string) (Artifact, error) {
	var a Artifact
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		var e error
		a, e = nativeCatalogArtifact(ctx, tx, i, repo, name, format, media)
		return e
	})
	return a, e
}
func nativeRepositories(ctx context.Context, tx pgx.Tx, i Identity, repo, name, format string) (Repository, []Repository, error) {
	r, e := repositoryInTx(ctx, tx, i, repo, "read")
	if e != nil {
		return r, nil, e
	}
	if r.Format != format {
		return r, nil, ErrConflict
	}
	out := []Repository{}
	for _, member := range MembersForPath(r, name+"/") {
		m, e := repositoryInTx(ctx, tx, i, member, "read")
		if e != nil {
			return r, nil, e
		}
		if m.Format != format || (r.Mode == "group" && m.Mode == "group") {
			return r, nil, ErrConflict
		}
		out = append(out, m)
	}
	return r, out, nil
}
func (s *Store) NativeRepositories(ctx context.Context, i Identity, repo, name, format string) ([]Repository, error) {
	var out []Repository
	e := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		_, members, e := nativeRepositories(ctx, tx, i, repo, name, format)
		out = members
		return e
	})
	return out, e
}
