// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

// Source-pinned native URLs still belong to their group. A known tombstone in
// an earlier source cannot be bypassed by constructing a lower-source URL. This
// check shares the serving transaction with current grants, revisions and bytes.
func checkNativeRetirementPrecedence(ctx context.Context, tx pgx.Tx, i Identity, source Repository, a Artifact, groups map[string]int64) error {
	if len(groups) == 0 || source.Format != "npm" && source.Format != "pypi" {
		return nil
	}
	var coordinate struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Filename string `json:"filename"`
	}
	if json.Unmarshal(a.Metadata, &coordinate) != nil || coordinate.Name == "" || len(coordinate.Name) > 214 {
		return ErrConflict
	}
	field, value := "version", coordinate.Version
	if source.Format == "pypi" {
		field, value = "filename", coordinate.Filename
	}
	if value == "" || len(value) > 255 {
		return ErrConflict
	}
	for name := range groups {
		_, members, e := nativeRepositories(ctx, tx, i, name, coordinate.Name, source.Format)
		if e != nil {
			return e
		}
		selected := false
		for _, member := range members {
			if member.Name == source.Name {
				selected = true
				break
			}
			var retired bool
			e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts a JOIN cratectl.artifact_lifecycle l ON (l.tenant,l.repository,l.path)=(a.tenant,a.repository,a.path) WHERE a.repository=$1 AND a.metadata->>'name'=$2 AND a.metadata->>$3=$4 AND l.deleted AND ($5::boolean OR a.source_revision=$6))`, member.Name, coordinate.Name, field, value, member.Mode != "proxy", member.SourceRevision).Scan(&retired)
			if e != nil {
				return e
			}
			if retired {
				return ErrDeleted
			}
		}
		if !selected {
			return ErrSourceChanged
		}
	}
	return nil
}
