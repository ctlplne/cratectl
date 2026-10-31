// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

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
			referencePath := ""
			if member.Mode == "proxy" {
				var present bool
				referencePath, present, e = currentNativeProxySubject(ctx, tx, member, coordinate.Name, value)
				if e != nil {
					return e
				}
				if !present {
					continue
				}
			}
			var retired bool
			e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.artifacts a JOIN cratectl.artifact_lifecycle l ON (l.tenant,l.repository,l.path)=(a.tenant,a.repository,a.path) WHERE a.repository=$1 AND a.metadata->>'name'=$2 AND a.metadata->>$3=$4 AND l.deleted AND ($5::boolean OR a.source_revision=$6) AND ($7='' OR a.path=$7))`, member.Name, coordinate.Name, field, value, member.Mode != "proxy", member.SourceRevision, referencePath).Scan(&retired)
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

// Read just this coordinate's current descriptor, never an unbounded catalog.
// Retained tombstones for descriptors no longer selected by the catalog cannot
// hide a legitimate lower-source candidate. Their own direct paths stay deleted.
func currentNativeProxySubject(ctx context.Context, tx pgx.Tx, member Repository, name, coordinate string) (string, bool, error) {
	catalogPath, media, field := NPMCatalogPath(name), NPMCatalogMedia, "versions"
	if member.Format == "pypi" {
		catalogPath, media, field = PythonCatalogPath(name), PythonCatalogMedia, "files"
	}
	var state Retrieval
	e := scanRetrieval(tx.QueryRow(ctx, `SELECT `+retrievalColumns+` FROM cratectl.retrievals WHERE repository=$1 AND path=$2`, member.Name, catalogPath), &state)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", false, nil
	}
	if e != nil {
		return "", false, e
	}
	if state.SourceRevision != member.SourceRevision {
		return "", false, ErrSourceChanged
	}
	if state.State == "negative" {
		return "", false, nil
	}
	if state.State == "failed" && !state.StalePermitted() {
		return "", false, ErrBusy
	}
	var key, decision string
	var present, object bool
	var revision int64
	e = tx.QueryRow(ctx, `SELECT left(COALESCE(a.metadata->($2::text)->>($3::text),''),65),COALESCE((a.metadata->($2::text)) ? $3,false),COALESCE(jsonb_typeof(a.metadata->($2::text))='object',false),COALESCE(d.decision,a.decision),a.source_revision FROM cratectl.artifacts a `+decisionJoin+` WHERE a.repository=$1 AND a.path=$4 AND a.media_type=$5 AND a.metadata->>'name'=$6`, member.Name, field, coordinate, catalogPath, media, name).Scan(&key, &present, &object, &decision, &revision)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", false, ErrNotFound
	}
	if e != nil {
		return "", false, e
	}
	if revision != member.SourceRevision {
		return "", false, ErrSourceChanged
	}
	if decision == "denied" {
		return "", false, ErrDenied
	}
	if !object {
		return "", false, ErrConflict
	}
	if !present {
		return "", false, nil
	}
	if len(key) != 64 || strings.Trim(key, "0123456789abcdef") != "" {
		return "", false, ErrConflict
	}
	if member.Format == "pypi" {
		return PythonBlobPath(name, key, coordinate), true, nil
	}
	return NPMBlobPath(name, key), true, nil
}
