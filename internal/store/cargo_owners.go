// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"math"
	"strings"

	"ctlplne.dev/cratectl/internal/cargo"
	"github.com/jackc/pgx/v5"
)

const cargoOwnerLimit = 64

type CargoOwner struct {
	ID    uint32 `json:"id"`
	Login string `json:"login"`
}

// An empty owner set denotes a crate published before ownership was introduced.
// Its existing writer grants remain sufficient until an administrator adds owners.
func requireCargoOwner(ctx context.Context, tx pgx.Tx, i Identity, repo, key string) error {
	if i.Role == "admin" {
		return nil
	}
	var hasOwners, owns bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cratectl.cargo_crate_owners
 WHERE tenant=$1 AND repository=$2 AND crate_key=$3 AND active),
 EXISTS(SELECT 1 FROM cratectl.cargo_crate_owners
 WHERE tenant=$1 AND repository=$2 AND crate_key=$3 AND actor=$4 AND active)`,
		i.Tenant, repo, key, i.Actor).Scan(&hasOwners, &owns)
	if err == nil && hasOwners && !owns {
		return ErrDenied
	}
	return err
}

func addCargoOwner(ctx context.Context, tx pgx.Tx, tenant, repo, key, actor string) error {
	// The tenant mutation lock serializes ID allocation. IDs remain assigned
	// to the same login even after its last crate ownership is removed.
	_, err := tx.Exec(ctx, `INSERT INTO cratectl.cargo_owner_actors(tenant,actor,cargo_id)
SELECT $1,$2,COALESCE((SELECT cargo_id FROM cratectl.cargo_owner_actors WHERE tenant=$1 ORDER BY cargo_id DESC LIMIT 1),0)+1
WHERE NOT EXISTS(SELECT 1 FROM cratectl.cargo_owner_actors WHERE tenant=$1 AND actor=$2)`, tenant, actor)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO cratectl.cargo_crate_owners(tenant,repository,crate_key,actor) VALUES($1,$2,$3,$4)
ON CONFLICT(tenant,repository,crate_key,actor) DO UPDATE SET active=true WHERE NOT cargo_crate_owners.active`,
		tenant, repo, key, actor)
	return err
}

func cargoOwnersInTx(ctx context.Context, tx pgx.Tx, i Identity, repo, key string) ([]CargoOwner, error) {
	owners := []CargoOwner{}
	rows, err := tx.Query(ctx, `SELECT a.cargo_id,a.actor FROM cratectl.cargo_crate_owners o
JOIN cratectl.cargo_owner_actors a ON (a.tenant,a.actor)=(o.tenant,o.actor)
WHERE o.tenant=$1 AND o.repository=$2 AND o.crate_key=$3 AND o.active ORDER BY a.actor LIMIT $4`,
		i.Tenant, repo, key, cargoOwnerLimit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var actor string
		if err = rows.Scan(&id, &actor); err != nil {
			return nil, err
		}
		if len(owners) >= cargoOwnerLimit || id < 1 || id > math.MaxUint32 || !Name.MatchString(actor) {
			return nil, ErrMetadataLimit
		}
		owners = append(owners, CargoOwner{ID: uint32(id), Login: actor})
	}
	return owners, rows.Err()
}

func cargoOwnersTarget(ctx context.Context, tx pgx.Tx, i Identity, repo, name, key string) error {
	r, err := repositoryInTx(ctx, tx, i, repo, "write")
	if err != nil {
		return err
	}
	if r.Format != "cargo" || r.Mode != "hosted" {
		return ErrConflict
	}
	var stored *string
	err = tx.QueryRow(ctx, `SELECT left(metadata->>'name',65) FROM cratectl.artifacts
WHERE tenant=$1 AND repository=$2 AND starts_with(path,$3) ORDER BY path LIMIT 1`,
		i.Tenant, repo, "crates/"+key+"/").Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if stored == nil || !strings.EqualFold(*stored, name) {
		return ErrNotFound
	}
	return requireCargoOwner(ctx, tx, i, repo, key)
}

func (s *Store) CargoOwners(ctx context.Context, i Identity, repo, name string) ([]CargoOwner, error) {
	key, err := cargo.CollisionKey(name)
	if err != nil {
		return nil, ErrNotFound
	}
	var owners []CargoOwner
	err = s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if err := cargoOwnersTarget(ctx, tx, i, repo, name, key); err != nil {
			return err
		}
		owners, err = cargoOwnersInTx(ctx, tx, i, repo, key)
		return err
	})
	return owners, err
}

func (s *Store) ChangeCargoOwners(ctx context.Context, i Identity, repo, name string, actors []string, add bool) error {
	key, err := cargo.CollisionKey(name)
	if err != nil {
		return ErrNotFound
	}
	if len(actors) < 1 || len(actors) > 32 {
		return cargo.ErrInput
	}
	requested := make(map[string]bool, len(actors))
	for _, actor := range actors {
		if !Name.MatchString(actor) || requested[actor] {
			return cargo.ErrInput
		}
		requested[actor] = true
	}
	return s.Tx(ctx, i, true, func(tx pgx.Tx) error {
		if err := cargoOwnersTarget(ctx, tx, i, repo, name, key); err != nil {
			return err
		}
		current, err := cargoOwnersInTx(ctx, tx, i, repo, key)
		if err != nil {
			return err
		}
		if len(current) == 0 && i.Role != "admin" {
			return ErrDenied
		}
		selection := make(map[string]bool, len(current))
		for _, owner := range current {
			selection[owner.Login] = true
		}
		changed := []string{}
		for _, actor := range actors {
			if selection[actor] != add {
				changed = append(changed, actor)
			}
		}
		if len(changed) == 0 {
			return nil
		}
		if add && len(current)+len(changed) > cargoOwnerLimit || !add && len(current) == len(changed) {
			return ErrConflict
		}
		for _, actor := range changed {
			if add {
				if err = addCargoOwner(ctx, tx, i.Tenant, repo, key, actor); err != nil {
					return err
				}
			} else if _, err = tx.Exec(ctx, `UPDATE cratectl.cargo_crate_owners SET active=false
WHERE tenant=$1 AND repository=$2 AND crate_key=$3 AND actor=$4 AND active`, i.Tenant, repo, key, actor); err != nil {
				return err
			}
		}
		return appendEvent(ctx, tx, i, "cargo.crate.owners.changed", map[string]any{
			"repository": repo, "crate_key": key, "actors": changed, "added": add,
		})
	})
}
