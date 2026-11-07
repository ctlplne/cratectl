// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var ErrJournalInput = errors.New("invalid bounded journal range input")
var ErrJournalChanged = errors.New("retained journal anchor does not match the supplied checkpoint")

type JournalRange struct {
	After       int64
	AfterHash   string
	Through     int64
	ThroughHash string
	Limit       int
}

func journalHashInTx(ctx context.Context, tx pgx.Tx, sequence int64) (string, error) {
	if sequence == 0 {
		return "", nil
	}
	var hash *string
	err := tx.QueryRow(ctx, `SELECT CASE WHEN octet_length(hash)=64 THEN hash ELSE NULL END FROM cratectl.events WHERE sequence=$1`, sequence).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrJournalChanged
	}
	if err != nil {
		return "", err
	}
	if hash == nil {
		return "", crypt.ErrJournalEvidence
	}
	return *hash, nil
}

func journalCheckpointInTx(ctx context.Context, tx pgx.Tx, tenant string) (crypt.JournalAnchor, error) {
	out := crypt.JournalAnchor{Tenant: tenant}
	if !out.Valid() {
		return crypt.JournalAnchor{}, ErrJournalInput
	}
	var hash *string
	err := tx.QueryRow(ctx, `SELECT sequence,CASE WHEN octet_length(hash)=64 THEN hash ELSE NULL END FROM cratectl.events ORDER BY sequence DESC LIMIT 1`).Scan(&out.Sequence, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return crypt.JournalAnchor{}, err
	}
	if hash == nil {
		return crypt.JournalAnchor{}, crypt.ErrJournalEvidence
	}
	out.Hash = *hash
	if !out.Valid() {
		return crypt.JournalAnchor{}, crypt.ErrJournalEvidence
	}
	return out, nil
}

// This is an unsigned observation, not an independently authenticated anchor.
func (s *Store) JournalCheckpoint(ctx context.Context, i Identity) (crypt.JournalAnchor, error) {
	var out crypt.JournalAnchor
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		var err error
		out, err = journalCheckpointInTx(ctx, tx, i.Tenant)
		return err
	})
	if err != nil {
		return crypt.JournalAnchor{}, err
	}
	return out, nil
}

func journalPageInTx(ctx context.Context, tx pgx.Tx, start, head crypt.JournalAnchor, limit int) (crypt.JournalPage, error) {
	out := crypt.JournalPage{Version: 1, Tenant: start.Tenant, After: start.Sequence, AfterHash: start.Hash, Through: head.Sequence, ThroughHash: head.Hash, Items: []crypt.JournalEvent{}, NextAfter: start.Sequence, NextHash: start.Hash}
	if !start.Valid() || !head.Valid() || start.Tenant != head.Tenant || start.Sequence > head.Sequence || limit < 1 || limit > crypt.MaxJournalPageEvents {
		return crypt.JournalPage{}, ErrJournalInput
	}
	for _, anchor := range []crypt.JournalAnchor{start, head} {
		hash, err := journalHashInTx(ctx, tx, anchor.Sequence)
		if err != nil {
			return crypt.JournalPage{}, err
		}
		if hash != anchor.Hash {
			return crypt.JournalPage{}, ErrJournalChanged
		}
	}
	// Read only bounded metadata first. A count limit alone would permit 1,000
	// arbitrarily large event payloads to cross the database connection.
	rows, err := tx.Query(ctx, `SELECT sequence,octet_length(payload),CASE WHEN octet_length(previous_hash)<=64 THEN previous_hash ELSE NULL END,CASE WHEN octet_length(hash)=64 THEN hash ELSE NULL END FROM cratectl.events WHERE sequence>$1 AND sequence<=$2 ORDER BY sequence LIMIT $3`, start.Sequence, head.Sequence, limit+1)
	if err != nil {
		return crypt.JournalPage{}, err
	}
	ids := []int64{}
	remaining := crypt.MaxJournalPageBytes - 4096
	expected := start.Sequence
	for rows.Next() {
		var sequence int64
		var size int
		var previous, hash *string
		if err = rows.Scan(&sequence, &size, &previous, &hash); err != nil {
			rows.Close()
			return crypt.JournalPage{}, err
		}
		if expected >= head.Sequence || sequence != expected+1 || previous == nil || hash == nil {
			rows.Close()
			return crypt.JournalPage{}, crypt.ErrJournalEvidence
		}
		if size < 1 || size > crypt.MaxJournalPayload {
			rows.Close()
			return crypt.JournalPage{}, crypt.ErrJournalLimit
		}
		// A JSON string can expand each input byte into six escaped bytes. The
		// fixed per-row/header reserve covers hashes, names, numbers and framing.
		cost := 6*size + 512
		if len(ids) >= limit || cost > remaining {
			break
		}
		ids = append(ids, sequence)
		remaining -= cost
		expected = sequence
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return crypt.JournalPage{}, err
	}
	if len(ids) == 0 && start.Sequence < head.Sequence {
		return crypt.JournalPage{}, crypt.ErrJournalEvidence
	}
	if len(ids) > 0 {
		rows, err = tx.Query(ctx, `SELECT sequence,payload,previous_hash,hash FROM cratectl.events WHERE sequence=ANY($1::bigint[]) ORDER BY sequence`, ids)
		if err != nil {
			return crypt.JournalPage{}, err
		}
		for rows.Next() {
			var event crypt.JournalEvent
			if err = rows.Scan(&event.Sequence, &event.Payload, &event.PreviousHash, &event.Hash); err != nil {
				rows.Close()
				return crypt.JournalPage{}, err
			}
			out.Items = append(out.Items, event)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return crypt.JournalPage{}, err
		}
		if len(out.Items) != len(ids) {
			return crypt.JournalPage{}, crypt.ErrJournalEvidence
		}
		last := out.Items[len(out.Items)-1]
		out.NextAfter, out.NextHash = last.Sequence, last.Hash
	}
	out.More = out.NextAfter < head.Sequence
	if _, err = crypt.VerifyJournalPage(ctx, out, start, head); err != nil {
		return crypt.JournalPage{}, err
	}
	return out, nil
}

func (s *Store) JournalPage(ctx context.Context, i Identity, input JournalRange) (crypt.JournalPage, error) {
	start := crypt.JournalAnchor{Tenant: i.Tenant, Sequence: input.After, Hash: input.AfterHash}
	head := crypt.JournalAnchor{Tenant: i.Tenant, Sequence: input.Through, Hash: input.ThroughHash}
	if !start.Valid() || !head.Valid() || start.Sequence > head.Sequence || input.Limit < 1 || input.Limit > crypt.MaxJournalPageEvents {
		return crypt.JournalPage{}, ErrJournalInput
	}
	var out crypt.JournalPage
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		var err error
		out, err = journalPageInTx(ctx, tx, start, head, input.Limit)
		return err
	})
	if err != nil {
		return crypt.JournalPage{}, err
	}
	return out, nil
}

// The older audit list retains its cursor/empty-future semantics while gaining
// the same response-byte and original-event integrity bounds. Its observed head
// is unsigned and may advance between separate list calls.
func (s *Store) JournalEvents(ctx context.Context, i Identity, after int64, limit int) (crypt.JournalPage, error) {
	if after < 0 || limit < 1 || limit > crypt.MaxJournalPageEvents {
		return crypt.JournalPage{}, ErrJournalInput
	}
	var out crypt.JournalPage
	err := s.Tx(ctx, i, false, func(tx pgx.Tx) error {
		if i.Role != "admin" {
			return ErrDenied
		}
		head, err := journalCheckpointInTx(ctx, tx, i.Tenant)
		if err != nil {
			return err
		}
		if after > head.Sequence {
			out = crypt.JournalPage{Version: 1, Tenant: i.Tenant, After: after, Through: head.Sequence, ThroughHash: head.Hash, Items: []crypt.JournalEvent{}, NextAfter: after}
			return nil
		}
		hash, err := journalHashInTx(ctx, tx, after)
		if err != nil {
			return err
		}
		out, err = journalPageInTx(ctx, tx, crypt.JournalAnchor{Tenant: i.Tenant, Sequence: after, Hash: hash}, head, limit)
		return err
	})
	if err != nil {
		return crypt.JournalPage{}, err
	}
	return out, nil
}
