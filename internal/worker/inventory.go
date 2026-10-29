// SPDX-License-Identifier: BUSL-1.1
package worker

import (
	"context"
	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/store"
	"errors"
	"time"
)

func executeInventory(parent context.Context, db *store.Store, objects *blob.Local, o Options, i store.WorkerIdentity, j store.Job) string {
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	stop, heartError := keepJobLease(ctx, db, i, j, o.Lease, cancel)
	defer stop()
	step, e := db.PrepareInventoryStep(ctx, i, j)
	var page blob.InventoryPage
	status := ""
	if e == nil {
		switch step.Kind {
		case "page":
			page, e = objects.ListInventoryPage(ctx, i.Tenant, step.Progress.RootIdentity, step.Area, step.Bucket, step.Progress.AfterName, step.Progress.PageSize, step.Progress.DirectoryEntries)
		case "hash":
			status, e = objects.CheckInventoryObject(ctx, i.Tenant, step.Progress.RootIdentity, step.Entry, o.MaxObjectBytes, o.BytesPerSecond)
		case "reference":
			var root string
			root, e = objects.InventoryRoot(i.Tenant)
			if e == nil && root != step.Progress.RootIdentity {
				e = blob.ErrStorageChanged
			}
			if e == nil {
				status, e = objects.CheckStored(ctx, i.Tenant, step.Reference.Digest, step.Reference.Size, o.MaxObjectBytes, o.BytesPerSecond)
			}
		}
	}
	if parent.Err() != nil {
		return "abandoned"
	}
	heartbeat := heartError()
	if heartbeat != nil && !errors.Is(heartbeat, store.ErrJobCancelled) {
		return "lease_or_credential_lost"
	}
	complete, done := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
	defer done()
	outcome := ""
	switch {
	case errors.Is(heartbeat, store.ErrJobCancelled) || errors.Is(e, store.ErrJobCancelled):
		outcome, e = db.FailJob(complete, i, j, "worker_stopped", false)
	case e == nil || errors.Is(e, context.DeadlineExceeded) && (step.Kind == "hash" || step.Kind == "reference"):
		if status == "" && e != nil {
			status = "timeout"
		}
		switch step.Kind {
		case "page":
			outcome, e = db.FinishInventoryPage(complete, i, j, page)
		case "hash":
			outcome, e = db.FinishInventoryHash(complete, i, j, step, status)
		case "reference":
			outcome, e = db.FinishInventoryReference(complete, i, j, step.Reference, status)
		default:
			outcome, e = db.FinishInventoryTransition(complete, i, j, step.Kind)
		}
	default:
		code, permanent := "handler_failure", false
		if errors.Is(e, blob.ErrInventoryBudget) || errors.Is(e, store.ErrInventoryEntries) {
			code, permanent = "inventory_budget", true
		}
		if errors.Is(e, blob.ErrStorageChanged) {
			code, permanent = "storage_changed", true
		}
		if errors.Is(e, blob.ErrUnsupported) {
			code, permanent = "unsupported_storage", true
		}
		if errors.Is(e, store.ErrConflict) {
			code, permanent = "invalid_target", true
		}
		outcome, e = db.FailJob(complete, i, j, code, permanent)
	}
	if e != nil {
		// Page acceptance can reject a total-entry budget only after enumeration.
		if errors.Is(e, store.ErrInventoryEntries) {
			outcome, e = db.FailJob(complete, i, j, "inventory_budget", true)
		}
		if e != nil {
			return "completion_unconfirmed"
		}
	}
	return outcome
}
