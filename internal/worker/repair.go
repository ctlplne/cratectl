// SPDX-License-Identifier: BUSL-1.1
package worker

import (
	"context"
	"ctlplne.dev/cratectl/internal/blob"
	"ctlplne.dev/cratectl/internal/store"
	"errors"
	"time"
)

func executeRepair(parent context.Context, db *store.Store, objects *blob.Local, o Options, i store.WorkerIdentity, j store.Job) string {
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	stop, heartbeat := keepJobLease(ctx, db, i, j, o.Lease, cancel)
	defer stop()
	plan, source, e := db.JobRepair(ctx, i, j)
	var prepared *blob.PreparedRepair
	if e == nil {
		prepared, e = objects.PrepareRepair(ctx, i.Tenant, source, o.MaxObjectBytes, o.BytesPerSecond)
	}
	if prepared != nil {
		defer prepared.Close()
	}
	if e == nil {
		e = db.ApplyRepair(ctx, i, j, func(effect context.Context) (blob.RepairInstallation, error) { return prepared.Install(effect) })
	}
	status := ""
	if e == nil {
		status, e = objects.CheckStored(ctx, i.Tenant, plan.Target.Digest, plan.Target.Size, o.MaxObjectBytes, o.BytesPerSecond)
	}
	if parent.Err() != nil {
		return "abandoned"
	}
	if heart := heartbeat(); heart != nil && !errors.Is(heart, store.ErrJobCancelled) {
		return "lease_or_credential_lost"
	}
	complete, done := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
	defer done()
	var outcome string
	if e == nil || status == "timeout" && errors.Is(e, context.DeadlineExceeded) {
		outcome, e = db.FinishRepair(complete, i, j, status)
	} else {
		code, permanent := "repair_attempt_unconfirmed", false
		switch {
		case errors.Is(e, store.ErrRepairAuthorization):
			code, permanent = "repair_requester_authorization", true
		case errors.Is(e, store.ErrRepairChanged), errors.Is(e, store.ErrNotFound):
			code, permanent = "repair_target_changed", true
		case errors.Is(e, store.ErrRepairReferences):
			code, permanent = "repair_reference_conflict", true
		case errors.Is(e, blob.ErrStorageChanged):
			code, permanent = "repair_storage_changed", true
		case errors.Is(e, blob.ErrUnsupported):
			code, permanent = "repair_unsupported_storage", true
		case errors.Is(e, blob.ErrIntegrity):
			code, permanent = "repair_source_integrity", true
		case errors.Is(e, blob.ErrLimit):
			code, permanent = "repair_object_limit", true
		case errors.Is(e, store.ErrRepairInput):
			code, permanent = "repair_invalid_intent", true
		case errors.Is(e, store.ErrJobCancelled):
			code = "repair_cancelled"
		}
		outcome, e = db.FailJob(complete, i, j, code, permanent)
	}
	if e != nil {
		if errors.Is(e, store.ErrRepairAuthorization) || errors.Is(e, store.ErrRepairChanged) || errors.Is(e, store.ErrRepairReferences) {
			state, finish := db.FailJob(complete, i, j, "repair_completion_authority_changed", true)
			if finish == nil {
				return state
			}
		}
		// Installation may have succeeded even when completion cannot be confirmed.
		// The retained source and original durable intent permit an explicit retry.
		return "completion_unconfirmed"
	}
	return outcome
}
