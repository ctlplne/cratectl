// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"fmt"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/store"
)

func TestGoChecksumControllerFailuresKeepStableDistinctCodes(t *testing.T) {
	for _, entry := range []struct {
		err  error
		code string
	}{{crypt.ErrGoChecksumFork, "upstream_checksum_fork"}, {fmt.Errorf("wrapped: %w", crypt.ErrGoChecksumFork), "upstream_checksum_fork"}, {crypt.ErrGoChecksumAuthority, "upstream_checksum_unverified"}, {store.ErrGoChecksumCheckpointChanged, "upstream_checksum_checkpoint_changed"}, {context.Canceled, "retrieval_cancelled"}, {context.DeadlineExceeded, "retrieval_cancelled"}, {errGoModuleChecksumRequired, "upstream_checksum_required"}, {errors.New("untrusted private detail"), "upstream_go_module_validation_failure"}} {
		if got := goModuleFillFailure(entry.err); got != entry.code {
			t.Fatal("checksum failure lost stable classification", got, entry.code)
		}
	}
}
