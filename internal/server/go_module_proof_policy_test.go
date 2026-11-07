// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"ctlplne.dev/cratectl/internal/store"
)

func TestGoChecksumExpiredProofReportsRetryableVerificationWithoutPrivateDetails(t *testing.T) {
	for _, err := range []error{store.ErrGoChecksumProofExpired, fmt.Errorf("private fixture detail: %w", store.ErrGoChecksumProofExpired)} {
		w := httptest.NewRecorder()
		respondErr(w, err)
		var response struct {
			Error struct{ Code, Action string } `json:"error"`
		}
		if w.Code != 503 || w.Header().Get("Retry-After") != "1" || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Error.Code != "go_checksum_proof_expired" || !strings.Contains(response.Error.Action, "checksum authority") || strings.Contains(w.Body.String(), "private fixture detail") {
			t.Fatal("expired proof became not-found, internal error or private detail", w.Code, w.Body.String())
		}
	}
}
