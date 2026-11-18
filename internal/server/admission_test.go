// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransferAdmissionCountsRejectedRequests(t *testing.T) {
	server := New(nil, nil, "https://localhost:38443")
	for range cap(server.slots) {
		server.slots <- struct{}{}
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/r/owned/object.bin", nil))
	used, limit, rejected := server.TransferAdmission()
	if response.Code != 503 || used != 16 || limit != 16 || rejected != 1 {
		t.Fatalf("unexpected admission observation HTTP %d, used %d, capacity %d, rejected %d", response.Code, used, limit, rejected)
	}
	<-server.slots
	used, limit, rejected = server.TransferAdmission()
	if used != 15 || limit != 16 || rejected != 1 {
		t.Fatalf("unexpected observation after releasing capacity %d/%d, rejected %d", used, limit, rejected)
	}
}
