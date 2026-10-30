// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"ctlplne.dev/cratectl/internal/store"
	"encoding/json"
	"strings"
	"testing"
)

func TestRepairPlanRejectsAmbiguousOrUnboundedJSON(t *testing.T) {
	valid := `{"path":"file","digest":"` + strings.Repeat("a", 64) + `","expected_source_revision":0,"reason":"recover","provenance":"independent copy"}`
	if _, ok := decodeRepairRequest([]byte(valid)); !ok {
		t.Fatal("valid plan rejected")
	}
	for _, raw := range []string{strings.Replace(valid, `"path":"file"`, `"path":"file","path":"other"`, 1), strings.Replace(valid, `"path":"file"`, `"path":"file","Path":"other"`, 1), strings.Replace(valid, `"expected_source_revision":0`, `"expected_source_revision":null`, 1), strings.Replace(valid, `"reason":"recover"`, `"reason":""`, 1), strings.Replace(valid, `"path":"file"`, `"path":"line\ncontrol"`, 1), strings.Replace(valid, `"provenance":"independent copy"`, `"provenance":"`+strings.Repeat("x", 1025)+`"`, 1), valid + `{}`, strings.Repeat(" ", 8193)} {
		if _, ok := decodeRepairRequest([]byte(raw)); ok {
			t.Fatal("ambiguous or unbounded repair plan accepted")
		}
	}
}
func FuzzRepairPlan(f *testing.F) {
	data, _ := json.Marshal(store.RepairRequest{Path: "file", Digest: strings.Repeat("a", 64), Reason: "recover", Provenance: "backup"})
	f.Add(data)
	f.Add([]byte(`{"expected_source_revision":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		input, ok := decodeRepairRequest(data)
		if ok && input.Validate() != nil {
			t.Fatal("invalid accepted plan")
		}
	})
}
