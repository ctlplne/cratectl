// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"strings"
	"testing"
)

const scheduleJSON = `{"expected_revision":0,"interval_seconds":60,"sample_size":2,"enabled":true,"reason":"Owned regression","run_immediately":true}`

func TestIntegrityScheduleParserRejectsAmbiguousOrUnboundedPlans(t *testing.T) {
	if _, ok := decodeScheduleRequest([]byte(scheduleJSON)); !ok {
		t.Fatal("valid schedule rejected")
	}
	for _, body := range []string{
		`{}`, strings.Replace(scheduleJSON, `"expected_revision":0`, `"expected_revision":null`, 1), strings.Replace(scheduleJSON, `"enabled":true`, `"enabled":null`, 1),
		strings.Replace(scheduleJSON, `"sample_size":2`, `"sample_size":0`, 1), strings.Replace(scheduleJSON, `"sample_size":2`, `"sample_size":1000001`, 1), strings.Replace(scheduleJSON, `"sample_size":2`, `"sample_size":2.5`, 1),
		strings.Replace(scheduleJSON, `"interval_seconds":60`, `"interval_seconds":59`, 1), strings.Replace(scheduleJSON, `"interval_seconds":60`, `"interval_seconds":31536001`, 1),
		strings.Replace(scheduleJSON, `"enabled":true`, `"enabled":false`, 1), strings.Replace(scheduleJSON, `"reason":"Owned regression"`, `"reason":" "`, 1),
		strings.Replace(scheduleJSON, `"expected_revision":0`, `"expected_revision":9223372036854775807`, 1),
		strings.Replace(scheduleJSON, `"enabled":true`, `"enabled":true,"enabled":false`, 1), strings.Replace(scheduleJSON, `"sample_size":2`, `"sample_size":2,"ignored":1`, 1),
		strings.Replace(scheduleJSON, `"sample_size":2`, `"sample_size":2,"repository":null`, 1), strings.Replace(scheduleJSON, `Owned regression`, strings.Repeat("x", 1025), 1),
		strings.Replace(scheduleJSON, `Owned regression`, string([]byte{0xff}), 1), scheduleJSON + ` {}`, strings.Repeat(" ", 8193),
	} {
		if _, ok := decodeScheduleRequest([]byte(body)); ok {
			t.Fatal("invalid plan accepted", body)
		}
	}
}
func FuzzIntegritySchedulePlan(f *testing.F) {
	f.Add([]byte(scheduleJSON))
	f.Add([]byte(`{"enabled":true,"enabled":false}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, ok := decodeScheduleRequest(data)
		if !ok {
			return
		}
		if r.Validate() != nil {
			t.Fatal("invalid accepted plan")
		}
		raw, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		if _, ok = decodeScheduleRequest(raw); !ok {
			t.Fatal("canonical plan rejected")
		}
	})
}
