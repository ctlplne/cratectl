// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"testing"
	"time"
)

func TestGoModuleNegativeAdmissionIsCurrentRequestAndGenerationScoped(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	state := Retrieval{Repository: "source", Path: "owned/@v/v1.0.0.zip", State: "negative", LastStatus: 404, Generation: 3, Now: now, FreshUntil: now}
	admission := NativeAdmission{Repository: state.Repository, Path: state.Path, Generation: state.Generation}
	if goModuleNegativeAdmitted(state, nil) || !goModuleNegativeAdmitted(state, []NativeAdmission{admission}) {
		t.Fatal("no-cache negative response was reused or failed its own request")
	}
	for _, field := range []string{"repository", "path", "generation", "stale"} {
		a := admission
		switch field {
		case "repository":
			a.Repository = "other"
		case "path":
			a.Path = "other"
		case "generation":
			a.Generation--
		case "stale":
			a.Stale = true
		}
		if goModuleNegativeAdmitted(state, []NativeAdmission{a}) {
			t.Fatal("unbound negative admission accepted", field)
		}
	}
	for _, field := range []string{"state", "status", "source", "generation"} {
		r := state
		switch field {
		case "state":
			r.State = "ready"
		case "status":
			r.LastStatus = 200
		case "source":
			r.SourceChanged = true
		case "generation":
			r.Generation = 0
		}
		if goModuleNegativeAdmitted(r, []NativeAdmission{admission}) {
			t.Fatal("invalid negative cache witness accepted", field)
		}
	}
	state.FreshUntil = now.Add(time.Second)
	if !goModuleNegativeAdmitted(state, nil) {
		t.Fatal("fresh bound negative response was not usable")
	}
}
