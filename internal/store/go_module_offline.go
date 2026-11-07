// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"encoding/json"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
)

// GoHostedPublication binds original representation bytes to a historical hosted
// publication. It carries no present-day authorization, policy or SumDB grant.
type GoHostedPublication struct {
	Tenant     string              `json:"tenant"`
	Repository string              `json:"repository"`
	Coordinate gomodule.Coordinate `json:"coordinate"`
	ZIP        string              `json:"zip_sha256"`
	Mod        string              `json:"mod_sha256"`
	Info       string              `json:"info_sha256"`
}

// BindGoHostedPublication checks the original event after its complete journal
// range and external checkpoint signature have independently verified. Merely
// hashing an isolated event is insufficient authentication.
func BindGoHostedPublication(tenant, repository string, c gomodule.Coordinate, event crypt.JournalEvent) (GoHostedPublication, error) {
	if !Name.MatchString(tenant) || !Name.MatchString(repository) {
		return GoHostedPublication{}, ErrGoModuleUnvalidated
	}
	if _, err := gomodule.Canonical(c.Module, c.Version); err != nil || crypt.VerifyJournalEvent(tenant, event) != nil {
		return GoHostedPublication{}, ErrGoModuleUnvalidated
	}
	envelope, ok := checksumJournalObject([]byte(event.Payload), "tenant", "sequence", "kind", "data")
	if !ok {
		return GoHostedPublication{}, ErrGoModuleUnvalidated
	}
	var originalTenant, kind string
	var sequence int64
	if json.Unmarshal(envelope["tenant"], &originalTenant) != nil || originalTenant != tenant || json.Unmarshal(envelope["sequence"], &sequence) != nil || sequence != event.Sequence || json.Unmarshal(envelope["kind"], &kind) != nil || kind != "go.module.published" {
		return GoHostedPublication{}, ErrGoModuleUnvalidated
	}
	data, ok := checksumJournalObject(envelope["data"], "repository", "module", "version", "representations_sha256")
	if !ok {
		return GoHostedPublication{}, ErrGoModuleUnvalidated
	}
	var repo, module, version string
	if json.Unmarshal(data["repository"], &repo) != nil || repo != repository || json.Unmarshal(data["module"], &module) != nil || module != c.Module || json.Unmarshal(data["version"], &version) != nil || version != c.Version {
		return GoHostedPublication{}, ErrGoModuleUnvalidated
	}
	digests, ok := checksumJournalObject(data["representations_sha256"], "zip", "mod", "info")
	if !ok || len(digests) != 3 {
		return GoHostedPublication{}, ErrGoModuleUnvalidated
	}
	var values [3]string
	for n, key := range []string{"zip", "mod", "info"} {
		if json.Unmarshal(digests[key], &values[n]) != nil || !uploadDigest.MatchString(values[n]) {
			return GoHostedPublication{}, ErrGoModuleUnvalidated
		}
	}
	return GoHostedPublication{tenant, repository, c, values[0], values[1], values[2]}, nil
}
