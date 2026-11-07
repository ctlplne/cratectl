// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"encoding/json"
	"strings"
	"testing"

	crypt "ctlplne.dev/cratectl/internal/crypto"
	"ctlplne.dev/cratectl/internal/gomodule"
)

func hostedPublicationEvent(t testing.TB) (GoHostedPublication, crypt.JournalEvent) {
	t.Helper()
	p := GoHostedPublication{"owned-team", "owned", gomodule.Coordinate{Module: "go.cratectl.invalid/Owned/offline", Version: "v1.0.0"}, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)}
	raw, err := json.Marshal(map[string]any{"tenant": p.Tenant, "sequence": 1, "kind": "go.module.published", "data": map[string]any{"repository": p.Repository, "module": p.Coordinate.Module, "version": p.Coordinate.Version, "representations_sha256": map[string]string{"zip": p.ZIP, "mod": p.Mod, "info": p.Info}}})
	if err != nil {
		t.Fatal(err)
	}
	event := crypt.JournalEvent{Sequence: 1, Payload: string(raw)}
	event.Hash = crypt.Digest([]byte("\n" + event.Payload))
	return p, event
}

func TestGoHostedPublicationRequiresExactOriginalThreeRepresentations(t *testing.T) {
	for _, scenario := range []string{"original", "wrong-tenant", "wrong-repository", "wrong-module", "wrong-version", "noncanonical-coordinate", "wrong-kind", "wrong-sequence", "changed-link", "missing-digest", "extra-digest", "null-digest", "uppercase-digest", "short-digest", "duplicate-digest", "digest-alias", "null-map", "duplicate-map", "duplicate-repository", "repository-alias", "null-data", "duplicate-data", "trailing", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			p, event := hostedPublicationEvent(t)
			rehash := true
			switch scenario {
			case "wrong-tenant":
				p.Tenant = "other-team"
			case "wrong-repository":
				p.Repository = "other"
			case "wrong-module":
				p.Coordinate.Module += "/other"
			case "wrong-version":
				p.Coordinate.Version = "v1.1.0"
			case "noncanonical-coordinate":
				p.Coordinate.Version = "v1.0"
			case "wrong-kind":
				event.Payload = strings.ReplaceAll(event.Payload, "go.module.published", "proxy.retrieval.ready")
			case "wrong-sequence":
				event.Payload = strings.Replace(event.Payload, `"sequence":1`, `"sequence":2`, 1)
			case "changed-link":
				event.Hash = p.Info
				rehash = false
			case "missing-digest":
				event.Payload = strings.Replace(event.Payload, `,"zip":"`+p.ZIP+`"`, "", 1)
			case "extra-digest":
				event.Payload = strings.Replace(event.Payload, `"zip":`, `"other":"`+p.ZIP+`","zip":`, 1)
			case "null-digest":
				event.Payload = strings.Replace(event.Payload, `"zip":"`+p.ZIP+`"`, `"zip":null`, 1)
			case "uppercase-digest":
				event.Payload = strings.Replace(event.Payload, p.ZIP, strings.ToUpper(p.ZIP), 1)
			case "short-digest":
				event.Payload = strings.Replace(event.Payload, p.ZIP, p.ZIP[1:], 1)
			case "duplicate-digest":
				event.Payload = strings.Replace(event.Payload, `"zip":`, `"zip":"`+p.ZIP+`","zip":`, 1)
			case "digest-alias":
				event.Payload = strings.Replace(event.Payload, `"zip":`, `"ZIP":"`+p.ZIP+`","zip":`, 1)
			case "null-map":
				event.Payload = strings.Replace(event.Payload, `"representations_sha256":{`, `"representations_sha256":null,"ignored":{`, 1)
			case "duplicate-map":
				event.Payload = strings.Replace(event.Payload, `"representations_sha256":`, `"representations_sha256":{},"representations_sha256":`, 1)
			case "duplicate-repository":
				event.Payload = strings.Replace(event.Payload, `"repository":`, `"repository":"owned","repository":`, 1)
			case "repository-alias":
				event.Payload = strings.Replace(event.Payload, `"repository":`, `"Repository":"owned","repository":`, 1)
			case "null-data":
				event.Payload = strings.Replace(event.Payload, `"data":{`, `"data":null,"ignored":{`, 1)
			case "duplicate-data":
				event.Payload = strings.Replace(event.Payload, `"data":`, `"data":{},"data":`, 1)
			case "trailing":
				event.Payload += `{}`
			case "oversize":
				event.Payload += strings.Repeat(" ", crypt.MaxJournalPayload)
			}
			if rehash {
				event.Hash = crypt.Digest([]byte(event.PreviousHash + "\n" + event.Payload))
			}
			got, err := BindGoHostedPublication(p.Tenant, p.Repository, p.Coordinate, event)
			if scenario == "original" {
				if err != nil || got != p {
					t.Fatal("original publication lost", err)
				}
			} else if err == nil || got != (GoHostedPublication{}) {
				t.Fatal("invalid binding exposed publication", scenario, err)
			}
		})
	}
}

func FuzzGoHostedPublicationBindings(f *testing.F) {
	p, event := hostedPublicationEvent(f)
	f.Add(event.Payload)
	f.Add(`{"kind":"go.module.published","data":null}`)
	f.Fuzz(func(t *testing.T, payload string) {
		if len(payload) > 64<<10 {
			return
		}
		event.Payload = payload
		event.Hash = crypt.Digest([]byte("\n" + payload))
		got, err := BindGoHostedPublication(p.Tenant, p.Repository, p.Coordinate, event)
		if err != nil && got != (GoHostedPublication{}) {
			t.Fatal("failed parse leaked publication")
		}
		if err == nil && (got.Tenant != p.Tenant || got.Repository != p.Repository || got.Coordinate != p.Coordinate || !uploadDigest.MatchString(got.ZIP) || !uploadDigest.MatchString(got.Mod) || !uploadDigest.MatchString(got.Info)) {
			t.Fatal("accepted binding changed identity")
		}
	})
}
