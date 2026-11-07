# Retain a hosted Go requirement graph

Collection/offline caller implemented but native unverified. Local ARM
build/unit/race/lint and tagged compilation do not qualify that caller's real
PostgreSQL, external signer, stock SDK or complete export journey. The separate
durable-creation source52dca42 is whole-campaign accepted by actual read-only
verifier42426208635:26 original jobs/19 unchanged safe summaries/78 reports. All 14 cases/seven environments in the
export plan remain required.

Use the same private request as the [preview](go-requirement-preview.md). A tenant
administrator needs current access to one hosted repository at its exact source
revision. Create with a stable idempotency key:

```sh
umask 077
cratectl --config /private/path/client.json \
  --method POST --path /api/v1/go/export-sets/requirements \
  --body-file /private/path/requirements-request.json \
  --idempotency-key project-export-unique-request \
  --timeout 2m --response-limit 16777216 --raw-response \
  > /private/path/requirement-export-receipt.json
```

Retry that exact request/key after an uncertain response. A changed project,
revision, lifetime or byte budget conflicts with the original receipt. Recovery
returns the original bytes after checking the caller's current administrator
access; it does not make a denied source downloadable.

Before committing references, the server reads original dependency metadata,
independently rebuilds the requirement graph, checks every selected ZIP/mod/info,
and stages/syncs the project, index, source manifests, selection and graph parent.
One fenced transaction rechecks all examined versions and selected roots, then
commits the session, references, event, receipt and job intent together. Missing
bytes, changed decisions, full queues or exhausted shared session quota refuse
creation. Staged but unreferenced files are not a committed export.

The receipt's `manifest` identifies the complete graph parent. Its separate
`selection_manifest` identifies the existing selected-root session. They have the
same session ID and lifecycle, with distinct immutable byte identities. Do not
substitute either manifest for the other's profile or signed creation binding.

Read status with `GET /api/v1/go/export-sets/requirements/{id}`. The following
GET/HEAD paths require `?generation={current-generation}`:

| Suffix after `/api/v1/go/export-sets/requirements/{id}` | Original bytes |
| --- | --- |
| `/manifest` | Complete graph parent, at most 16 MiB |
| `/main` | Supplied original project go.mod, at most 1 MiB |
| `/proof` | Canonical original-input index, at most 2 MiB |
| `/selection` | Existing selected-root manifest, at most 8 MiB |
| `/inputs/{ordinal}/manifest` | Examined input's source-policy manifest |
| `/inputs/{ordinal}/mod` | Examined input's original go.mod |

Ordinals start at zero and follow the parent source list. Range, HEAD and
conditional responses retain current all-input policy/generation checks. Each
transfer rechecks after opening verified bytes and during its bounded lease.
An unselected lower input's later denial fences the complete graph, including
selected-root reads through the existing set routes. A later allowance does not
silently replace original decision evidence: cancel and prepare a fresh export.

Selected payloads remain at `/api/v1/go/export-sets/{id}/roots/{ordinal}/{kind}`.
Renew, acknowledge or cancel through that set's existing `/control` route using
the receipt's **selection_manifest.digest**, expected generation and a stable
mutation key. An acknowledgment records client intent; `delivery_verified` stays
false. Terminal states release selected payload pins while retaining the project,
index, graph/source/selection manifests and examined .mod originals as audit data.
This reference accounting is not physical garbage collection or byte erasure.

Project files can contain private comments and dependency paths. Keep downloaded
metadata and request/receipt files private. The export appends no runtime config,
credential value or signing key. It creates no signing service, CA or vault.

Collect every original with the new requirement-specific command. Independently
select the tenant, full journal range/head, original creation sequence and trusted
external public key. The bundled public key is retained evidence; its presence
does not make it trusted. Substitute your exact reviewed values below:

```sh
cratectl go-requirement-export-collect \
  --config /private/path/client.json --set-id "$SET_ID" --generation "$GENERATION" \
  --output-directory /private/path/requirement-collection \
  --journal-file /private/path/journal.jsonl --journal-tenant "$TENANT" \
  --journal-event-sequence "$CREATED_SEQUENCE" \
  --journal-through "$HEAD_SEQUENCE" --journal-through-hash "$HEAD_HASH" \
  --checkpoint-file /private/path/checkpoint.json \
  --checkpoint-signature-file /private/path/checkpoint.sig \
  --checkpoint-key-file /independent/trust/signer-public.pem
```

For a range starting above zero, also supply `--journal-after` and
`--journal-after-hash`. The directory's parent must already be owner-private.
Add `--resume` only for the same immutable collection and explicitly current
generation. Each original range checks current complete-input source authority.
Partial bytes remain private on interruption; corrupt prefixes are refused and
preserved. Renewal uses the existing control route and selection digest; the
first completed local receipt retains its original generation/bytes on replay.

After transfer, independently select that same original trust before verification
or assembly. The source registry is unnecessary for these historical checks:

```sh
cratectl go-requirement-export-verify \
  --collection-directory /private/path/requirement-collection --set-id "$SET_ID" \
  --journal-tenant "$TENANT" --journal-event-sequence "$CREATED_SEQUENCE" \
  --journal-through "$HEAD_SEQUENCE" --journal-through-hash "$HEAD_HASH" \
  --checkpoint-key-file /independent/trust/signer-public.pem

cratectl go-requirement-export-offline \
  --collection-directory /private/path/requirement-collection --set-id "$SET_ID" \
  --output-directory /private/path/requirement-offline \
  --journal-tenant "$TENANT" --journal-event-sequence "$CREATED_SEQUENCE" \
  --journal-through "$HEAD_SEQUENCE" --journal-through-hash "$HEAD_HASH" \
  --checkpoint-key-file /independent/trust/signer-public.pem
```

These commands bind the complete original signed journal to the actual creation,
verify every indexed original, replay metadata version selection and inspect all
selected native representations. The offline receipt returns a private `file:`
`goproxy` after the complete bundle is synced/published. Its proof directory
retains all originals. Examined lower versions supply `.mod` metadata for native
selection replay; version lists/latest and ZIP/info advertise selected roots only.
Existing output requires explicit `--resume`; changed published bytes are refused.

Both commands accept bounded `--max-bytes` (default 2 GiB, maximum 65 GiB) and
`--timeout` (default five minutes, maximum one hour). Collection/assembly chunk
sizes range from 64 KiB to 8 MiB. The collector also caps requests at 16,384.
Bindings/completions remain at most 512 KiB. Linux/macOS private-file locking/sync
semantics are required; Windows qualification remains open.

The immutable index can reproduce metadata version selection. Receipt flags for
package/platform closure, checksum authority and current destination admission
remain false. Historical offline proof does not bypass a new destination's
permissions or scanning policy. No package script or downloaded code is executed.
See [the caller decision](adr/0071-signed-go-requirement-collection-and-offline.md)
for the precise implementation and remaining qualification boundaries.
