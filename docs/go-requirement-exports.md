# Retain a hosted Go requirement graph

Implemented but unverified. Local ARM build/unit/race/lint and tagged compilation
do not qualify real PostgreSQL, the native CLI, upgrades or the complete export
journey. Resumable graph collection and the independently signed offline caller
remain required. All 14 cases/seven environments in the export plan stay open.

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

The immutable index can reproduce metadata version selection. It establishes no
package/platform closure, current checksum authority, current destination grant
or complete signed offline collection. Those grants remain false. The full
independently selected key/head and original journal must authenticate the exact
creation before any future offline caller trusts these references.
