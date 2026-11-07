# Create and control one common hosted Go export set

The set API creates one immutable selection of up to 256 exact hosted Go versions
from one common database observation. The explicit selection, collection and
private file-proxy controls pass the scoped native
[175 campaign](../evidence/2026-11-07/github-1756bb0-checkpoint.json). Complete
dependency/platform closure and current destination admission remain required. See
[ADR0063](adr/0063-atomic-common-go-export-set.md) and the
[complete export plan](qualification/go-export-plan.json).

To derive a proposed selection from project metadata, use the separate
[requirement preview](go-requirement-preview.md). That new API has local evidence
and pending native qualification; complete package/platform closure and immutable
graph proof remain required.

Use a current tenant administrator credential with read access to every selected
repository. Start with the private request body in the
[preview guide](go-export-set-preview.md). Preview is unsigned metadata and
starts no session. Creation independently inspects all original package bytes,
syncs the common manifest and checks every current source/policy identity again.
One late denied, missing, changed or corrupt member refuses the entire creation.

```sh
cratectl --config /private/path/client.json \
  --method POST --path /api/v1/go/export-sets \
  --body-file /private/path/export-set-request.json \
  --idempotency-key my-explicit-export-set-001 --timeout 150s
```

Keep the returned set ID, manifest digest/size, generation and creation sequence
private. If the response is lost, explicitly repeat the same request and key.
The original receipt returns byte for byte under current source administrative
access, with `Idempotent-Replayed=true`. Reusing that key for another selection,
order, lifetime or byte budget conflicts. A replay does not reopen expired or
cancelled downloads or grant current policy approval.

Read `/api/v1/go/export-sets/{set}` for current metadata. Read exact canonical
manifest bytes at `/api/v1/go/export-sets/{set}/manifest?generation=N`. Original
representations use `/api/v1/go/export-sets/{set}/roots/{ordinal}/{kind}?generation=N`,
where ordinal is the zero-based original request order and kind is zip/mod/info.
Set `--response-limit 16777216` for a potentially large common manifest.
Use the CLI's `--raw-response` when retaining hashed bytes; it suppresses the
extra output newline. Save them only to private regular files. GET/HEAD, ranges
and conditionals recheck every selected source before delivery. A denied later
member also fences earlier members. Current generation and ETag bind resumption.
Individual downloads do not record whole-collection completion. The collector
below retains the complete explicitly selected originals. Its private file proxy
passes the scoped 175 campaign; automatic closure and broader qualification remain.

To renew, acknowledge, cancel or expire, POST all four fields to
`/api/v1/go/export-sets/{set}/control` with a new explicit idempotency key:

```json
{
  "action": "renew",
  "expected_generation": 1,
  "lifetime_seconds": 900,
  "manifest_sha256": "<exact original manifest digest>"
}
```

Renewals recheck the complete current selection and never exceed the original
24-hour window. Other actions require lifetime_seconds=0. Each accepted change
increments generation. Acknowledgment records your statement and keeps
`delivery_verified=false`; it certifies no destination publication. Cancellation
and durable expiry release package pins together and retain the historical
manifest. Queue failure retains pins. Terminal sets cannot reopen. Manifest
retention and package-pin accounting do not authorize physical garbage collection.

For independent attribution, retain the complete original journal, external
checkpoint statement/signature, and a public key selected through your separate
trust channel. An adjacent key or copied receipt is insufficient. Bind the exact
common manifest after the complete signed pass:

```sh
cratectl go-export-set-verify \
  --manifest-file /private/path/common-manifest.json \
  --set-id <exact-set-id> \
  --journal-file /private/path/journal.jsonl \
  --journal-tenant <tenant> --journal-event-sequence <creation-sequence> \
  --journal-through <exact-head-sequence> --journal-through-hash <exact-head-hash> \
  --checkpoint-file /private/path/checkpoint.json \
  --checkpoint-signature-file /private/path/checkpoint.sig \
  --checkpoint-key-file /private/path/separately-trusted-public.pem
```

The bounded result identifies the original manifest, root count, declared bytes,
complete journal and independently selected signer. It authenticates the server's
historical common-snapshot statement. It opens no package bytes and leaves
`artifact_bytes_verified`, `dependency_closure`, `checksum_authority_verified`
and `current_registry_admission` false. It cannot establish latest or revoked
history beyond your supplied head. A failed complete pass emits no result.
Use `go-export-set-collect` below for this set format. The existing single-version
collector, index verifier and import profiles retain their original formats.

Limits are 256 entries, 256 KiB request, 32 KiB per child, 8 MiB common manifest and 64 GiB
of declared representations. Creation has 2 minutes, store operations 30 seconds,
and each transfer 90 seconds or the earlier session deadline. The configured
object and shared active-session limits still apply. Reduce the selection or
adjust the explicitly relevant operator budget after a capacity refusal; never
interpret a missing or failed member as a complete bundle. Current destination
scanning/import/provenance, full closure, operator progress and production
qualification remain required.

## Retain every selected original with explicit resume

`go-export-set-collect` passes the scoped native 175 campaign.
It verifies the complete original signed journal before contacting the source,
then binds and downloads the original common manifest and every selected
ZIP/mod/info. Use a current serving generation from set status and the same
independently trusted journal inputs used for verification:

```sh
cratectl go-export-set-collect \
  --config /private/path/client.json --set-id <exact-set-id> --generation 1 \
  --output-directory '/private/path/collected common set' \
  --journal-file /private/path/journal.jsonl \
  --journal-tenant <tenant> --journal-event-sequence <creation-sequence> \
  --journal-through <exact-head-sequence> --journal-through-hash <exact-head-hash> \
  --checkpoint-file /private/path/checkpoint.json \
  --checkpoint-signature-file /private/path/checkpoint.sig \
  --checkpoint-key-file /private/path/separately-trusted-public.pem
```

The output's parent must already be owner-private. Keep tokens and client config
outside the collection. Retained files are manifest.json, checkpoint.json,
checkpoint.sig, signer-public.pem, journal.jsonl and root.NNN.zip/mod/info for
every zero-based original root, plus immutable bindings.json and final receipt.json.
The directory is flat retained input for the native file proxy below. It supplies
no current destination admission or automatic dependency selection.

An interruption keeps private checkpointed bytes and emits no new success result.
Read current set status, explicitly renew if needed, then repeat with the same
original inputs, the new `--generation` and `--resume`. Retained bytes are rehashed.
Corrupt bytes require another directory; the collector preserves the original.
A completed collection resumed under a later generation returns the same original
receipt bytes after current source and content checks. A copied receipt alone
cannot establish current byte integrity or independent signer trust.

The final receipt sets bytes_verified only after every proof and package member
passes its original digest and bounded ZIP/mod/info consistency checks. Current
admission, checksum authority, dependency closure and delivery remain false. A
late denied or missing member leaves earlier retained files without a new complete
receipt. Existing original receipts remain historical records when a later resume
fails. The single-version collector keeps its original independent format.

Choose `--chunk-bytes` from 65536 through 8388608, `--max-bytes` through 65 GiB and
`--timeout` through 1h. Default chunks are 4 MiB; use 8 MiB when needed to stay within
the 16,384 network-request ceiling. The separate journal byte/time budgets apply
before the HTTP/copy/inspection deadline. Source expiry and 90-second transfer
leases still apply. Metadata is bounded to 512 KiB and directory enumeration to 780
entries. Actual throughput/large-volume/Windows qualification remains required.

## Prepare one private native file proxy

`go-export-set-offline` independently verifies the complete retained journal and
original common creation again, using your separately selected signer/head. It
then copies every selected original into native Go proxy paths, retains all seven
original proof/collection metadata files, and checks the ZIP/mod/info consistency
and native h1 identities. It needs no registry connection or client credentials.

```sh
cratectl go-export-set-offline \
  --collection-directory '/private/path/collected common set' \
  --set-id <exact-set-id> --output-directory '/private/path/offline common set' \
  --journal-tenant <tenant> --journal-event-sequence <creation-sequence> \
  --journal-through <exact-head-sequence> --journal-through-hash <exact-head-hash> \
  --checkpoint-key-file /private/path/separately-trusted-public.pem
```

Select the key through an independent trust channel. The command uses only the
collection's exact journal.jsonl/checkpoint.json/checkpoint.sig for the other
proof inputs. Merely copying signer-public.pem or receipt.json grants no trust.
Its parent and output must be owner-private, and output must be outside the
collection. Keep the original directory unchanged during preparation.

The command stages everything under `staging/`, syncs files and directories, then
atomically publishes `bundle/`. Use the receipt's exact `goproxy` file URL, which
points to `bundle/proxy`. `bundle/proof` retains original proof and collection
metadata; `bundle/receipt.json` records the complete selected originals and hashes.
Lists and latest information describe this selected set only. No package content
is extracted or executed by cratectl.

A failed or interrupted command emits no complete success result. Keep its
private state and repeat the same command with `--resume`; matching partial bytes
are checked before appending. Corrupt or unknown state is preserved and refused.
A completed replay rechecks source and output without repairing published data,
and returns its original receipt byte for byte, including after a lost final
acknowledgement. Applications must accept only a complete successful result.

The receipt's dependency_closure, checksum_authority_verified and
current_registry_admission remain false. Explicitly including a graph does not
prove automatic dependency/permission/provenance closure or destination scanning.
For the declared private download profile, select exactly this file proxy and
disable VCS/toolchain/network fallback. Public checksum authority, full closure,
independent host/platform/scale and destination admission require their own proof.
The 175 campaign qualifies this explicit private graph and interrupted-launch/
acknowledgement replay. Independent-host/PID-descriptor controls belong to the
newer bb source, whose whole campaign acceptance remains pending.
