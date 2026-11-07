# 0063: Commit and control one common Go export set

Date: 2026-11-07. State: implemented; actual native qualification pending.

ADR0062 reads explicitly selected hosted versions in one PostgreSQL snapshot.
Make that selection one durable parent rather than committing each version
separately. A source administrator supplies exact coordinates, expected source
revisions, a lifetime and a declared-byte budget. Automatic dependency selection
and destination admission remain separate unfinished requirements.

Physically hash and inspect every original ZIP/mod/info using the existing
bounded package inspector. Keep at most three files open at once. The original
package objects already occupy immutable synced CAS storage. Write and sync the
complete canonical common manifest before committing any new reference. Under
the same tenant mutation fence as publication, read every source again using
the original preparation time and journal observation. Compare the complete
canonical byte/policy/lifecycle identity. Any changed or denied member rolls
back the entire set. Parent, ordered roots, representation references, event,
original mutation receipt and job intent share one transaction. Replay checks
current administrative source access and returns the exact original receipt;
it does not re-admit historical bytes or reopen a terminal session.

Append migration 17 after the independently qualified schema 16 source `ca44b37`.
Preserve the first 16 checksummed definitions. Three new tenant tables have forced
RLS, immutable identity columns, no runtime DELETE, and only explicit renewable
parent columns writable. Require the exact tenant/expiry/id partial index at
migration and runtime admission. Rebuild sixteen historical native binaries and
run twenty-one upgrade reports on each actual GitHub Linux architecture. Native
schema 16-to 17 tests retain old rows and receipts, reject old binaries, altered
expiry indexes and missing FORCE, and refuse runtime identity rewrites.

Legacy and common exports share the configured active-session budget. Common
manifests remain inventory roots in every state. Representation roots remain
protected until the entire parent is durably cancelled or expired; wall-clock
expiry alone releases nothing. A separate bounded worker reconciles at most one
common set per tenant visit under the same database fence. Queue failure rolls
back expiry and retains all pins. Replica races produce one transition/event/job.
Physical garbage collection remains unfinished; these roots do not authorize it.

Status, renewal, acknowledgment and delivery use current access to every selected
repository. Renewal and each representation/manifest download also check every
current source epoch, allowed representation and immutable item identity. Thus a
late-member denial fences the first member and conditional 304 responses too.
Each control transition increments generation; old ranges cannot resume with an
old generation. Transfers are private/no-store, hash the stored object before
response visibility, recheck whole-set authority during the transfer, and stop
at the session deadline or 90 seconds. Already delivered bytes are not recalled.
Acknowledgment records the caller's statement and leaves delivery_verified=false.

`go-export-set-verify` first authenticates the complete retained journal against
a separately selected external checkpoint key/head. Bind the exact canonical
common manifest to its original creation event, set ID, root count, declared
bytes, immutable object and initial lifecycle fields. Emit only identities,
counts and signature attribution; omit private paths and original policy bodies.
`common_snapshot_manifest_bound=true` authenticates the server's historical
statement. It is not independent inspection of package bytes or a proof of
closure, checksum authority, current admission or history beyond the chosen head.
The original single-version/index profiles keep their existing semantics.

Bound requests to 256 KiB, roots to 256, each child to 32 KiB, common metadata to 8 MiB,
declared package bytes to 64 GiB, complete creation to 2 minutes and store operations
to 30 seconds. The existing server concurrency and object limits still apply.
No package scripts, VCS fallback, toolchain downloads or model deserialization run.
External signing remains external; no CA, vault, issuer or signing service is added.

Native cases must pass on both actual Linux architectures: whole-set physical
intake, ranges/HEAD/conditional denial, generation renewal, byte-exact receipt
replay, late policy/physical failure without partial refs, queue/quota rollback,
replica expiry, inventory roots, old-schema preservation and actual candidate
CLI/external OpenSSL signed two-repository binding with changed-late-member,
wrong event/ID and trailing-journal refusals. Local parser/HTTP/FS stand-ins,
normal/race tagged compilation and vet do not count as native execution.

The all-member durable collector, complete private offline proxy, dependency/
authority/permission/provenance closure, current destination scanner/import,
console progress and full lifecycle/provider/platform/production qualification
remain required by all fourteen export cases, seven environments and the full
450-capability/41-family/later GOAL 4.1 scope. The stopped schema 11 primary,
selected qualified 5483878 b binaries and ten receipts remain untouched.
