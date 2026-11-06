# Go content checksums and external checksum authority

Observed: 2026-11-06. Status: hashing and offline proof primitives implemented;
configured authority, durable publication and customer journeys remain open.
This consumes an external verification service. It does not introduce a signing
service, key custody, CA, vault or workload issuer; GOAL section 4.1 governs.

## Implemented boundary

Go's `h1:` ZIP checksum covers a sorted inventory of original entry names and
SHA-256 file-content digests. ZIP compression, order and timestamps do not define
that checksum. The separate go.mod checksum hashes the original bytes as the
single file `go.mod`. A raw ZIP SHA-256 remains the immutable blob identity;
neither checksum alone establishes an independent trust authority.

The existing bounded ZIP inspection now streams each admitted entry into a
checksum writer, including explicit empty directory entries. It retains bounded
names and digests, not another copy of the expanded archive. Structural, CRC,
size, module-prefix, path, exact-root-mod and cancellation checks must all pass
before either hash is returned. Inspection errors still return an empty result.
All primitives remain in `internal/crypto`. Differential tests compare original
ZIPs against pinned x/mod `dirhash.HashZip` and go.mod against `Hash1`.

`VerifyGoSumDB` consumes original lookup/tile bytes entirely offline. The caller
separately supplies the current configured verifier key, retained signed
checkpoint and the expected ZIP/go.mod h1 values. Empty/unsigned bootstrap trust
is refused; an operator can explicitly configure a signed empty tree. The Go
sumdb client verifies signed heads, record inclusion and consistency, then both
exact module/version checksum entries must match. Missing/duplicate entries,
forged proofs, wrong keys and a same-key signed fork fail without partial output.
Untrusted error details are not returned or logged. No process exits on a fork.

The input has at most128 responses and1MiB total key/checkpoint/path/response
bytes; each response is at most64KiB, each signed checkpoint16KiB and a verifier
key4096bytes. Only the exact canonical lookup and height8 hash-tile paths are
accepted, with exact tile lengths. Reads, including partial-tile fallback, share
a256request/1MiB copied-response budget. These are bounded admission profiles,
not claims of full arbitrary-log-size compatibility or whole-process RSS limits.

An old immutable record can remain valid on a proven newer timeline. Verification
retains the newer checkpoint; this establishes consistency, not current freshness,
publisher identity, scan evidence or package approval. The returned checkpoint is
only a proposal until the following durable path exists. `require_checksum` still
refuses bundle retrieval: this foundation does not enable public Go proxy mode.

## Required integration, in dependency order

1. Add an explicit Go proxy authority configuration using the common destination,
   DNS/CIDR, redirect, TLS and credential-reference controls. Bind the verifier key
   and initial signed checkpoint separately from package responses. Never infer
   a destination from `.info` Origin, a package URL, client input or environment
   defaults. No implicit public checksum service, VCS/direct fallback, or secret
   values in repository metadata. Surface current trust and failure in API/CLI/UI.
2. Retain tenant-scoped authority/key revisions and original signed checkpoints
   with forced RLS. Bind authority identity to the exact verifier key, not only
   its human-readable name. Preserve previous trust and audit explicit key/reset
   changes. Repository source revision and current grants must fence every use.
   Concurrent publications need compare-and-swap of the prior checkpoint plus
   consistency verification against a winner; never overwrite a newer timeline.
3. Gather bounded original lookup/tile responses outside database transactions,
   sharing the retrieval's deadline, transfer slots and renewable lease. Stage
   and sync immutable proof bytes before referencing them. Replay the same proof
   offline against the current authority and archive-derived h1 values. An online
   collector must enforce the same bounds at transfer time, before allocation.
4. Extend typed common bundle completion with exact authority/key/source/prior-
   checkpoint bindings and proof references. Verify current trust and both
   hashes; commit the proposed checkpoint, all three artifact references,
   integrity work, journal/outbox and idempotency together. A competing trust,
   source, lease, grant or checkpoint change must roll back the whole result.
   A caller-supplied `verified` flag is insufficient evidence.
5. Add current-policy cache and post-readback guards. Offline use requires retained
   proof and an explicit current trust/freshness policy; an unavailable authority
   does not mean verified. Keep independent checksum status separate from scan,
   approval, quarantine and mutable latest/catalog advertisements. Preserve proof
   references through lifecycle/GC, backup/restore and export; provide independent
   offline verification without a vendor account or running cratectl server.
6. Qualify the complete configured proxy/group journey before enabling its public
   route or repository creation. Then finish conditional refresh as a separate
   complete three-member validation contract; a ZIP-only304 remains insufficient.

## Evidence and test placement

The real x/mod test server is used only as an in-memory external-service stand-in;
test signing keys are in-memory synthetic fixtures. The public deterministic
fuzz seed keeps signed coordinator/worker baselines identical; no fixture key
implements a product signing service.
ARM local gates exercise parsing, streams, real owned child processes and these
stand-ins. No local PostgreSQL or emulated x86 acceptance is claimed.

Existing GitHub unit/race jobs run these primitives on actual Linux amd64,
Linux arm64 and macOS arm64. Existing native Go jobs retain all28 real-PostgreSQL
functions normally/race and every312check hosted/group case on both Linux hosts.
New durable-authority tests must run through those native jobs, with missing
database configuration fatal and no skipped cases counted as passes. Preserve
first failures, exact source/binary/tool/fixture identity and original safe
summaries. An external provider fixture pass is not public-service interoperability.

Required future cases include authority/key/source/grant change during fetch and
readback, concurrent checkpoint advancement, signed fork and corrupt/missing
proofs, origin/authority failures, tenant collision, no-cache/expired/offline
policy, restart, interrupted publication, export/restore and GC protection.
Full stock-client checksum-on proxy/group qualification must distinguish the
client's own checksum policy from cratectl's independent verification policy.
All450 artifact capabilities/41families and later stages remain incomplete.

Primary references checked 2026-11-06: [Go authentication and checksum
database](https://go.dev/ref/mod#authenticating), [directory hash
contract](https://pkg.go.dev/golang.org/x/mod/sumdb/dirhash), and [standard checksum
client operations](https://pkg.go.dev/golang.org/x/mod/sumdb#ClientOps).
Implementation uses the already pinned BSD-3-Clause x/mod v0.42.0 dependency;
no new dependency, automatic upgrade or external service is introduced.
