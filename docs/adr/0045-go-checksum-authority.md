# Go content checksums and external checksum authority

Observed: 2026-11-06. Status: hashing, offline verification and bounded configured
proof collection qualified in named internal profiles. Durable timeline and
atomic publication qualify in38native GoPGfunctions normally/race. Actual proof
readback/current opaque admission qualifies in43native GoPGfunctions normally/
race; private fill/controller wiring awaits native replay. Customer journeys stay open.
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
only a proposal until durable transaction admission. `require_checksum` and any
configured authority refuse publication without a complete fenced proof; cached
serving remains closed pending proof readback. Public Go proxy mode stays gated.

## Configured collection boundary

Repository settings now carry an explicit endpoint/CIDRs, credential reference,
canonical verifier key and original signed bootstrap checkpoint. Keys distinguish
the authority by exact digest, including when names match; Base64 `+` is part of
the key body. An initial signed checkpoint is not an instruction to reset a
retained timeline. Other formats/modes reject this setting. Public Go proxy
creation remains gated, so this is not yet a customer configuration surface.

`CollectGoSumDB` drives the same authenticated client through a supplied bounded
reader. It retains only successful original lookup/hash-tile responses, with
two concurrent reads, context-aware waiting and no callback entry after observed
cancellation. Proof failure returns neither verification nor a partial snapshot.
Successful snapshots retain the original separately supplied checkpoint and can
replay offline to the same proposed head. A new fuzz target exercises both lookup
and tile mutation, requiring its valid deterministic worker seeds to authenticate.

The server collector uses existing tenant/destination-bound credentials and
DNS/CIDR/redirect/TLS controls. It shares one120second deadline and reserves a
maximum body plus overflow-detection byte and path before each transfer from a
1MiB budget that also charges trust/identity overhead. Failed attempts keep their
reservation; successful short responses refund unused body space. Response
headers have the common separate32KiB transport cap. No implicit public sumdb,
Origin-derived destination, HTTP304, partial/encoded response, cross-authority
redirect, credential fallback or no-store override without explicit opt-in.

The typed proof binds canonical module/version, both archive-derived h1 values
and the separately supplied key/checkpoint. The server replays it offline before
staging original proof JSON with expected SHA256 and exact length; staged bytes
are at most2MiB and remain subject to the common metadata budget. It creates no
artifact reference, trust update, approval, event or idempotency receipt. It is
not yet wired into the common renewable lease/fill admission. Current bundle
fetch and cache guards still refuse configured/required checksum admission.
Common completion now accepts only the complete durable publication below;
a self-selected key, h1 assertion or unfenced proposal cannot bypass it.

Tests use actual inert ZIP/mod inspection and an owned HTTP authority serving a
frozen public x/mod fixture. No private signing key is retained or used by the
server. The new database regression tests both publication and prior cached bytes
under newly required/configured trust, even in a deliberate same-epoch row fault.
Exact5380 executes this29function named Go regression suite normally/race and
the original312stock hosted/group checks on both native GitHub Linux hosts.
Source/unit/race and43fuzz targets pass on Linuxamd64/arm64/macOSarm64. Its wider
ARM durable-jobs profile fails after68assertions; no whole-campaign pass follows.

## Durable publication boundary, qualified internally

Appended immutable migration12 adds forced-RLS tenant/key checkpoint history,
a current-head pointer and repository-scoped proof receipts. Existing11receipt
definitions stay byte-identical. Runtime roles can insert history/receipts, read
their tenant and update only the head revision. A database trigger requires each
head update to advance exactly once to a strictly larger signed tree. The
application checks signatures and consistency before that update. Missing head
history fails closed; it never falls back to a new bootstrap.

An authorized source-epoch snapshot supplies the retained head or explicit
revision-zero bootstrap. Common bundle completion validates original proof JSON's
staged SHA256/length, both independently inspected h1 values and the canonical
coordinate. Under the existing tenant write lock/current source and lease, it
authenticates against the separately retained expected pin. An identical winning
head coalesces by tree size/root; another winner requires bounded offline replay
against that head. Missing tiles return a recollection conflict, with no network
inside the transaction. Authenticated same-size differing roots are a distinct
fork error, even when the authority withholds the retained head's tiles.

The initial/advanced signed heads, three bundle references, internal immutable
proof reference, source/generation receipt, all integrity intents and ready
journal/outbox event share one transaction. The receipt binds all three raw
SHA256 digests and the exact proof object. Proof metadata contains no top-level
module/version and cannot masquerade as a package advertisement. References
retain ordinary unassessed policy; checksum consistency grants no scan approval.

Nine new PostgreSQL functions cover actual staged ZIP/mod hashes, concurrent
repository collectors, same-head coalescing, consistent growth/older lookups,
rollback, source/lease/grant/tenant/key fences, missing tiles/forks, retained
11receipt upgrade, immutable runtime privileges and forced-RLS admission. Exact5ee executes these functions normally/race on bothLinuxhosts, rebuilds11
historical native baselines and runs schema2–11 maintenance journeys into12. The retained primary remains
schema11 on its existing selected binaries, stopped; source work does not migrate it.

The server collector is not yet connected to this publication under the shared
renewable fill lease. Bounded recollection, failure-evidence publication, customer API/CLI/UI, explicit
offline policy, export/backup/GC and native checksum-on proxy/group remain required.
The readback path below admits internal cached bytes only with an opaque token;
current fetch/default resolve/public routing remain closed until integrated.

## Current proof readback, qualified internally

`GoModuleChecksumReadback` authorizes source/grants and the complete current
three-member cache/policy unit in one repeatable-read snapshot. It binds the
immutable receipt, current exact verifier key, retained accepted signed head and
current forward-only timeline. Proof metadata has a4KiB SQL projection bound;
package metadata uses the existing4KiB Go profile bound. The proof reference can
retain an older source epoch because its bytes are immutable; the package and
receipt must match the current epoch and root validation generation.

The server opens the exact proof blob with common SHA256/length verification,
reads at most its bounded size plus one, and accepts only canonical typed JSON.
Decoded field/count/byte bounds apply before re-encoding. Exact re-encoding
rejects duplicate/unknown/trailing fields and ambiguous encodings. Original log
response bytes remain unchanged. The proof's original signed pin must parse
under the configured key but never defines current trust: verification replays
against the separately retained accepted checkpoint and both admitted h1 values.

Only successful verification creates `GoChecksumAdmission`, whose bindings are
unexported and omitted from `NativeAdmission` JSON. The final current SQL guard
rebuilds the same witness and compares tenant, repo, source epoch, root attempt/
validation generations, stale context, exact key/head, proof digest/length and
all3package digests/sizes. It also rechecks current package/proof decisions and
lifecycle. Another tenant's otherwise identical proof token cannot authorize
bytes. A consistent later timeline head leaves an unchanged accepted proof valid.

Proof content is inert verification evidence: unassessed proof bytes may be
parsed and verified, while explicit proof denial or retirement blocks packages.
This does not mark scan evidence clean or relax any package `require_review`.
No network or mutation occurs in readback. The helper will run under the existing
bounded HTTP transfer admission when connected to resolution; private controller below now wires coordinate resolution. Public Go proxy mode
remains gated; metadata and customer/offline/governance journeys are still open.

One new28case unit function and deterministic public-seed fuzz target plus
5PostgreSQL functions/33cases cover canonical parsing, actual corrupt/missing
proof objects, current post-readback denial, digest/size/epoch/generation/stale
changes, historical proof continuity, cross-epoch immutable proof reuse and
cross-tenant identical-token refusal. Exactb6 executes all43named Go functions normally/race and312stock checks onboth
Linuxhosts. Its wider217fullPG/44fuzz campaign is tracked separately. The new44th
fuzz profile also passed10090local ARM executions in11.225seconds with2workers.

## Coordinate controller integration, native replay pending

Configured bundle intake now reads the authorized retained checkpoint before
network access, inspects all three actual representations and both h1 values,
collects/stages proof and submits typed common publication. Missing authority or
standalone configured fetch without a database stays closed. No implicit public
service or response-selected key is introduced.

The existing common fill slot and renewable lease enclose one120second parent
context for all package/proof transfers and publication. At most two completion
attempts are allowed. Only an offline consistency conflict requiring missing
tiles triggers one new proof collection against current trust, outside SQL;
package bytes are not fetched again and the timeline cannot reset. A second
conflict terminates. Cache hit/stale/filled coordinate reads retain physical
proof admission in the resolved request for final common selection after package
readback. Metadata advertisements still need their distinct bounded receipt/
policy witness before complete discovery is qualified.

Stable cache/journal failure codes distinguish a signed fork, unverified proof
and checkpoint conflict. None grants stale. An unavailable checksum authority
currently fails conservatively as unverified evidence; it does not borrow ordinary
origin transient status. Package cancellation/explicit ordinary-origin transient
rules remain. This retains a failure classification only: original failed proof
bytes, tenant/key-wide governance and complete operator recovery remain required.

Five new real-PG functions/12fixed cases cover12concurrent representations sharing
one fill,8fault cases, a blocked proof whose1second lease renews with no partial
references/work/trust, a second repository winning the head followed by exactly
one proof-only recollection, and a known signed fork that preserves prior trust
and denies stale despite its retained window. One8case unit function covers stable
classification. Current48Go/222fullPG compile normally/race locally; actual native
execution is required. Public repository creation/HTTP proxy routing stays gated.

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

### Durable checkpoint implementation constraints

Keep a tenant/key timeline across repository source changes. A shared authority
key must not acquire inconsistent heads through two repositories in the same
tenant; its checkpoint record contains signed heads, not other repositories'
private module names or proof bodies. Proof receipts remain repository-scoped
and bind source/lease, exact three representation digests and the admitted trust
revision. Force RLS on every new table and retain immutable checkpoint history.
Append a new checksummed migration; do not edit the existing11receipts or migrate
the retained primary as a side effect of source development.

Concurrent completion can coalesce an identical already-retained proposed head.
For a different winning head, verify consistency against current trust using
bounded retained evidence, with no network in the transaction. If additional
tiles are needed, roll back and perform bounded re-collection outside it; never
reset the timeline or mislabel missing evidence as clean. Distinguish a proven
signed fork from unavailable/incomplete proof, retain failure evidence and keep
artifact references, trust change, journal/outbox and job intent atomic.

The next native proxy/group profile must separately exercise the stock client's
GOSUMDB policy and cratectl's configured authority. Namespace/source shadowing
does not authorize different contents for one coordinate under one checksum key.
Tenant collision fixtures may use explicitly separate private-log trust keys;
a conflicting lower source under the same authority must fail verification.
Keep the original hosted/group profile and every required failure/restart case.

## Evidence and test placement

The real x/mod test server is used only as an in-memory external-service stand-in;
test signing keys are in-memory synthetic fixtures. The public deterministic
fuzz seed keeps signed coordinator/worker baselines identical; no fixture key
implements a product signing service.
ARM local gates exercise parsing, streams, real owned child processes and these
stand-ins. No local PostgreSQL or emulated x86 acceptance is claimed.

Existing GitHub unit/race jobs run these primitives on actual Linux amd64,
Linux arm64 and macOS arm64. The current native Go inventory retains the original
28 real-PostgreSQL functions plus the new checksum-policy function:29 required
normally/race and every312check hosted/group case on both Linux hosts. The new
collector fuzz target makes43automatic targets; this later source still requires
its own exact native replay after the accepted3b24job/17summary campaign.
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
