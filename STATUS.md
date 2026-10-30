# cratectl execution status

Audited exact-byte repair is implemented locally and awaiting clean-candidate
qualification. It provides administrator preview, a durable source-waiting job,
streaming source submission, fenced installation and immutable readback receipts
while retaining corrupt bytes and preserving policy/lifecycle state. Schema 5
rejects older workers without changing migration receipts 1–4. API, streaming CLI
and console workflows are present. See ADR 0024 and docs/operator/byte-repair.md.

Dirty-build preflights passed real PostgreSQL/race fault, authorization, source,
cancellation and lease checks; stock ORAS recovery; parser fuzzing; and seven
Chromium workflows. These are preliminary observations, not a new clean-build
checkpoint. All broad readiness verdicts and the full remaining scope stay open.


Latest qualified source: `06156af19b9759035e96d63cf7a8bf52903235f7`, authored and committed only as
`imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`.
The authoritative checkpoint is `evidence/2026-10-29/source-configuration-checkpoint.json`.

Proxy/group source settings now have administrator preview, immutable history,
exact-revision replacement, monotonic rollback and cache/locator/writer fences.
Source/group configuration, grants and artifact admission share one snapshot.
Old validators, stale windows and native download authority cannot cross source
revisions. Invalid 304 responses terminate their lease. OCI catalog observations
retain retired/denied peers without reviving them or losing visible content.
See ADR 0023 and `docs/operator/source-configuration.md`.

Clean production artifacts passed 859 assertions and separate race artifacts
passed 350, across 19 runtime records. Stock ORAS, npm, pip and Maven
source replacement/rollback use independent client caches and nontrivial content;
controlled suspension/private-provider reload/epoch refresh/resume is covered.
Six Chromium workflows and 29 named automated A/AA states pass per build. Schema-2
and schema-3 old-binary upgrades, legacy adoption/process kill and repeated real
PostgreSQL race suites pass. Migration receipts 1–3 remain frozen; schema 4 is
current on the owned test database. Unit/vet/race, console reproduction, current
vulnerability and scoped credential/history checks pass. Linux/Windows compile
only. Identity hooks are enabled and reject author and committer overrides.
No reset, recreation, remote mutation or push was executed by this turn.

All 450 capabilities and 41 families remain unfinished, with broad readiness
negative. Complete wider source/grant/locator/network races, managed/hot secret
providers, supported corrupt/old-byte repair, retention/GC, other clients/providers/
platforms, fault/scale and production recovery. Owned test services are stopped;
private data and clean artifacts are retained. Earlier checkpoint evidence follows.

Previous lifecycle-qualified source: `bea2472271bd15993bcae9b8ea12a102b2608abe`, with both
author and committer `imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`.
The authoritative checkpoint is `evidence/2026-10-29/lifecycle-checkpoint.json`;
see `docs/operator/oci-lifecycle.md` for operation and current limits.

Retained OCI retirement now has canonical tombstones, native hosted digest/tag
DELETE, strong-reference protection, administrator holds, explicit byte/graph-
verified restore and repository suspension/removal/recovery. State, writer fences,
journal, durable job intent and idempotency response commit together. A suspended
or removed source fails closed; resumed writers cannot reuse fenced generations.
Current grants/roles apply to replay. Restore preserves quarantine/manual denial
and newer tag targets. No CAS bytes are erased or reported as reclaimed.

Schema 3 adds forced-RLS lifecycle tables and preserves both earlier migration
checksums. Real old-binary version-2 upgrade and legacy adoption/process-kill,
unknown-version, drift, no-op and runtime admission regressions pass. The owned
primary test database was upgraded during controlled maintenance. Older binaries
reject the upgraded schema; rolling/zero-downtime and backup/downgrade recovery
remain open.

Clean production artifacts passed 731 assertions across ten native/installation/
console/maintenance/provider campaigns. Separate race artifacts passed 220
assertions across lifecycle, schema, console, install and OCI hosted/proxy cases.
Full real-PostgreSQL store/server/native-driver race packages ran twice without
skips or races. Five Chromium tests and 24 named automated A/AA states pass per
build, including lifecycle impact previews, holds and explicit recovery. Unit,
vet, race, architecture, console reproduction, Go symbol/dependency vulnerability
and scoped source/history secret checks pass. Linux amd64/arm64 server and Windows
amd64 CLI compile only. No remote mutation or push was executed by this turn.

Retained first failures cover a fixture no-store override, a browser test locator,
async dialog focus, forced-tag group fallback and nested-image restore. The group
negative overlay reproduced HTTP 200 from a lower source after an upstream miss;
current preselection guards return the local tombstone before network/cache work.
Root kind now uses its canonical final path, and older unvalidated manifests must
be repaired before deletion. The exact clean candidate covers these repairs.

All 450 capabilities and 41 format families remain unfinished. Complete versioned
source configuration/credential changes and cache/locator/grant races, full proxy
native discovery through local tombstones, supported old/corrupt-byte repair,
retention/GC, other clients/providers/platforms, security/fault/scale and production
recovery. Test services are stopped; private data and clean artifacts are retained.
Earlier source checkpoints below remain historical evidence within their scope.
The shared remote advanced to `bea2472` outside this turn’s tool commands; GitHub
verifies all 38 published authors/committers and the only contributor as
`imfeelingtheagi`. The initiating actor is not inferred. See
`evidence/2026-10-29/remote-state-lifecycle-audit.json`. No repeated recreation,
reset or push was executed by this turn.

Owner-directed repository reset completed on 2026-10-28. Private GitHub repository
`ctlplne/cratectl` was recreated (new ID 1437631481); the preserved implementation
has a fresh root `887c569ac96c451bccd91ae872317c06a890117a`. GitHub verifies both
author and committer as `imfeelingtheagi`. Repository identity hooks reject the
previous wrong email and block incorrectly attributed history from push.

Fresh clean-build native qualification passed 226 assertions against that exact
root, with matching embedded binary identities. Unit/vet/race, two repeated real
PostgreSQL/server race runs and current/history secret scans passed. The existing
implementation matches the pre-reset SHA-256 inventory. Test services are stopped;
private database data and the original-history recovery copy are retained.
See `evidence/2026-10-28/history-reset.json` for the authoritative new baseline.

Pre-reset commit anchors in the older sections belong to archived original
history. The current checkpoints and fresh root below identify the replacement
history. All 450 capabilities, 41 format families and negative readiness verdicts
remain.
The owner authorized pushing this recreation; later feature pushes still require
the owner's authority under the standing project contract.

Previous Maven-qualified source: `10ea6499d874018178b43ee38a9070e81e5a0686`, with both
author and committer `imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`.
The authoritative checkpoint is `evidence/2026-10-29/maven-checkpoint.json`;
see `docs/operator/maven.md` for the native behavior and remaining limits.

Maven discovery now parses bounded G/A/V XML and merges eligible version lists,
plugin prefixes and snapshot extension/classifier mappings. Current hosted POM
references preserve versions across stale/concurrent client metadata replacement.
Groups apply current grants, digest decisions, stronger review and version-level
namespace ownership before returning any body, checksum, conditional, range or
HEAD response. Known denied collisions do not fall through to another source or
an older snapshot. Proxy catalogs must belong to the currently configured source.
Changed read snapshots retry at most three times and fail explicitly under
sustained contention; invalid XML and source-binding changes have actionable
error responses. Native metadata is a derived view; original submitted bytes
remain behind the journaled reference.

Metadata checksum uploads now have four actor/repository/path-scoped publication
receipts in the existing forced-RLS mutation table. They commit with the metadata
reference, journal and integrity-job intent. A delayed publisher sidecar can prove
its accepted original bytes after another publisher replaces the pointer. Current
download checksums always hash the exact current synthesized response. Unknown,
cross-actor and cross-repository receipts fail; a receipt-storage fault rolls back
the pointer and journal. No schema change was needed, and both frozen migration
checksums remain unchanged.

The first clean Maven candidate `ae69eb9f4f06ab8bd10ab8d3b7ee9641fdcdcdf8`
passed its earlier campaign, but further review and a negative regression exposed
proxy publication hints ordered by local POM download time. Actual HTTP reproduced
upstream latest `1.1-SNAPSHOT` becoming proxy latest `2.0.0`. The corrected source
uses producer hints/timestamps, supports an omitted version list and keeps source
precedence on equal timestamps. Both production and race stock Maven LATEST
journeys now install the producer snapshot after an older release was cached.
First failures, fixture corrections and both source candidates remain retained.

The corrected clean source passed 682 production assertions across migration,
console, native TLS initialization, inventory, sweeps, leases, worker jobs,
combined stock clients and pinned public OCI. Separate race artifacts passed
107 migration/console/installation/Maven assertions. Real PostgreSQL store/server
and native-driver race packages ran twice without skips or race reports. Unit,
vet, architecture and race checks pass. A short bounded parse/render fuzz campaign
passed 5261 executions after corpus replay; it is not the complete fuzz campaign.
Go symbol vulnerability analysis, dependency scans including browser development
dependencies and scoped source/history secret scans report no findings.

Stock Maven 3.10.0 with JDK 21.0.13+9 proves releases with transitive dependencies,
group-spanning version ranges, independent concurrent publishers, repeated unique
snapshots, independent `sources` classifiers, parent-POM inheritance/property
resolution across sources, restart and exact installed bytes. Five new real
PostgreSQL integration tests and seven parser/algorithm tests cover current
policy, actor/tenant/grant boundaries, malformed XML, metadata budgets, numeric
build ordering, plugin-prefix authority, source changes and receipt atomicity.
Concurrent publisher JVMs use independent local caches. A shared local metadata
cache caused a retained fixture failure and is not qualified. An overlapped
fixed-port native-driver run was also retained as invalid and replayed serially.

Four real Chromium tests and 19 named automated A/AA states pass on production
and race artifacts, retaining paging/search, policy, tenant fencing and schema
maintenance credential/retry checks. Full WCAG, assistive technologies, other
native browsers, PKI/credential lifecycle and remaining operator workflows stay
open. Native Maven proof uses explicit loopback HTTP; Maven TLS/native platform
qualification, Gradle/Ivy/SBT, every plugin workflow, metadata signatures,
nonunique snapshot redeployment, recursive groups and complete lifecycle/fault/
scale journeys remain required. Linux amd64/arm64 server and Windows amd64 CLI
compile only; native runtimes and Windows ACL semantics remain unqualified.

Previous migration and management-pagination checkpoints remain authoritative
within their named scope: `evidence/2026-10-29/schema-checkpoint.json` and
`evidence/2026-10-29/pagination-checkpoint.json`. Current-schema migration repeats
do no DDL; old binaries require explicit controlled legacy adoption. Transaction
admission does not drain entire transfers. Compatible-version/expand-contract
design, multi-node rolling upgrades, HA, downgrade and backup/restore remain open.

All 450 broad capabilities/journeys and 41 format families remain unfinished.
Every broad readiness verdict is negative. Continue OCI source lifecycle/removal/
delete/restore and source/locator/grant races, remaining Maven/npm/PyPI and other
format/client journeys, sampling/repair, retention/holds/GC, S3, scanners, identity,
console, migration/exit, upgrade/recovery, packaging and every later product stage.
Docker recovery is verified and its coordination hold released; owned container/
OCI/packaging work can resume without shared lifecycle changes.

Owned registry/worker/PostgreSQL listeners are stopped; private data, credentials,
keys, native fixtures, earlier history recovery and original Docker resources are
retained. Production binary bytes were restored and verified. No push or remote
mutation was executed by this turn. The read-only audit
`evidence/2026-10-29/remote-state-maven-audit.json` confirms the same private
replacement/root and all 34 published commits attributed only to imfeelingtheagi.
Shared-checkout remote tracking advanced to the prior documentation commit; this
turn did not initiate that push and does not infer its actor. New Maven source
remains local. Feature pushes, releases and publication require owner authority.

**Goal active; full product goal incomplete.** Origin remains the private
`https://github.com/ctlplne/cratectl.git`, rooted at
`887c569ac96c451bccd91ae872317c06a890117a`. Earlier records below are historical
scoped observations, not evidence of complete current readiness.

Stage 0 has architecture, threat model, conventions, licensing hold and an initial
450-row committed capability backlog across 41 protocol families. Documentary
baseline review is partial: Nexus 3.97.3 and Harbor 2.15.0 observed; current exact
JFrog/Pulp versions and exhaustive vendor cross-links still need qualification.

Named foundation candidate: `2526db96522defe83cc2fa06a0e260aab23cad7e`. Its two binary digests and the 88-assertion
clean-source native replay are retained in `evidence/2026-10-28/foundation-checkpoint.json`.
All three readiness verdicts remain negative.

Stage 1 now has a runnable Go service, CLI, forced PostgreSQL RLS, restricted
runtime role, tenant tokens, durable filesystem publication, hash-chained events,
transactional idempotency/outbox intent and current-policy serving checks. Native
hosted proof journeys ran with npm, twine/pip, ORAS and Maven. These prove the
listed operations only. Initial broad format rows stay implementing/unverified.

Observed and repaired: same-length stored-object corruption was served; scoped
npm attachment names were rejected; driver transitive x/text had two reachable
vulnerabilities. A stricter native OCI intake test then exposed a quarantine
publication defect, repaired with one shared graph-policy reader. First failures and replays are retained in the defect ledger.

Foundation combined working-tree conformance: 88 assertions, including native package
dependencies, restart, manual quarantine, immutable races, HTTP range/ETag,
idempotency, token expiry/revocation, OCI interrupted upload offsets, quarantined
graph intake and denial propagation to manifests/tags/inventory. Unit/vet/race, real PostgreSQL
RLS/graph integration (also race-instrumented) and two short fuzz campaigns pass. Govulncheck rescan and Trivy
source scan report no findings; Gitleaks sanitized-current-source scan is clean.
History findings were all verified public fix-commit URLs; a rule-scoped exception
passes positive/negative fixtures. This is not the full security campaign: artifact/image scanning, every
parser, all authorization races and independent review remain required.

Generic/Maven raw proxy and group paths now have early native proof with fenced
retrieval, source checksums, actor grants, namespace ownership and bounded stale
policy. Tenant-scoped credentials are bound to their approved URL and auth scheme;
an operator private-network ceiling applies independently of repository CIDRs.
Named proxy candidate: `7f0ce80f9fc8b5f55200495331f9f1a61ba521cc`. The clean-source combined
run passed 127 assertions; exact binary digests, client versions and limits are in
`evidence/2026-10-28/proxy-checkpoint.json`.
New retrieval/grant tables force RLS, with race-instrumented real-PostgreSQL fence
checks. The initial credential-scope defect and a connection-pool fixture defect
are preserved with replay evidence. Source/vulnerability/secret checks report no
findings for the current implementation.

Full proxy/group semantics, S3 production path, console, scanner, identity federation,
replication, migration, full governance, lifecycle/GC/recovery, distribution,
remaining formats, production packaging and performance/HA campaigns remain incomplete.

Prior npm intake source candidate: `a848b9d7e3bc12b99d5269ed4e7669bf7e055e2c`.
The strict clean-build replay passed 146 assertions, including embedded source
identity checks, across stock npm/twine/pip/ORAS/Maven and raw proxy/group paths.
Exact binary digests, build metadata, database feed age and limits are retained in
`evidence/2026-10-28/npm-checkpoint.json`. Earlier checkpoints predate embedded
binary identity enforcement; this strict replay supplies that qualification.

Manual decisions now cover current and future aliases of a repository digest.
Hosted npm has durable tag revisions/tombstones, semantic versions, exact-version
and tag resolution, complete metadata snapshots and configurable safety budgets.
Bounded gzip/tar inspection checks coordinate identity, paths, links and integrity
without extraction or execution; package dependencies come from the archived
package.json. npm latest/prerelease installation, tag mutation, invalid archives,
restart and denial are retained in the native replay.

Unit/vet/race and two repeated real-PostgreSQL race runs passed. Short archive and
coordinate fuzz campaigns ran 66654 and 99445 executions respectively. Go
vulnerability, Trivy sanitized source and Gitleaks current/history scans report no
findings within their recorded scope. The digest alias, JSONB-query, stale binary
identity and OpenAPI documentation defects have retained failures and replays.
This does not complete the full security or parser campaign.

Latest npm proxy/group source candidate: `6b5da7702ffa9357aac61bec40110e355843430b`.
Its strict clean-build combined replay passed 182 assertions on real native
PostgreSQL 16.15. Binary identities, client versions, limits and source/security
checks are retained in `evidence/2026-10-28/npm-proxy-checkpoint.json`.
The npm proxy/group subset has durable source/SRI bindings, separate approved
credentialed download origins, cache refresh, version/tag union, namespace
ownership, denied collision tombstones, quarantined intake and current grants.
Stock npm exercised dependencies, normalized executable metadata, restart, retained
lockfile URLs, fresh-cache denial, invalid integrity and forged dependency graphs.
Full npm behavior, deprecation, signatures, lifecycle and all fault cases remain open.

Two real-PostgreSQL race runs and the unit/vet/race gates passed. Short SRI and
catalog fuzz campaigns ran 418210 and 39462 executions. Native Gitleaks 8.30.1,
Go vulnerability and retained-database Trivy source checks report no findings in
their recorded scope. Full security and packaging gates remain incomplete.

Docker currently fails OCI task creation even for a disposable owned probe. The
original `cratectl-dev-postgres` container is stopped; its named volume is intact.
No global Docker service was restarted. Checksum-verified PostgreSQL 16.15 was
built into `.cache/postgresql-16.15-install`; a separate retained cluster lives
under `.private/cratectl-native-postgres`. It is stopped at handoff. Use
`CRATECTL_DEV_DATABASE=native python3 scripts/dev.py init` to resume that profile;
see `docs/operator/native-development-database.md`. This is a fresh native test
dataset, not restoration of the container data or Linux/container qualification.

Latest Python/source-store candidate: `f2c363d4e9fafb54f551002076e269982f40a3c1`.
The strict clean-build combined native replay passed 210 assertions on real native
PostgreSQL 16.15; exact binary identities and limits are retained in
`evidence/2026-10-28/python-checkpoint.json`.

PyPI hosted/proxy/group paths now have archive-derived identity, modern HTML/JSON
indexes, source/hash-pinned URLs, parent-governed metadata sidecars, Requires-Python,
versioned yanks, namespace/filename precedence, quarantine and current grants.
Stock pip verified dependencies, hash-locked restart, yanked exact pins, ordinary
yank avoidance, incompatible-Python exclusion, group denial and a benign PEP 517
source build confined to an owned consumer. The registry never ran that backend.
A common forced-RLS source table preserves old npm binding keys during migration.

The original Python identity failure and HTML tokenizer defect are repaired and
replayed. Unit/vet/race and two repeated real-PostgreSQL race runs passed. Initial
archive fuzzing reached only 12 executions; the retained follow-up reached 76732.
Index fuzzing reached 86291. Go vulnerability (238 records), retained-database Trivy
source and native Gitleaks checks report no findings in their recorded scope.
Full standards, root enumeration, uv/legacy formats, dynamic metadata, parser/fault,
security and production qualification remain open. All 450 broad rows remain open.
Native PostgreSQL is stopped at handoff; both retained database datasets remain.

Latest OCI graph source candidate: `68297a128123820642d058529476c7037a3be175`.
The strict clean-build combined native replay passed 226 assertions on native
PostgreSQL 16.15. Binary identities, primary specification references and limits
are retained in `evidence/2026-10-28/oci-graph-checkpoint.json` and ADR 0007.

OCI hosted intake now validates exact manifest/index structure, embedded data and
descriptor identities. Durable graph and current-policy checks share the root/tag
publication transaction. Native ORAS attached, discovered, filtered and pulled
exact evidence bytes, created an index, handled image names containing protocol
words and replayed restart/denial. Weak subject associations accept out-of-order
publication; known and late subject policy still governs reads. The serving guard
rechecks mutable tags after byte verification. Unvalidated development manifests
fail closed until an authorized same-byte re-import.

The missing-config first failure and three harness corrections are retained.
Unit/vet/race and two repeated real-PostgreSQL/server race runs passed. The short
manifest fuzz run reached 126351 executions. Go vulnerability (238 records),
retained-database Trivy source and native Gitleaks checks report no findings in
their recorded scope. Full OCI proxy/group, token challenges, multi-platform and
Docker/Podman/Helm clients, signatures, lifecycle, parser/fault and production
campaigns remain open. All 450 broad capability rows remain open.
Native PostgreSQL is stopped at handoff; both database datasets remain retained.

The outbox records pending intent; there is not yet a working fair job processor.
The native tests use one host and do not qualify independent-machine consumption.

Next: resume the owned database and finish Stage 1
OCI proxy/group graph retrieval using the shared validated intake contract, token
challenges and remaining npm/PyPI cases, Maven metadata
merging, policy races, fair durable workers, recovery and blank-install/console journeys; expand the adapter
contracts only after those journeys pass. Full work remains in GOAL.md and
`docs/qualification/remaining.json`; no owner scope has been removed.

Host: macOS 27.2 arm64, project Go 1.27.3; npm 11.16.0, Node 26.0.0,
Python 3.14.6, twine 7.0.0, pip 26.1.2, ORAS 1.3.6, Maven 3.10.0 with
Temurin JDK 21.0.13. Docker Desktop 4.94.0 / Engine 29.8.2, Linux arm64 VM.
An escalated read-only probe confirms 10 CPU cores and 64 GiB host RAM, with
about 133 GiB free disk. The test topology is still the small profile, not an
isolated standard/large benchmark or independent-host HA campaign.

Owned resource (stopped at handoff; retained data): `cratectl-dev-postgres`, loopback 35432, retained volume
`cratectl-dev-postgres-data`, 512 MiB / 2 CPU limit, PostgreSQL 16.15-alpine.
Conformance server processes and client containers terminate after each run.
Private credentials/fixtures remain under ignored `.private/` (0700). Local
native client/toolchain/scanner downloads remain under ignored `.cache/`.
Nothing in sibling workspaces or services was changed.

An attempted credential-bearing Maven container test was rejected by automatic
approval review. It was replaced with checksum-verified native macOS Maven/JDK;
no credential was sent to that container, and native Maven qualification ran.
