# cratectl execution status

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

Every earlier commit/checkpoint reference below is historical evidence from the
archived original history. It does not identify the new history's current source.
All 450 capabilities, 41 format families and negative readiness verdicts remain.
The owner authorized pushing this recreation; later feature pushes still require
the owner's authority under the standing project contract.

Latest source candidate: `17182b6aa6bae022f5f18a4d3842fb90ee82479a`, committed locally as
`imfeelingtheagi` for author and committer. Clean qualification passed 71 new
worker assertions, 274 existing native-client assertions and 33 real-provider
assertions against the same exact binaries. See
`evidence/2026-10-28/worker-checkpoint.json`. Review range remains `887c569..main`;
this worker source and checkpoint remain local.

A dedicated native worker now executes source-event indexing and stored-byte
SHA-256 integrity checks. Publications record exact-byte work atomically with
references/journal/idempotency. Persisted tenant lane budgets bound admission,
running concurrency, attempts and backoff. Independent lane slots and local
round robin prevent the tested hash backlog from starving event indexing or the
second tenant. Dedicated worker credentials cannot use the public API; each
worker operation rechecks purpose, revocation and current expiry under forced RLS.

Lease generations/tokens fence stale owners. Actual process kills and restart
recover work without observations from the killed attempt. Cancellation and
idempotent redrive retain honest state and attempt history. Integrity checks
stream bounded paced reads; observations never approve quarantine or bypass
serving policy. Native proof covers same-length corruption, bounded retry,
repair, current denial, credential rollover and registry restart.

Repaired and retained: source-sequence activity pagination lost late projections;
transaction-start authentication let a waiting claim outlive expiry; queue
rejection could leave a source fill fetching. Completion positions, current-clock
authentication and audited fence-specific abandonment pass their regressions and
native source-capacity recovery. An initial fixture incorrectly treated tenant-
local job IDs as globally unique; no tenant leak was established by that failure.

Two repeated clean PostgreSQL/store/server/native-process race suites pass.
The separately identified race-instrumented registry/worker build also passes all
71 worker assertions with no Go race reports; production binaries were restored.
Canonical job selector fuzzing ran 103502 executions. Unit/vet/race,
Govulncheck (238 records), scoped Trivy and Gitleaks source/history/review
pass. Exact native registry/worker binaries also pass the earlier npm/Python/OCI/
Maven/generic and pinned Docker Hub/token/CloudFront journeys. Full security and
production packaging remain incomplete.

Last verified GitHub main remains `b13550a` with author/committer
`imfeelingtheagi`. The prior remote-state correction remains authoritative.
No new push was made; feature pushes require owner authority. See
`evidence/2026-10-28/remote-state-audit.json`.

All 450 broad capabilities and 41 families remain open. Worker scanners/external
adapters, orphan/CAS and retrieval/upload reconciliation, retention, multi-host/
mixed-load fairness, S3, source lifecycle/delete/restore, remaining format
semantics, operator install/console, recovery and every later product stage remain
required. A complete historical storage-integrity sweep is also required.
Owned registry/worker/fixture and native PostgreSQL processes are
stopped; private datasets, repaired owned fixtures, original container/volume and
history recovery are retained.

**Goal active; full product goal incomplete.** No design-partner, ordinary-operator
or enterprise readiness verdict is positive. Original-history starting commit
`fa727a9` is retained only in private recovery; current local review range is
`887c569..main`. Origin is the recreated private `https://github.com/ctlplne/cratectl.git`.
Pushes, public visibility, releases and publication remain unauthorized.

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
