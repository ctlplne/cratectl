# GitHub Actions qualification plan

Updated: 2026-11-04. Owner: `imfeelingtheagi`. The complete `GOAL.md`, all
450 capabilities / 41 families and all later stages remain committed scope.
This plan places work on suitable hosts and describes how to accept evidence.
It does not turn an unfinished feature or absent test into a pass.

The public repository and CI pushes/repairs are owner-authorized. Work and
commits stay on `main`, with both author and committer exactly
`imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`.
Release, package/image publication and customer/primary/sibling changes remain
outside this CI authority. No autonomous delegation.

## Current qualification state

Exact `0edd1a4` passes all 21 actually selected jobs: main9/JVM8/OCI2/
upgrades2. All 15 accepted safe summaries bind exact source/native binaries,
actual tools, fixture bytes and artifact identities. Both baselines pass663,
real PostgreSQL normal/race/five snapshot regressions and four Maven warm-cache
stages/six bindings. Full x86 Chromium passes119/all15workflows without skipped,
flaky or unexpected results. All three native source and fuzz jobs pass,
including macOS ARM. See the [whole observed checkpoint](../../evidence/2026-11-04/github-0edd1a4-checkpoint.json).
Library/focused-browser workflows were not selected on this source; earlier
[1974 library proof](../../evidence/2026-11-04/nuget-1974d94-checkpoint.json)
remains separate with both actual SDK10.0.403/runtime10.0.14 contracts passing
all37original assertions. Whole observed success does not qualify the full goal.

The accepted JVM campaign includes Ivy666/cache-v4/ten stages/34wire plus six
retained-cache bindings per host, Gradle199/eight/24 and four SBT release
profiles161/seven/12. Both OCI214 and both upgrade10pins/15reports pass.
Ivy retains the same changing consumer/cache/module through initial/update/
restart, exact changed POM/JAR bytes and the first observations before overwrite.
Warm proxy snapshot/offline/fault and broader lifecycle requirements remain open.

At later exact `0cff4b8`, SBT snapshot-v2 passes all four series/architecture jobs:
SBT1.13.0 and2.0.11 each pass269checks/eight stages/eight snapshot cases/18bindings
on native Linux x86 and ARM. Every original release case remains. These commands
use fresh project caches copied from frozen tool-only seeds; warm project caches
are unqualified. See the [named checkpoint](../../evidence/2026-11-04/sbt-snapshots-0cff4b8-checkpoint.json).
The whole campaign is incomplete:19jobs pass and two macOS jobs remain queued.
No duplicate dispatch, retry or skipped-job acceptance. All actual JVM/SDK/
PostgreSQL campaigns run on GitHub; local tests use small owned stand-ins.

All original first failures/capacity cancellations remain retained. The c030
Maven fixture's missing re import now has both663native replays. Original9b
browser timeout and d405dotnet401causes remain unknown; later passes cannot
recover missing original private detail. Owner-encrypted failure diagnostics
remain bounded and have no plaintext fallback. The baseline failure collector
currently covers OCI/extendedJVM/browser profiles, so c030baseline traceback
identity came from privately retained job logs, with only fixed markers public.

The next setup revision bounds the two remaining ORAS/Helm curl invocations
and caches their exact public compressed archives on GitHub. Original versions,
pins, checksum/extraction and client/database commands remain. Every existing
or restored archive must pass bounded regular-file/SHA256 validation; a corrupt
cache fails intact. Child kernel file caps are32/64MiB, curl bounds15seconds
connect/180total/five HTTPS redirects, and the common owned-process deadline
is195seconds with64KiB output. Ten local stand-in/real-kernel/deadline/privacy
tests and full lint pass. See the [development record](../../evidence/2026-11-04/native-tool-archive-cache-development.json).

Three immutable-action cache steps cover six existing jobs: main/upgrades ORAS
and OCI Helm, each on both native architectures. Each stores one exact public
archive, with OS/architecture/installer-source keys and no prefix restore. All
normal verification/client commands execute on hits. The cache step has a
five-minute budget and two-minute segment bound; original job/client budgets,
permissions, cases and concurrency remain. The reviewed
[cache action](https://github.com/actions/cache/blob/55cc8345863c7cc4c66a329aec7e433d2d1c52a9/action.yml)
saves only after job success. Whole ignored directories, private credentials,
databases, extracted tools and consumer caches are outside these paths.
At exact f91, both actual native OCI214 journeys pass and fixed Helm keys
show miss, bounded pinned download and post-success save. See the
[named checkpoint](../../evidence/2026-11-04/helm-cache-f91f19a-checkpoint.json).
Matching cache-hit, ORAS and whole-campaign acceptance remain separate;
no timing benefit is inferred. The f91 revision selects21actual jobs, currently queued/pending. Enumerate the
actual full SHA and retain placement/step evidence before native acceptance.
Other JVM/tool-cache opportunities remain separate required placement reviews.

Go hosted/group-v2 is implemented but unverified. Its two native Linux jobs
require four real PostgreSQL functions normally and with race, then an owned
trusted-TLS installation, CLI publication and stock Go transitive downloads.
Every original hosted case remains. The profile requires nine ordered stages,
24 publisher/reference/HTTP bindings and16exact cached ZIP/mod bindings.
Groups preserve first-source ownership, stronger whole-bundle review, escaped
namespace pins, source grants and terminal denial/partial-version behavior.
The [group development record](../../evidence/2026-11-04/go-module-groups-development.json)
records source hashes and local checks. Go proxy retrieval remains rejected;
legacy/alias/warm-cache/lifecycle/fault/migration/scale/platform/browser outcomes
remain separate committed work. Original45minute jobs and120second/8MiB
commands remain; no retries, skipped-job acceptance or successful-empty export.

Original exact e62 fails both Go jobs at two event-baseline assertions: the
fixture expected one total event after provisioning had already recorded one.
The race and client steps did not execute. Both safe summaries contain zero
records and the exporter correctly rejects them as empty. Actual job/artifact
identities and fixed private-log hashes remain in the
[first failure](../../evidence/2026-11-04/go-module-e62ac69-first-failure.json).
The d183 repair compares with the actual journal baseline and confines deliberate
reference damage to the fresh fixture DB owner. Runtime DELETE/BYPASSRLS grants
remain absent. Repaired-source native replay is still required; no pass inferred.

Four owned file-proxy stand-ins pass with actual Go1.27.3 on this ARM Mac:
exact transitive modules, cached ZIP/mod bytes and info version/time. They run
through `make lint` on all three native source hosts, assigning x86 execution
to GitHub. This qualifies fixture compatibility, without HTTP/TLS/registry/PG.
Local unit/race/lint/console reproduction and four database-test compilations
pass; database and registry outcomes remain unverified.

Go commands retain mode0600 streams through deadline/output limits. The workflow
seals selected failures or the last pre-cleanup observation and registry logs to
the unchanged owner-held CMS recipient; NETRC/config/token files are excluded.
Seven real CMS and four helper tests pass. Actual failed-job upload/decryption
integration remains unverified; a failure before a report exists still requires
separate job observations. See the
[fixture/diagnostic record](../../evidence/2026-11-04/go-module-fixture-diagnostics-development.json).

The workflow union is28jobs across seven workflows. Enumerate actual paths and
full-SHA selections for every source. NuGet library selection includes shared ZIP
inspection and module dependency pins. Native private clients use ordinary TLS,
private NETRC/cache directories and one explicit source without VCS/direct/public
package fallback. Fixture GONOSUMDB policy is explicit; public checksum mirroring
and offline behavior remain separate. Existing formats, commands, cases and
budgets remain intact.

The following campaign notes are historical.

Owner resumed the full goal on 2026-11-04. The latest fully accepted whole
observed campaign remains `708214f`: all 17 jobs and eleven safe summaries.
Exact `42f9366` completes with 15 successes and two unexecuted macOS source/fuzz
cancellations. GitHub explicitly reports runner acquisition failure and macOS
ARM capacity constraints; no runner or test step ran. Preserve the
[original cancellations](../../evidence/2026-11-04/github-42f9366-macos-capacity-cancellation.json)
and the [partial checkpoint](../../evidence/2026-11-04/github-42f9366-checkpoint.json).
The main run fails overall; no canceled or absent result is a pass. All named
Linux PostgreSQL/race, 645-client/56-HTTP-restart, x86 Chromium 15, OCI 214,
15-upgrade-report/ten-pin and 324 scoped-security cases pass on that source.

The expanded Ivy profile passes 494 checks/eight stages/eight metadata cases/
28 publisher-reference-HTTP identities and three SHA-2 consumers on each native
architecture. Gradle passes 199/eight stages/24 identities. All four profiles
also replay on [72b98be](../../evidence/2026-11-04/jvm-72b98be-checkpoint.json),
including the bounded process/input/output helper; full baseline replay remains
separate. Original Ant/checksum failures and each exact source remain retained.

All four SBT profiles now pass on exact `d4056d9`: versions 1.13.0 and
2.0.11 on each native Linux architecture, 161 checks/seven stages/twelve byte
bindings each. [All eight JVM jobs](../../evidence/2026-11-04/jvm-d4056d9-checkpoint.json)
pass their named scope. The [SBT checkpoint](../../evidence/2026-11-04/sbt-d4056d9-checkpoint.json)
preserves both original failures and their repair. Official tool/metaproject
sources stay separate from the sole package source. The resource-only project
uses Java-only mode and verifies both resolver tasks and its effective dependency
graph before every command, including expected denials. No fallback or case was
removed. Compiled Scala application workflows and broader SBT scope remain open.

The next candidate adds hosted Maven nonunique snapshot policy/discovery and
Ivy `maven-snapshots-v3`, preserving every earlier release/metadata case. It
requires nine stages/eight snapshot cases/34 producer-reference-HTTP identities,
real PostgreSQL integration/race and expanded Chromium source administration.
Local checks pass; native replay remains unverified. First-snapshot hashes are
observed before replacement. Read the [development record](../../evidence/2026-11-04/maven-nonunique-snapshot-development.json)
for exact tests, source hashes, bounds and remaining warm-cache/fault/lifecycle
work. This change selects main9/JVM8/OCI2/upgrades2/focused3 (24 expected jobs);
no NuGet library path changed. Enumerate the actual full-SHA runs after push.

All broad readiness verdicts, complete security and packaging remain negative.
`make security` and `make packaging` continue to fail with their unfinished
scope. The [remaining record](remaining.json), [parity](parity.json) and
[journeys](journeys.json) are the backlog, not a list of inferred passes.

## Existing job placement

| Workflow / jobs | Actual environment | Required work and current limits |
| --- | --- | --- |
| `ci.yml`: source / 3 | Ubuntu 24.04 amd64 and arm64; macOS 15 arm64 | Build, Go unit/race/vet, architecture/API and Python contracts, console reproduction and npm audit. 30-minute job budget. Source checks do not qualify a full macOS server/package journey. |
| `ci.yml`: fuzz / 3 | Same three native hosts | Every checked-in Go fuzz target, bounded five-second smoke per target; 25-minute job. Retain target inventory and failures. This is not a long parser campaign. |
| `ci.yml`: scoped security / 1 | Ubuntu x86 | Pinned source/binary analysis, full reachable Git history secret scan and synthetic rule regressions. 30-minute job. Current324-case named proof is separate from full security/feed/image coverage. |
| `ci.yml`: PostgreSQL and stock clients / 2 | Both native Linux architectures; real PostgreSQL16.15 | Integration/race, bounded timing, durable jobs/leases, integrity and baseline client/recovery journeys; 120-minute job. Full Chromium suite only on x86. ARM browser placement is skipped and never counted as passing. |
| `jvm-clients.yml`: Gradle / 2 | Both native Linux architectures; real PostgreSQL | Gradle9.8.2, exact JDK21 build, eight stages and24 publisher/reference/raw-HTTP digests. 60-minute job. Named v2 profile passes; broader JVM remains open. |
| `jvm-clients.yml`: Ant/Ivy / 2 | Both native Linux architectures; real PostgreSQL | Ant1.10.18/Ivy2.6.0 and exact JDK. Cache-v4 passes666checks/10stages/34wire+6cachebindings on both hosts at0edd, retaining all release/metadata/snapshot/SHA-2 cases. 60-minute job. Broader Ivy remains open. |
| `jvm-clients.yml`: SBT / 4 | SBT1.13.0 and2.0.11, each on native Linux amd64/arm64; real PostgreSQL | Snapshot-v2 passes269checks/8stages/8snapshotcases/18bindings on all4cases at0cff, retaining every release case. Frozen tool-only boot cache/fresh project caches. Five-minute bootstrap, two-minute commands, 60-minute job. |
| `go-modules.yml`: hosted / 2 | Native Linux amd64/arm64; pinned Go, real PostgreSQL16.15, trusted loopback TLS | Four database regressions normal/race; CLI publication, stock hosted/group transitive downloads and current-policy/source/tenant/restart/revocation cases. Implemented but unverified. 45-minute job. |
| `nuget-contract.yml`: libraries / 2 | Both native Linux architectures; exact SDK10.0.403 selection | Original37assertions/unchanged dense corpora pass both at1974, actual runtime10.0.14 and separate DLLhashes. 20-minute job. Does not replace actual NuGet HTTP/restore/restart proof. |
| `oci-clients.yml`: native clients / 2 | Both native Linux architectures; Docker, Podman, Helm, real PostgreSQL | Actual publication/consumption and policy/tenant/recovery cases with inert owned data; 45-minute job. Do not execute the uploaded image. External-provider interoperability is separate. |
| `browser-repair.yml`: focused / 3 on relevant pushes | Native x86 Chromium; five fresh PostgreSQL databases per selected journey | Repair, retention and NuGet each repeat five complete journeys; 45-minute job. Manual dispatch selects one. Stop on failure; no retries/skips count as acceptance. |
| `upgrade-qualification.yml`: controlled upgrades / 2 | Both native Linux architectures; fresh PostgreSQL | Rebuild ten immutable historical pins and require15 reports each; 120-minute job. Relevant pushes, manual dispatch and Monday08:17UTC. Not rolling upgrade, downgrade or backup/restore proof. |

The union is 26 jobs when every relevant workflow triggers. A normal push can
trigger fewer jobs because paths differ. Always enumerate actual runs for the
full source SHA; never assume 26, treat a missing lane as passing, or substitute
an old run. Library jobs run only when their own paths select; a workflow omitted by its
path filter is not evidence for that source. No duplicate dispatch merely to recover visibility.

Workflow files define exact triggers, permissions, matrices and commands. Use
read-only tokens, checkout without persisted credentials, fail-fast=false for
independent matrix results, and no continue-on-error. No publication step is
implicitly authorized by this plan.

CI now gives source, fuzz and PostgreSQL jobs independent per-architecture
concurrency groups, with a separate security group. A queued macOS lane cannot
hold unrelated Linux lanes behind one workflow-wide mutex. Running main jobs
remain preserved; PR work can supersede the same lane. GitHub's default single
pending slot still applies within each lane, so retain any superseded pending
job as unexecuted. Every job, matrix case, command and timeout is unchanged.
Main cross-run independence is now observed: newer0efa Linux source completes
and its security job progresses while older1e9macOS is still unassigned. Seven
newer pending cases were canceled before execution and never count as passes.
See the [native observation](../../evidence/2026-11-04/ci-independent-lanes-native-observation.json).
This proves the observed scheduling separation, not a timing improvement,
every queue cause or a whole-candidate pass. Runner capacity remains separate.
See the [development record](../../evidence/2026-11-04/ci-independent-lanes-development.json)
and GitHub's [job concurrency contract](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).

## Resource and evidence contract

- Use actual native hosts for OS/architecture claims. This ARM Mac runs source
  checks and small Python/HTTP stand-ins; x86, real JVM/client/PostgreSQL and
  managed browser qualification runs on GitHub. No emulation-based pass.
- Each disposable environment owns `cratectl-*` resources, loopback38443/35432,
  a private generated credential directory and restricted PostgreSQL runtime:
  nonsuperuser, nonowner, no BYPASSRLS. No primary or sibling service changes.
- Pin client distributions and verify their bytes before executing them.
  Executable JVM pins live in `jvm-clients.json`; narrative state lives in
  `jvm-client-plan.json`. Prose/checkpoint edits alone must not restart a client
  lane. Keep owned package payloads inert; run only owned fixture build rules
  and reviewed tool binaries, never uploaded package scripts/classes/models.
- Preserve started main-branch jobs across repair pushes. All six project
  workflows now use job/profile/platform groups, including SBT series and
  focused browser journey. Each group has the default one pending tip. A newer pending
  tip can replace an older pending tip; PR work may still be superseded.
  Pending cancellation supplies no evidence. See
  [GitHub's concurrency contract](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).
  Semantic comparison of the five newly changed workflows proves only concurrency
  differs: all triggers, cases, commands, permissions, budgets and failure handling
  stay equal. Main scheduling has native evidence; the other groups still need
  their own observation. See the [development record](../../evidence/2026-11-04/ci-family-independent-lanes-development.json).
  Editing all five paths selects all26union cases; enumerate the actual source
  inventory, including the two actual NuGet library jobs.
- The owned JVM command helper has a two-minute deadline,8MiB output failure
  threshold and64KiB captured tail. The baseline-helper revision on `72b98be`
  routes `conformance.run` through the same path, drains output through a
  nonblocking pipe, bounds private UTF8 input to1MiB and preserves complete
  structured results up to8MiB. Local stand-ins and native JVM
  profiles pass; full baseline replay is still pending on that revision. See the
  [development record](../../evidence/2026-11-04/baseline-client-bounds-development.json).
  SBT configures four concurrent downloads, two reported processors and a 768MiB
  heap/384MiB metaspace. Its cold official-tool bootstrap has a separate
  five-minute deadline; project commands retain two minutes. Boot/tool caches
  are bounded to20,000files/768MiB each and reject project coordinates before
  being copied; command caches are removed after their proof bytes are copied.
  Gradle uses two workers; the direct Ant JVM declares512MiB
  heap/384MiB metaspace and two processors. Owned process-group cleanup covers
  children remaining in that group. Explicitly detached sessions remain an
  open containment limit. Other direct library/build probes, HTTP response
  helpers and orchestration output/fork bounds still require review. Timeouts
  leave remote mutation outcomes unconfirmed.
- Bind source SHA, clean state, embedded binary revision/OS/architecture,
  actual tool and fixture bytes, mandatory stages and independent HTTP effects.
  A publisher-generated hash alone is not wire proof. Historical upgrade
  binaries retain their own reviewed source identities; do not relabel them.
- Upload only reviewed bounded counts, hashes, fixed diagnostics and stages.
  Raw command/browser/SQL reports, private paths and credentials stay private
  on disposable runners. Browser failure exports use a separate reviewed safe
  schema. Keep unchanged summaries under `evidence/`, plus artifact ID/digest
  and checkpoint limits. Safe summary retention is30days; durable accepted
  summaries must survive expiry in Git. JVM/OCI failures may retain only
  bounded owner-recipient CMS ciphertext and fixed metadata for7days. The
  decryption key never visits CI; there is no plaintext fallback. The collector
  excludes credential/config fields and selects at most two actual failed
  commands, or the last observation after an assertion. Candidate/source,
  generated-report inventory, owned paths and byte budgets are checked before
  encryption. No broad raw-artifact upload fallback.
- Preserve first failures. Re-poll a confirmed live handle after an observation
  timeout; do not restart from elapsed time. Repair from actual evidence, keep
  every original case and replay it on the new exact source. Partial, skipped,
  canceled, stale, missing or unverified stages never count as passes.

## Remaining offload inventory and order

| Work still required | Placement / acceptance evidence |
| --- | --- |
| Ant/Ivy and SBT client breadth | Ivy cache-v4 and all4SBTrelease cases now pass. Qualify new SBTsnapshot-v2, then remaining warm-cache/classifier/parent/BOM/compiledScala/metadata/interruption/outage/lifecycle/JVM combinations. The [JVM plan](jvm-client-plan.json) preserves exact cases and bootstrap/cache limits. |
| Every later format and native client | Native Linux architectures and stock ecosystem tools as each adapter is implemented; real restricted PostgreSQL and nontrivial dependency graphs. Hosted/proxy/group, exact bytes, permissions, policy, concurrency, interruption, restart, freshness, lifecycle and migration remain separate required cases. |
| Real third-party OCI/upstream interoperability | Explicitly authorized project-owned repositories/realm/registry services with pinned tools and inert data. Keep changing external services separate from deterministic PR gates; no publication authority is assumed. |
| TLS, private trust and identity | Disposable real compatible IdPs/PKI and native clients, scoped tenants, rotation/expiry/revocation, failure and recovery. Stand-ins do not qualify every vendor or customer CA. |
| S3 and storage semantics | Pinned real compatible object services, multipart/versioning/retention, integrity, faults, quotas, tenant isolation, recovery and byte inventories. A filesystem pass does not qualify S3. |
| Scanner, dependency, image and artifact analysis | Pinned engines and legally usable corpora, explicit feed identity/age/license and unavailable/stale behavior, source/binary/image coverage, false positives/negatives and reachability. Missing intelligence is never clean. |
| Packaging, Compose/Helm and offline bundles | Build once, hash exact artifacts and install on disposable native targets with persistent data, trust, upgrade/recovery and actual network isolation. Rendering a chart or finding a download link is not install/offline proof. |
| Native Windows and additional macOS runtimes | Published native runners, actual supported CLI/package/server journeys and Windows private-file ACL behavior. Cross-builds and Linux containers are separate evidence. |
| Release SBOM/signatures/provenance | Named SPDX/CycloneDX/build manifests, scoped identities/trust and independent offline verification of exact shipped bytes. Requires separate distribution/signing authority; no automatic release. |
| Replication, migration, federation, backup/restore and faults | Real compatible sources/destinations, bounded inventories, durable checkpoints and controlled process/network/storage faults. Preserve identities, metadata, policy and bytes; one-host smoke does not qualify multi-host recovery or cutover. |
| Longer parser/differential campaigns | Scheduled/manual native jobs, reviewed seed/corpus identity, explicit CPU/time/memory/concurrency budgets, minimized failures and replay. Five-second smoke remains visibly separate. |
| Standard/large profiles,24-hour soak and operating cost | Sized independent hosts and declared real database/object/network topology. Shared runners do not prove the required8vCPU/32GiB/1million-record profile,10million-record/1000tenant large profile or24-hour soak. Retain unfavorable measurements. |
| Paid comparisons and customer acceptance | Authorized licensed incumbent systems and explicit environment access. These external inputs do not block independent implementation or authorize customer changes. |

Each implementation must update its workflow placement, fixtures, safe evidence
schema, operator documentation and capability/journey limits together. Prefer
focused stand-ins locally and actual native clients/services in CI. Do not drop
an original case, silently widen a budget or redefine the product scope to
obtain a pass. Final readiness still requires every applicable GOAL requirement
and final gate on a named candidate, with no mandatory unresolved gap.

Historical versions, defects, accepted samples and earlier plans are retained
in [the history](github-actions-history.md) and immutable evidence. They explain
how the current plan developed; they do not supersede the full owner goal.


Runner acquisition is an independent gate. Keep a canceled source/fuzz result,
its exact source/job/labels and platform annotations; distinguish no execution
from an executed assertion failure. Continue independent native Linux/client
work while macOS capacity is unavailable. Preserve live handles and started
main runs; no timeout, queue replacement, earlier source or emulated run fills
a missing native result. The new SBT matrix brings the fully selected six
project workflows to 26 jobs; a source change selecting main/JVM/OCI/upgrades
runs 21. This SBT change also touches the common safe exporter, so it selects
the three focused browser jobs: 24 expected in total. Exact selected jobs are
always recorded per candidate.
