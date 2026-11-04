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

Exact `636dea9` has 25 successful jobs out of 26, with 20 accepted safe
summaries. GitHub reports that the macOS ARM source runner was not acquired
and identifies capacity constraints; that job is unexecuted. Both Linux source
jobs, all three native fuzz jobs and scoped security pass. Both native real
PostgreSQL integration/timing/race suites pass, including all five immutable/
opt-in/tenant/queue/concurrent snapshot regressions. Both 647-check baseline
campaigns pass, including the joined-key probe and 56 SDK HTTP cases before/
after restart. Full x86 Chromium passes 119 checks/all 15 workflows with zero
unexpected/skipped/flaky results; each focused journey separately passes five
fresh-database repetitions. See the [partial checkpoint](../../evidence/2026-11-04/github-636dea9-checkpoint.json).
Latest fully accepted whole observed campaign remains `708214f`.

All eight native JVM jobs pass on that exact source: Ivy 654/nine stages/34 byte
bindings, Gradle 199/eight/24, and four SBT 161/seven/12 profiles. Both OCI jobs
pass 214 checks; both upgrade jobs rebuild ten historical pins and pass 15
reports. See the [JVM checkpoint](../../evidence/2026-11-04/jvm-636dea9-checkpoint.json).
These named results do not close broader client, fault, lifecycle or goal scope.

The library pair also passes its original 37 assertions and unchanged corpora
with zero mismatches. Actual x86 SDK/runtime are 10.0.402/10.0.13 and ARM
10.0.403/10.0.14, with separately retained NuGet 7.9.0.0 DLL hashes. The native
HTTP baselines independently used SDK 10.0.403 on both hosts. Never relabel the
library x86 result as 10.0.403; see its [checkpoint](../../evidence/2026-11-04/nuget-636dea9-checkpoint.json).

The next revision makes SDK selection reproducible through root `global.json`:
10.0.403, rollForward=disable, allowPrerelease=false. Both native feed jobs and
both library jobs use `actions/setup-dotnet@v6` with that file; both harnesses
require the actual SDK to equal the pin before running their original cases.
The library path filter includes the pin and its shared validator. Runtime
patch/DLL hashes remain actual observations; no implicit package restore, cache,
authentication or publication step is added. See the official
[setup action](https://github.com/actions/setup-dotnet) and
[SDK selection contract](https://learn.microsoft.com/en-us/dotnet/core/tools/global-json).
Four contract tests, full lint and semantic workflow comparison pass locally.
Only two setup steps and two library path inputs change; all cases, commands,
budgets, permissions and concurrency remain. Native replay is required; the
[development record](../../evidence/2026-11-04/sdk-pin-maven-identity-repair-development.json)
selects 23 expected jobs (main9/JVM8/OCI2/upgrades2/library2). Enumerate actual
runs for the full SHA; focused browser jobs are not selected by these paths.

The hosted retained-cache Maven fixture at `c030aa0` failed on both actual Linux
hosts after 231 assertions, before completing client identity: its new parser
omitted the `re` import. Preserve the [first failure](../../evidence/2026-11-04/maven-warm-c030aa0-first-failure.json),
including both original safe summaries and fixed traceback identity. The import
is repaired and the actual fixture's version gate now runs against local
plain/ANSI/wrong/malformed observations, stopping before deployment. No JVM or
PostgreSQL runs on this Mac. Require the original 647 baseline checks plus 16
new checks (663 total), four mandatory stages and six publisher/reference/HTTP/
retained-local-cache bindings on both native hosts. Warm proxy/group/Ivy/SBT,
offline, interruption and broader scope remain open. Existing c030 runs are
observed separately, without a blind restart or canceled started main job.

The earlier timeout, first dotnet 401 and Maven bootstrap failures remain
retained. A passing newer full browser suite does not establish the unknown
original timeout cause. The owner-encrypted browser failure collector was not
exercised by that success. The c030 baseline failure produces no collector
record because its current profiles cover OCI/extended JVM/browser only; raw
job logs remain private and only fixed reviewed traceback identities are public.

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
| `jvm-clients.yml`: Ant/Ivy / 2 | Both native Linux architectures; real PostgreSQL | Ant1.10.18/Ivy2.6.0, exact JDK, Initial release profile passes228checks/sevenstages/12bytebindings/threeSHA2consumers. Named metadata-v2 passes494checks/8stages/8cases/28bytebindings. Snapshot-v3 passes654checks/9stages/8snapshot cases/34bytebindings on both hosts at636dea9. 60-minute job. Broader Ivy remains open. |
| `jvm-clients.yml`: SBT / 4 | SBT 1.13.0 and 2.0.11, each on native Linux amd64/arm64; real PostgreSQL | Separate series/version cases, exact JDK, tool-only boot cache, fresh project caches, seven stages/twelve byte bindings. Five-minute cold bootstrap, two-minute project commands, 60-minute job. Named release profile passes161checks on each of the four cases atd4056d9; broader SBT remains open. |
| `nuget-contract.yml`: libraries / 2 | Both native Linux architectures; exact SDK10.0.403 pin on the next revision (636observed x86.402/ARM.403) | Dense version, archive, casing, dependency and framework differential contracts; 20-minute job. Does not replace actual NuGet HTTP/restore/restart proof. |
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
| Ant/Ivy and SBT client breadth | Initial Ivy release/metadata cases pass. Qualify both new SBT series, then finish all snapshots/metadata/interruption/lifecycle and remaining JVM combinations. The [JVM plan](jvm-client-plan.json) records exact cases and bootstrap/cache limits. |
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
