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

Exact9b00f7e now passes all eight native JVM jobs, including Ivy654checks per
architecture/nine stages/eight snapshot cases/34byte bindings. Both main native
PostgreSQL integration/race and baseline steps pass. The final x86 Chromium
suite timed out at300seconds before producing JSON:23of24jobs pass, with18safe
summaries in the [partial checkpoint](../../evidence/2026-11-04/github-9b00f7e-checkpoint.json).
No complete browser workflow is accepted from this attempt. See also the
[JVM checkpoint](../../evidence/2026-11-04/jvm-9b00f7e-checkpoint.json).

The olderd4056d9 baseline has two preserved failures: first dotnet push401 and an
ARM Maven tool-download timeout. Its eight JVM passes remain valid only for
their named scope. Maven bootstrap now uses a committed reviewed SHA512 and two
approved Apache locations, each bounded15s connect/180s total/32MiB/HTTPS only.
Only a failed transfer can use the archive; a completed wrong digest stops.
Five local stand-in tests cover these boundaries. This fallback never changes
package sources or retries a failed qualification campaign.

Opaque NuGet keys stay attached as --api-key=value in the harness and copyable
examples. A deterministic actual-SDK leading-hyphen invalid-key probe must
reach real401 without the missing-key warning and leave no reference. The full
baseline retains its original645checks and adds two (647expected). The original
key/request was not exported, so its precise401cause remains unresolved. New
native replay is required; see the
[repair record](../../evidence/2026-11-04/ci-bootstrap-key-hardening-development.json).

Browser diagnostics now retain bounded private command output even when the
suite deadline prevents final JSON. Main and focused failure steps seal only
selected owned command/report/registry logs with the existing owner CMS
recipient, never token/config/fixture files. Ciphertext and fixed metadata
expire after seven days; private key stays local, with no plaintext fallback.
Ten owned-process and six CMS/collection regressions pass locally. The deadline,
all15workflows and zero retries remain unchanged; native observation is still
required. See the [development record](../../evidence/2026-11-04/browser-timeout-diagnostics-development.json).

A definite new snapshot browser-fixture locator mismatch is now independently
reproduced: a nonempty repository search shows the heading action named
`＋ Create repository`, while the test exactly matched the absent empty-state
action. Native ARM Chromium static DOM checks old0/corrected1matches. Only that
heading locator changes; the dialog submit, assertions and budgets stay intact.
The [repair](../../evidence/2026-11-04/maven-snapshot-locator-repair-development.json)
still requires actual x86/full-application replay. This test-only push selects
main9; enumerate actual runs, and retain existing1e9/0efa workflow handles for
their separate source-bound qualification. No new JVM/OCI/upgrade/focused pass
is implied by a path filter that does not select those workflows.

The following campaign notes predate this9b00f7e observation.

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
| `jvm-clients.yml`: Ant/Ivy / 2 | Both native Linux architectures; real PostgreSQL | Ant1.10.18/Ivy2.6.0, exact JDK, Initial release profile passes228checks/sevenstages/12bytebindings/threeSHA2consumers. Named metadata-v2 passes494checks/8stages/8cases/28bytebindings. New snapshot-v3 requires9stages/8snapshot cases/34bytebindings; native replay pending. 60-minute job. Broader Ivy remains open. |
| `jvm-clients.yml`: SBT / 4 | SBT 1.13.0 and 2.0.11, each on native Linux amd64/arm64; real PostgreSQL | Separate series/version cases, exact JDK, tool-only boot cache, fresh project caches, seven stages/twelve byte bindings. Five-minute cold bootstrap, two-minute project commands, 60-minute job. Named release profile passes161checks on each of the four cases atd4056d9; broader SBT remains open. |
| `nuget-contract.yml`: libraries / 2 | Both native Linux architectures and actual SDK10.0.403 libraries | Dense version, archive, casing, dependency and framework differential contracts; 20-minute job. Does not replace actual NuGet HTTP/restore/restart proof. |
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
Native scheduling observation remains pending; runner capacity is separate.
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
- Preserve started main-branch runs across repair pushes. Existing per-workflow
  groups allow one active run and the default one pending tip. A newer pending
  tip can replace an older pending tip; PR work may still be superseded.
  Pending cancellation supplies no evidence. See
  [GitHub's concurrency contract](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).
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
