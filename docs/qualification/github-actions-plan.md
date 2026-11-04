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

Owner resumed the full goal on2026-11-04. Clean `708214f` now has all17
observed jobs and11unchanged safe summaries accepted in the
[whole observed checkpoint](../../evidence/2026-11-04/github-708214f-checkpoint.json):
main9/JVM4/OCI2/upgrades2. Both native PostgreSQL integration/race lanes pass,
including the new parent-derived checksum regressions. Broader clients pass645/
56SDK HTTP-restart cases; x86 Chromium15with0bad/skipped results; OCI214,
15upgrade reports/10historical pins per architecture and324scoped-security cases.
ARM Chromium placement is skipped and never counted as a pass.

The [native JVM proof](../../evidence/2026-11-04/jvm-708214f-checkpoint.json)
binds Ivy228checks/sevenstages/12publisher-reference-HTTP identities/threeSHA2
consumers and Gradle199checks/eightstages/24bytebindings on each architecture.
Original Ant-selection and checksum-spelling failures remain retained.
The preceding419861c partial22job campaign and its focused-browser/SDK library
proof retain their separate exact source. Ancillary Dependabot jobs never count
as product qualification. Earlier halt evidence remains historical.

The expanded `maven-metadata-v2` profile is now
[verified on42f9366](../../evidence/2026-11-04/ivy-42f9366-checkpoint.json):494checks,
eightstages/eight metadata cases and28matching publisher/reference/HTTP identities
per native architecture, retaining all original releases and threeSHA2consumers.
Both Gradle profiles also pass199checks/8stages/24bytebindings on that source;
the [four JVM summaries](../../evidence/2026-11-04/jvm-42f9366-checkpoint.json)
are accepted separately from still-live main/upgrade jobs. Parent property/
management, classified JAR policy, optional/test sets, POM/client exclusions,
conflict, cached parent policy, actual restart and revocation pass. Snapshots,
interruptions/upstreamoutage,lifecycle,SBTandallotherGOALscope remain open.

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
| `jvm-clients.yml`: Ant/Ivy / 2 | Both native Linux architectures; real PostgreSQL | Ant1.10.18/Ivy2.6.0, exact JDK, Initial release profile passes228checks/sevenstages/12bytebindings/threeSHA2consumers. Named metadata profile passes494checks/8stages/8cases/28bytebindings on42f9366. 60-minute job. Broader Ivy remains open. |
| `nuget-contract.yml`: libraries / 2 | Both native Linux architectures and actual SDK10.0.403 libraries | Dense version, archive, casing, dependency and framework differential contracts; 20-minute job. Does not replace actual NuGet HTTP/restore/restart proof. |
| `oci-clients.yml`: native clients / 2 | Both native Linux architectures; Docker, Podman, Helm, real PostgreSQL | Actual publication/consumption and policy/tenant/recovery cases with inert owned data; 45-minute job. Do not execute the uploaded image. External-provider interoperability is separate. |
| `browser-repair.yml`: focused / 3 on relevant pushes | Native x86 Chromium; five fresh PostgreSQL databases per selected journey | Repair, retention and NuGet each repeat five complete journeys; 45-minute job. Manual dispatch selects one. Stop on failure; no retries/skips count as acceptance. |
| `upgrade-qualification.yml`: controlled upgrades / 2 | Both native Linux architectures; fresh PostgreSQL | Rebuild ten immutable historical pins and require15 reports each; 120-minute job. Relevant pushes, manual dispatch and Monday08:17UTC. Not rolling upgrade, downgrade or backup/restore proof. |

The union is22 jobs when every relevant workflow triggers. A normal push can
trigger fewer jobs because paths differ. Always enumerate actual runs for the
full source SHA; never assume22, treat a missing lane as passing, or substitute
an old run. The repair touches every workflow, so its native NuGet library
lanes also need observation. No duplicate dispatch merely to recover visibility.

Workflow files define exact triggers, permissions, matrices and commands. Use
read-only tokens, checkout without persisted credentials, fail-fast=false for
independent matrix results, and no continue-on-error. No publication step is
implicitly authorized by this plan.

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
  threshold and64KiB captured tail. The next local baseline-helper revision
  routes `conformance.run` through the same path, drains output through a
  nonblocking pipe, bounds private UTF8 input to1MiB and preserves complete
  structured results up to8MiB. Local stand-ins pass; actual baseline/JVM
  replay is still required on that revision. See the
  [development record](../../evidence/2026-11-04/baseline-client-bounds-development.json).
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
| Ant/Ivy and SBT client breadth | Initial Ant/Ivy releases pass; the named metadata profile also passes; finish snapshots/interruption/lifecycle and SBT2.x plus supported1.x. The [JVM plan](jvm-client-plan.json) records exact cases and bootstrap/cache limits. |
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
