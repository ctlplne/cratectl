# GitHub Actions qualification plan

Updated: 2026-11-07. Owner: `imfeelingtheagi`.

The entire `GOAL.md`, all450capabilities/41families and later stages remain
committed scope under section4.1. This plan assigns work to suitable hosts and
defines acceptance. Broad readiness, security and packaging remain unqualified.
A selected CI campaign is a scoped result, not full product parity.

## Authority and current sources

Work and commits stay on `main`. Before every commit, verify both author and
committer are exactly `imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`;
audit afterward. Public repository and CI pushes/repairs are authorized. Release,
package/image publication, customer, primary and sibling changes need their own
authority. No autonomous delegation.

Current pushed qualification source: `ae7d00ece68d45f953d53f1728169e00b6dbe608`.
Its six completed handles are in [STATUS.md](../../STATUS.md) and
[remaining.json](remaining.json). [Final campaign](../../evidence/2026-11-07/github-ae7d00e-final-checkpoint.json):
26jobs/25success1x86Chromiumfailure,19safe72reports. BothLinux274PG normal/race,
96namedGo/312stock and other native main stages pass;57fuzz/source passes three
native hosts and JVM/OCI/upgrades/portable pass. Kernel controls and original
full-race replay pass bothLinux; historical socket cause remains unknown.
Originalb5serious Axe scrollable-region-focusable is retained. Six focus fixes
and keyboard/Axe regression pass local build/reproduction/console race/lint;
actual new browser replay remains required. Wholeb5/ae7are not accepted.

Latest whole selected acceptance: [4956197](../../evidence/2026-11-07/github-4956197-checkpoint.json),
26jobs/six workflows,19safe summaries/72reports. Its exact inventory is273fullPG,
95namedGo normal/race,55fuzz onthreehosts and19main151Chromium. Four UI workflows
use declared response stand-ins. Focused browser/NuGet-library/strict SDK were
unselected, never passes.

Later `badb85b` has separate accepted profiles:

- [96Go normal/race and312stock per Linux host](../../evidence/2026-11-07/go-module-badb85b-native-checkpoint.json).
- [15historical native binaries/20upgrade reports per host](../../evidence/2026-11-07/github-badb85b-upgrades-checkpoint.json).
- [16stages on actual separate x86 producer/ARM consumer](../../evidence/2026-11-07/go-export-portability-badb85b-checkpoint.json).
- [666Ivy checks per host and exact warm archive restore/pin revalidation](../../evidence/2026-11-07/apache-archive-badb85b-warm-native-checkpoint.json).

Its whole campaign now fails one x86 race conformance bind on38443;25jobs succeed.
Retain the [failed final checkpoint](../../evidence/2026-11-07/github-badb85b-final-checkpoint.json),
skipped stock/browser stages and zero-report summary. New TLS/
destination SDK/multiple-event cases are outside that proof. Original0132/0133/
0135failures, skipped stages and zero-report summaries stay unchanged. DEFECT0126
strict SDK trust-state failure and DEFECT0122unknown browser intermittent remain
open. Inspect live handles before deciding any outcome.

## Placement and required inventory

Local ARM work is focused build/unit/race/lint, parser fuzz and owned HTTP/FS/
shell/kernel stand-ins. Some existing unit/lint probes execute stock Go against
stand-ins. Normal/race PostgreSQL compilation and tagged vet prove compilation
only. Real PostgreSQL/registry/external signer/stock-client campaigns and Chromium
run on GitHub. Local emulation/cross-compilation never qualifies x86 behavior.

New source requires274fullPG/96namedGo normal/race onboth Linux hosts,
57checked-in product fuzz targets onthreehosts,19main151Chromium, original312Go/
683baseline checks,15historical20upgrades perhost,16portable stages and every
other actually selected profile. Existing jobs discover the new fuzz target and
extended native function; no duplicate local integration campaign is needed.

| Workflow / jobs | Actual placement | Work and budget |
| --- | --- | --- |
| `ci.yml`: selector /1 | Linux x86 | Bounded exact Git changes select runtime work;5minutes. Placement evidence only. |
| `ci.yml`: source /3 | Ubuntu24.04 x86/ARM; macOS15 ARM | Build, Go unit/race/vet, Python architecture/API/contracts, console reproduction, npm audit;30minutes. |
| `ci.yml`: fuzz /3 | Same three hosts | Every checked-in target,5seconds each;25minutes. Smoke, not a long parser campaign. |
| `ci.yml`: security /1 | Linux x86 | Pinned source/binary vulnerability analysis, tree/full-history Gitleaks and rule regressions;30minutes. Scoped security only. |
| `ci.yml`: PostgreSQL/clients /2 | Both Linux architectures, real PostgreSQL16.15 | Integration/race/timing, baseline clients, jobs/leases, integrity/hold/install/recovery;120minutes. Main Chromium only on x86. |
| `go-modules.yml` /2 | Both Linux architectures, PostgreSQL/Go1.27.3/OpenSSL | Named GoPG normal/race and312stock trusted-TLS checks;45minutes. New collector/import fixture uses TLS and controlled process/socket faults. |
| `jvm-clients.yml`: Gradle /2 | Both Linux architectures, PostgreSQL/JDK | Pinned Gradle9.8.2 publication/resolution/policy/recovery;60minutes. |
| `jvm-clients.yml`: Ant/Ivy /2 | Both Linux architectures, PostgreSQL/JDK | Ant1.10.18/Ivy2.6.0,666checks, original SHA512 pins and verified compressed archive cache;60minutes. |
| `jvm-clients.yml`: SBT /4 | SBT1.13.0/2.0.11 onboth Linux architectures | Release/snapshot cases, fresh project caches, pinned tool-only boot cache;60minutes. |
| `oci-clients.yml` /2 | Both Linux architectures, PostgreSQL/Docker/Podman/Helm | Inert publication/consumption, tenant/policy/revocation/restart;45minutes. Uploaded images are not executed. |
| `upgrade-qualification.yml` /2 | Both Linux architectures, fresh PostgreSQL | Rebuild15frozen historical native sources,20reports each, actual maintenance-process interruption;120minutes. Also scheduled/manual. |
| `go-export-portability.yml` /2 | x86 PostgreSQL producer; separate ARM consumer without DB | Exact synthetic signed capsule, separate trust fingerprints, CLI/SDK in observed empty child network namespaces;30/25minutes. |
| `nuget-contract.yml` /2 | Both Linux architectures | Actual pinned SDK10.0.403/NuGet-library differential corpus;20minutes. Separate from HTTP feed/restore journeys. |
| `browser-repair.yml` /up to3 | x86 Chromium, fresh PostgreSQL per replay | Repair/retention/NuGet, five full repetitions per selected journey;45minutes. Stop on failure. |
| `qualification-acceptance.yml` /1 | Linux x86, manual main dispatch | Contents/actions read only; bounded exact-source API/log/archive/report inspection,19stand-in tests, scoped counts/hash verdict;20minutes. Starts no native tests. |
| `go-checksum-client.yml` /3 | Linux x86/ARM and macOS ARM | Seven strict Go1.27.3 controls perhost, owned authority stand-ins. Altered-ZIP assertion fails onallthreehosts; six other controls pass each. |

Native test union:34possible matrix jobs/nine workflows. The new manual
read-only acceptance job makes35possible jobs/ten workflows. Sourceae7selects
six standard workflows/26native jobs. The scroll-region repair also touches
focused-browser triggers, so expect seven native workflows/29jobs; verify actual
API inventory. Manual acceptance is a separate job, never another native pass. Enumerate actual expanded jobs per exact
source; path filters and inputs vary. An omitted lane supplies no evidence.
Documentation may select planner/security with runtime jobs skipped. Neither
that green result nor an older source qualifies changed runtime code.

Workflow files own triggers, versions, permissions and commands. Executable
pins/cases also live in [jvm-clients.json](jvm-clients.json),
[jvm-client-plan.json](jvm-client-plan.json), [go-export-plan.json](go-export-plan.json)
and the other qualification manifests. Narrative edits do not change tool pins.

## Scheduling and resources

- Read-only tokens, checkout without persisted credentials, independent matrix
  outcomes and no `continue-on-error` for required gates.
- Profile/platform concurrency preserves running `main` jobs; PR work may be
  superseded. Selector keys include source SHA. Heavy/security groups still
  have replaceable pending slots. A later push can cancel an unstarted case;
  preserve it as unexecuted. Avoid documentation pushes that displace a required
  pending source job. Queue/observation timeouts never justify redispatch.
- Re-poll known handles and retain actual runner labels/start/steps. Distinguish
  acquisition/capacity from executed assertions; no missing native result is
  filled by emulation, an earlier source or a canceled job.
- Owned `cratectl-*` resources, loopback38443/35432 and private generated
  credentials only. PostgreSQL runtime is nonsuperuser/nonowner/noBYPASSRLS;
  tenant tables have forced RLS. No primary/customer/sibling service changes.
- ADR0060adds guarded disposable Linux port reservation and two fresh child
  namespace kernel controls before integration. Preserve inherited reservations
  and parent automatic range; only35432/38443are added on the runner. Bounded
  future bind-state counts aid diagnosis. Local stand-ins and actual both-host kernel
  controls/full274PG normal-race replay pass atae7. Full campaign fails Chromium;
  original DEFECT0136socket owner remains unknown.
- Pin/verify executable bytes. Cache only reviewed public compressed archives
  or bounded approved tool-only boot data. Reverify archive pins after restore;
  no credentials/databases/uncontrolled project dependency caches. Cold/save
  and warm restore are separate observations. Real Apache fallback is unselected.
- Retain bounded command helpers: JVM baseline2minute deadlines,8MiB output
  ceiling/64KiB tail; SBT cold bootstrap5minutes and20,000file/768MiB tool caches,
  four downloads/two processors/768MiB heap; Gradle two workers; direct Ant
  512MiB heap/384MiB metaspace/two processors. Qualify remaining probes' process/
  output/fork bounds. Detached sessions remain a containment gap. Timeout can
  leave a remote mutation outcome uncertain.
- Keep fixture package payloads inert; never execute uploaded scripts/classes/
  models. Retain native SDK behavior, including read-only caches; clean only
  owned caches with the pinned tool after evidence is copied.

## Acceptance and failure handling

1. Bind full source SHA/clean state, actual host/OS/arch, embedded binary revision,
   exact tools/fixtures and mandatory stage inventory. Historical binaries keep
   their frozen original source identities.
2. Inspect every selected job and required step. Pending/skipped/canceled/missing/
   stale/empty results never pass. Integration claims need real PostgreSQL and
   stock clients, alongside meaningful regression tests.
3. Validate original bounded safe summaries with the exact source's typed
   contracts. Retain unchanged accepted JSON, report hashes, artifact IDs/action
   digests, private-log hashes and scope/limits under `evidence/`. A publisher's
   hashes alone do not establish independent wire effects.
4. Preserve first failures before repair. Retain every original case/assertion
   and replay the repaired source on suitable native hosts. Retries, larger
   budgets, SDK bypasses and skipped stages are not repairs.
5. Keep stand-ins, real DB/client effects, separate hosts, vendor interoperability
   and scale distinct. Four UI response stand-ins do not qualify DB/cryptography.
   Private fixture SumDB bypass never repairs DEFECT0126.
6. Update capability/journey evidence precisely. `implemented but unverified`
   differs from verified. Full readiness needs every required outcome/final gate.
   `make security`/`make packaging` still fail explicitly while incomplete.

Public uploads contain reviewed counts/hashes/fixed diagnostics/stages or the
reviewed synthetic capsule. Raw browser/command/SQL reports, credential/config
values and signing private keys stay private. Safe summary retention is currently
14days for Go/portable and30days for the other workflows;
preserve accepted bytes in Git before expiry. Failure diagnostics may retain
bounded owner-recipient CMS ciphertext/fixed metadata for7days. Decryption keys
never visit CI; no plaintext fallback. Existing collectors select at most two
failed commands or the final assertion observation, validate source/inventory/
owned paths/budgets, then encrypt.

Manual read-only aggregation is implemented as `qualification-acceptance.yml`
and `scripts/ci/accept_campaign.py` (ADR0059). Local19unit functions and required
lint pass. It binds all observed selected runs to one clean owner-authored main
source; rejects pending/failed/canceled/rerun/skipped required/empty or changed
inventories; checks34native job variants, exact native labels, required steps,
source-compatible typed contracts, complete report/binary/tool/fixture inventories,
actual separated portability runners and kernel/fuzz observations. Only fixed
bounded GitHub API routes, token-free reviewed download redirects and digest-
verified single-JSON archives are admitted. No downloaded artifact code executes.
Only constructed labels/counts/hashes/IDs are uploaded; goal/readiness stayfalse.

The actual workflow/source-reader/API path remains unqualified. First inspect
the complete retained495six-workflow campaign in a manual main dispatch: candidate
workflow/typed contract/script bytes match the current verifier, but actual Git
and API inspection must confirm. No native test restart. Then independently
accept the new repaired source only after its entire actual selected inventory
finishes. Existing reviewed exact-source records remain authoritative. No
workflow_run/PR privilege path, external message, publishing or implicit release.
See [development evidence](../../evidence/2026-11-07/campaign-acceptance-development.json).

## Remaining offload order

| Required work | Placement / acceptance |
| --- | --- |
| Exact-source campaign acceptance | The read-only aggregator above, retaining per-job originals/typed contracts/source inventories/first failures. Its scoped green verdict never grants full readiness. |
| Complete export/import/disconnected outcomes | Native Linux and separate producer/consumer hosts; full dependency/authority/permission/provenance closure and current destination scanning/import session/progress. One version/manual review is incomplete; retain all14cases/7environments in the Go export plan. |
| JVM breadth and every later format | Native stock tools/restricted PostgreSQL; hosted/proxy/group, nontrivial dependencies, exact bytes, permissions/policy/concurrency/faults/restart/freshness/lifecycle/migration. Retain all41families and JVM plan cases. |
| OCI/upstream interoperability | Authorized owned compatible registries/realms, pinned tools/inert content. Changing external services stay separate from deterministic gates; no publication authority inferred. |
| Own TLS/access/external identity | Real compatible customer-selected IdPs/trust services/native clients, scoped tenants/rotation/expiry/revocation/failure/recovery. Retain artifact verification/external signing adapters; no excluded CA/vault/issuer/signing-custody platform. |
| S3/storage/provider semantics | Real compatible services, multipart/versioning/retention/integrity/faults/quotas/tenant isolation/recovery and complete byte inventories. Filesystem proof does not qualify S3. |
| Scanner/dependency/image/artifact analysis | Pinned engines, legally usable corpora, feed identity/age/license and stale/unavailable behavior, source/binary/image coverage, false positives/negatives/supported reachability. Missing intelligence never means clean. |
| Packaging/Compose/Helm/disconnected install | Build/hash exact artifacts and install on disposable native persistent targets with supplied trust/upgrade/recovery/actual network isolation. Chart rendering/download lists are not installation proof. |
| Windows/additional macOS runtimes | Actual native CLI/package/server journeys. Implement/qualify Windows private ACL/atomic durability; unsupported commands do not inherit POSIX proof. |
| SBOM/signature/provenance/releases | Exact SPDX/CycloneDX/build manifests and independent offline verification under selected external trust. Distribution/signing publication needs separate authority. |
| Replication/federation/migration/backup/restore/HA | Real compatible sources/destinations, bounded complete inventories/checkpoints and controlled process/network/storage faults. Preserve identities/metadata/policy/bytes and qualify actual independent-host recovery/cutover. |
| Longer fuzz/differential campaigns | Manual/scheduled native jobs, reviewed corpora, explicit CPU/time/memory/concurrency budgets, retained minimized failures/replay. Keep5second smoke separate. |
| Standard/large/24hour soak/cost | Sized independent hosts and declared storage/network topology, orchestrated off this Mac. Required standard8vCPU/32GiB/1million records and large10million/1000tenants need actual measurements; shared runner smoke is not that proof. Retain unfavorable results and continuous soak requirements. |
| Licensed comparisons/customer acceptance | Authorized licensed incumbent systems and explicit access. Missing external inputs do not block independent work or authorize customer changes. |

Every implementation updates placement, fixtures, safe evidence schema, operator
docs and capability/journey limits together. Full completion still needs every
applicable owner requirement, repaired/replayed defects and final gates on a
named candidate. Only the owner can remove scope.

## Preserved history and local state

The previous plan is preserved byte-for-byte in
[the archived plan](github-actions-plan-history-before-b5cfb5d-acceptance.md),
SHA256 `bd9d42a2da23adda13460da49bd06174ab43a2f24c42d46513aed9b69a955d4c`. Earlier
[Actions history](github-actions-history.md), exact-source evidence, ADRs and
original failures retain their scopes. Historical current-state statements do
not supersede this plan or `STATUS.md`.

All16source migrations remain frozen. Primary is stopped at schema11 with
qualified5483878b selected binaries and tenreceipts unchanged. Local builds use
`.cache/` output directories. Preserve ignored `.private/`0700 and `.cache/`;
never commit credential values. No release/package/image/customer/sibling action
is part of this CI plan.
