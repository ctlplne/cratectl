# GitHub Actions qualification plan

Updated: 2026-11-06. Owner: `imfeelingtheagi`. The complete `GOAL.md`, all
450 capabilities / 41 families and all later stages remain committed scope.
This plan places work on suitable hosts and describes how to accept evidence.
It does not turn an unfinished feature or absent test into a pass.

The public repository and CI pushes/repairs are owner-authorized. Work and
commits stay on `main`, with both author and committer exactly
`imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`.
Release, package/image publication and customer/primary/sibling changes remain
outside this CI authority. No autonomous delegation.

## Current qualification state

Exact5ee [campaign checkpoint](../../evidence/2026-11-06/github-5ee4fbc-checkpoint.json)
accepts all29actually selected jobs in7workflows:22safe summaries/79reports.
All212PGfunctions run normally/race onbothLinuxhosts, source/unit/race/lint and
43fuzz targets pass on3native hosts, original38PG/312Go profile passes onboth,
11historical baselines and16upgrade reports perarch cover schema2–11 into12.
JVM/OCI, exactSDK NuGet libraries and15focused x86browser trials also pass.
Mainx86Chromium119checks/15tests has0skips/flaky/unexpected; ARMunselected. This
qualifies the named profiles; full450capabilities/security/packaging remain open.

The [named Go checkpoint](../../evidence/2026-11-06/go-module-5ee4fbc-native-checkpoint.json)
qualifies configured collection plus9new durable timeline/publication functions,
including actual concurrent repository collectors, immutable/RLS/lease/source/
policy/capacity/fork fences and11receipt preservation into12. The original5380
ARMjobs68assertion failure did not reproduce:5eepasses all71assertions and later
profiles. Its cause remains unknown. KeepDEFECT.0122 intermittent/open; new
bounded encrypted assertion/process-log coverage is instrumentation, not proof
of repair. No retry/deadline increase or original failure removal.

The [whole b6 campaign](../../evidence/2026-11-06/github-b6bb53f-checkpoint.json)
now accepts all24actually selected jobs/5workflows,17safe summaries/62reports,
217fullPGnormally/race on bothLinuxhosts and44fuzz/source/unit/race/lint on3native
hosts. Library/focused were unselected; retain their previous5ee source-specific
results. Original5380jobs68failure remains unknown/intermittent, not repaired.

The [exact2da named Go checkpoint](../../evidence/2026-11-06/go-module-2da6957-native-checkpoint.json)
qualifies48PGfunctions normally/race and all312stock checks onboth native Linux
hosts. Configured renewable fill,12concurrent callers,8faults, held-proof lease
renewal, one proof-only CAS recollection and known signed fork/no-stale are now
observed. Its wider222PG/44fuzz campaign remains separately tracked.

The [current discovery development](../../evidence/2026-11-06/go-checksum-discovery-development.json)
adds3PGfunctions/39cases plus one8case unit function and a45thfuzz target.
Current51Go/225fullPG must run normally/race onboth native GitHub Linuxhosts;
45fuzz/source/unit/race/lint stays on3native hosts. Preserve312stockGo, all other
actually selected client profiles and11historical native/16upgrade reportsperarch.
No new workflow, duplicate dispatch, retry/deadline increase or case removal.
Local ARM gates/tagged compile/vet pass; no localPG/JVM/SDK campaigns or emulatedx86.

Discovery now uses one bounded known-root receipt/proof-policy batch per source
under the existing complete-view budget. Expired complete packages can still
route for refresh, but missing receipts, current proof denial/retirement or
permanent checksum failures retain first-source blocking. Catalog/unknown version
advertisements never grant bytes; physical proof readback/current guards remain.

Then complete explicit offline/freshness policy and original failure/fork evidence
with tenant/key-wide governance; customer/export/backup/GC and checksum-on stock
proxy/group journeys before public mode. Keep independent client GOSUMDB policy,
original hosted/group checks and every original failure. Running main jobs remain
preserved; the retained schema11 primary is outside disposable CI maintenance.

Earlier source-specific observations below retain their historical limits; the
newest exact checkpoint above governs current qualified scope.

Exactdbd [both-native checkpoint](../../evidence/2026-11-06/go-module-dbd5671-native-checkpoint.json) verifies25PGfunctions normally/
race and the original312check/9stage24wire16cache profile on both actual Linux
hosts, including typed original latest-advertisement/network transaction cases.
Later1e current hint cache/caller remains unqualified; observe existing26function
Go run42284736457 without duplicate dispatch. No skipped/empty/compile-only result
counts as a pass, and public proxy/fullGo/product readiness remain unfinished.

The latest-hint current-cache/renewable caller adds1PGfunction/14scenarios,
compiled normally/race only; current26functions must run through the unchanged
filter/profile on both native hosts. ARM build/unit/race/lint/vet pass; zero local
PostgreSQL. Hints retain bounded metadata/current grants/source/cache and grant
no package approval. [Development evidence](../../evidence/2026-11-06/go-latest-hint-caller-development.json)
keeps absent optional hints separate from module/version absence. Discovery/final
latest integration and public proxy remain unfinished.

Exact8f [both-native checkpoint](../../evidence/2026-11-06/go-module-8f66bf4-native-checkpoint.json) now verifies all23PGfunctions
normally/race and the unchanged312check/9stage/24wire/16cache hosted-group-v2 on
both actual Linux hosts, including queue and503 source-change repairs. The next
latest-advertisement foundation adds2PGfunctions/eight scenarios compiled only;
current25requires a new exact native replay. ARM full build/test/race/lint and
short fuzz smoke pass; no local PostgreSQL campaign. Latest hints preserve
original response bytes and coordinate identity without granting package approval.
Current hint cache/caller/discovery/selection and public proxy remain unfinished.
See [development evidence](../../evidence/2026-11-06/go-latest-advertisement-development.json). No new workflow/budget/retry or case
removal; all original profile checks remain mandatory. GOAL4.1 exclusions apply.

The owner resumed the amended goal on2026-11-06. Section4.1 excludes trstctl
services; artifact verification/external provider adapters and cratectl own
access/TLS remain. Both210native Go jobs fail two response assertions: final
guards return the expected ErrSourceChanged, while the existing shared503
response conflicts with fixture409. Production response/serving code is unchanged
by the repair; both no-byte/validator checks remain. ARM unit/race/full lint and
23PGnormal/race compilation/vet pass. Race/client stages skipped and empty
summary exports remain failures. See the [first failure](../../evidence/2026-11-06/go-module-210ac68-source-response-first-failure.json)
and [repair](../../evidence/2026-11-06/go-source-response-repair-development.json). Re-run all23functions normally/race and every
original312stock check on both GitHub hosts; no duplicate dispatch.

Exact946fails both normalserver packages at the queue fixture label; the common
store already retired the lease as queue_capacity. Race/client stages skip and
empty summaries remain failures. The repair retains every assertion, requires
no live lease, and adds capacity recovery/new-generation proof. The same revision
adds atomic post-readback latest selection in2PGfunctions/22scenarios; current23
functions compile normally/race only. All original312stock checks remain mandatory.
See the [first failure](../../evidence/2026-11-05/go-module-946fe55-queue-fixture-first-failure.json) and
[latest development](../../evidence/2026-11-05/go-latest-current-selection-development.json). Public proxy remains disabled.

Exact4a Go [both-native checkpoint](../../evidence/2026-11-05/go-module-4a131f7-native-checkpoint.json)
verifies the unchanged hosted/group-v2 profile and13PGfunctions normally/race.
The internal caller adds6functions/25scenarios, including12concurrent requests;
metadata preparation adds2functions/24scenarios. All21execute on both GitHub hosts
through the existing filter. ARM build/unit/race/lint and tagged compile/vet pass;
zero PostgreSQL runs locally. No retries, budgets widened, cases removed or public
proxy enablement. Source946 and0c normalserver packages fail the queue-label fixture;
no pending/skipped/canceled source counts as a pass. [Metadata development](../../evidence/2026-11-05/go-metadata-preparation-development.json)
records complete grants/source catalogs, running byte/deadline limits, typed cache
admission, current response view and the precise overflow/network-byte limits.

Exact `0cff4b8` now passes all 21 actually selected jobs: main9/JVM8/OCI2/
upgrades2. All 15 accepted safe summaries bind exact source/native binaries,
actual tools, fixture bytes and artifact identities. Both baselines pass663,
real PostgreSQL normal/race/five snapshot regressions and four Maven warm-cache
stages/six bindings. Full x86 Chromium passes119/all15workflows without skipped,
flaky or unexpected results. All three native source and fuzz jobs pass,
including macOS ARM. See the [whole observed checkpoint](../../evidence/2026-11-04/github-0cff4b8-checkpoint.json).
Library/focused-browser workflows were not selected on this source; earlier
[1974 library proof](../../evidence/2026-11-04/nuget-1974d94-checkpoint.json)
remains separate with both actual SDK10.0.403/runtime10.0.14 contracts passing
all37original assertions. Whole observed success does not qualify the full goal.

The accepted JVM campaign includes Ivy666/cache-v4/ten stages/34wire plus six
retained-cache bindings per host, Gradle199/eight/24 and four SBT release
snapshot profiles269/eight/18. Both OCI214 and both upgrade10pins/15reports pass.
Ivy retains the same changing consumer/cache/module through initial/update/
restart, exact changed POM/JAR bytes and the first observations before overwrite.
Warm proxy snapshot/offline/fault and broader lifecycle requirements remain open.

At later exact `0cff4b8`, SBT snapshot-v2 passes all four series/architecture jobs:
SBT1.13.0 and2.0.11 each pass269checks/eight stages/eight snapshot cases/18bindings
on native Linux x86 and ARM. Every original release case remains. These commands
use fresh project caches copied from frozen tool-only seeds; warm project caches
are unqualified. See the [named checkpoint](../../evidence/2026-11-04/sbt-snapshots-0cff4b8-checkpoint.json).
The whole campaign now passes all21jobs/15safe summaries: both formerly queued
macOS jobs actually executed and passed. The earlier0edd checkpoint remains
retained; later Go/scanner/selection revisions need separate native evidence.
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
Named native proof now covers both ORAS and Helm on both architectures:
f91 misses, bounded verified downloads and post-success saves; later5b restores
the exact same platform/source keys and revalidates the pins without a fresh
download. All original OCI214 and controlled-upgrade10pin/15report campaigns
pass on both sources. See the [scoped checkpoint](../../evidence/2026-11-04/native-tool-archive-cache-checkpoint.json).
Installer/helper/workflow bytes match. No timing/speedup or whole-candidate claim.
Other downloads/caches, including Gitleaks' security curl, remain separate review
and qualification work. These cache paths select only public compressed
archives, and restored bytes are reverified before use.

The scoped security job now uses this bounded fetcher for the exact existing
Gitleaks8.30.1Linux-x64 archive/SHA256 pin and a new single-public-archive cache.
The official release API reports8,230,402bytes and the same SHA256. Cap32MiB,
15/180/195second budgets and all failure/cache defenses remain. Runtime version
8.30.1 is required after the restricted extraction. All original source/binary/
current-tree/full-history/324synthetic-rule checks remain independent of runtime
selection and execute on cache hits. Eleven fetch tests/full lint plus YAML/shell
and semantic workflow preservation pass. Named x86 cold/save at `fdff445` and
exact-key restore/revalidation at `b7cc74c` now pass with both original scoped
security jobs and all 324 rule cases. This helper revision refreshes ORAS/Helm
cache keys; earlier named proof remains specific to f91/5b. No timing or complete
security claim. See the [development record](../../evidence/2026-11-04/gitleaks-bounded-download-development.json)
and [official release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1).

Go hosted/group-v2 now has named qualification at `4a131f7` on both actual
Linux architectures, including all thirteen source-defined PostgreSQL functions
normally and with race. Broader format qualification remains unfinished. The
next caller revision requires nineteen such functions, then an owned
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
integration now has both d183 native failed-job proofs: one authenticated CMS
record per host decrypts locally; raw streams stay private. Both PG normal/race
steps pass before an independent CLI-path failure. The stock Go registry journey
and later group function remain unverified. A failure before a report exists
still requires separate job observations. The later f959 group fixture fails
only at its incorrect413 budget expectation; its original503 refusal is retained.
Canonical CLI upload and strengthened shared503 row/byte/list/latest checks
are implemented locally but require native replay. See the
[fixture/diagnostic record](../../evidence/2026-11-04/go-module-fixture-diagnostics-development.json).

Exact802 now passes all4original server PG functions normally/race and actual
CLI TLS upload on both hosts, then fails401 after40checks/3stages/9wire because
its NETRC machine omitted the port. Original authenticated failures remain.
Current authority/console repair passes actual ARM Go against an owned trusted
TLS/auth stand-in: hostname-only denial, exact authority success,2modules and
4cached bindings. Full lint/console reproduction pass; complete registry
9stage/24wire/16cache proof remains required. The new stand-in runs through
make lint on all3source hosts without reducing any native registry case.

The internal atomic Go intake extension shares common lease/source/authority
and reference/integrity/event/outbox transaction paths. Three new store PG
functions pass both hosts at a630; thirteen functions pass both hosts at4a. Both normal/race commands include
store and server. A new HTTP-intake transaction function makes eight PG
functions before the latest cache-admission addition, retaining all four original
server functions and every client stage. The caller revision brought nineteen; metadata preparation brings twenty-one, latest selection twenty-three functions.
Public proxy mode remains rejected until full network/checksum/cache/serving
integration and actual native proof. No schema or runtime privilege change.
See the [intake](../../evidence/2026-11-04/go-module-atomic-intake-development.json)
and [auth repair](../../evidence/2026-11-04/go-netrc-authority-repair-development.json) records.

Exact `5be6d38` passes both normal server packages, then fails one final store
snapshot assertion. Race/client stages skip; empty summaries remain failures.
The fixture now compares persisted JSON before/after conflict rather than input
JSON formatting, retaining all immutable-byte assertions. Normal/race compilation
and vet pass; native replay is required. The new bounded upstream bundle fetcher
passes five ARM stand-in tests/39 subcases, affected checks and full lint. It
preserves all info/mod/ZIP bytes and combined cache directives, rejects incomplete
intake, and refuses require-checksum without independent authority. Full-body
refresh only. Public proxy stays disabled pending complete catalog/current-serving
integration and native proof. See the [first failure](../../evidence/2026-11-05/go-module-5be6d38-persisted-json-first-failure.json)
and [development record](../../evidence/2026-11-05/go-upstream-bundle-fetch-development.json).

The internal proxy cache selector now joins tenant/grant/source/three-receipt
and complete-bundle policy checks in one database snapshot. Its ninth PG function
has 18 freshness/stale/negative/receipt/policy/tenant/fault scenarios; compilation
only. Store unit/race, integration vet and architecture checks pass. The OCI
admission type retains a compatible alias and byte-identical helper bodies.
No public proxy route, group selection or actual cache qualification follows.
See the [cache admission record](../../evidence/2026-11-05/go-bundle-cache-admission-development.json).

Typed source catalog intake now binds raw upstream list bytes and canonical
advertisement names through the common retrieval transaction; names grant no
package approval. ARM owned HTTP/unit/race/vet/full lint and five-second fuzz
smoke pass. Two local draft allocation failures remain recorded; final per-entry/
count bounds pass. The tenth PG function compiles only, adding initial/refresh/
source/lease/outbox cases without changing the workflow filter or budgets.
Current catalog/group/freshness selection and public proxy remain unfinished.
See the [catalog development record](../../evidence/2026-11-05/go-source-catalog-development.json).

Internal discovery now joins current catalogs, complete cached-bundle policy,
namespace pins and first-source precedence in one read snapshot. SQL metadata/
row and complete-result bounds reject overflow without a prefix. It advertises
names rather than approving/serving bytes. ARM affected checks/full lint and
plain503/retry contracts pass. The eleventh PG function has15scenarios compiled
only; final group byte selection/latest/pseudo/caller integration remains open.
See the [discovery record](../../evidence/2026-11-05/go-current-discovery-development.json).
Both6bGo jobs cancel before steps/artifacts, while earliera630 jobs remain queued
and8698jobs pending at observation. No pass or retry follows; see the
[cancellation record](../../evidence/2026-11-05/go-module-6b564e7-pending-cancellation.json).

Exact `a630875` x86 now verifies312checks/all9stages/24publisher-reference-HTTP
bindings and16exact cached ZIP/mod bindings with actual pinned Go1.27.3 and
trusted generated TLS. Both native binaries bind clean exact source, and all
eight PG functions at that source pass normally/race, replaying the NETRC and
persisted-JSON fixes. ARM126972556526 remains queued. Later cache/catalog/
discovery functions are absent from this source and remain unqualified.
See the [named x86 checkpoint](../../evidence/2026-11-05/go-module-a630875-amd64-checkpoint.json).

The same exacta630 profile now also passes ARM: both hosts verify312checks,
all9stages/24wire/16cache and8PGfunctions normally/race. See the
[both-architecture checkpoint](../../evidence/2026-11-05/go-module-a630875-native-checkpoint.json).
Newer1c fails both normal store steps; race/client skip and empty summaries are
retained. Repairs honor source revision0, PG16 suffix SQL, restricted runtime
deletion and journal-bound queue seeds. No schema/grant/FK weakening. The new
post-readback serving guard reselects current precedence and receipts before
headers, including readable-first grants and request-bound negative404s.
Unit/race/lint and normal/race compilation/vet pass. All13PGfunctions now pass normally/race on both hosts at4a, including2new
25scenario guard functions and16case discovery. The new durable caller adds
6functions/25scenarios (including12concurrent requests), compiled normally/race
only; all19still require a new exact-source native execution.
Public proxy remains disabled; see the [first failure](../../evidence/2026-11-05/go-module-1c5e3a1-cache-fixture-first-failure.json)
and [development record](../../evidence/2026-11-05/go-current-serving-selection-development.json).

Upstream info/mod/ZIP validators now have local bounded-input unit/race/vet
and five-second ARM fuzz-smoke proof. The new target joins the existing GitHub
fuzz inventory automatically; no test budget or original target is removed.
These validators do not enable proxy routes or qualify retrieval. Future proxy
work must retain both normal/race PostgreSQL and every original stock-Go stage
while adding upstream authority, multi-object commit/cache, policy/fault and
group-source journeys. See the [development record](../../evidence/2026-11-04/go-upstream-representations-development.json).

The full workflow union is now29jobs across seven workflows, including one
new bounded main-CI selection job. It compares exact base/head Git changes and
records a fixed reason/count/hash. Runtime inputs, known pins/instructions,
unknown files, uncertain diffs and manual dispatch select all original source/
fuzz/native lanes. Only documentation/evidence-only changes can leave those
lanes unselected; independent scoped source/binary/history/secret scans always
remain. Every prior command, matrix, budget, permission and concurrency value
is preserved. Six real-Git/stand-in tests, full lint and semantic YAML comparison
pass. Actual source-true placement passes at63ad692 with exact8path/hash evidence and
all3source/3fuzz/2native matrix jobs present. Those jobs remain pending/queued in
that observation; independent security was canceled pending. The e627 docs-only
selector was canceled before execution, so false selection remains unverified. See the [selection development record](../../evidence/2026-11-04/ci-selection-development.json).

The five-minute selection job now isolates its pending slot by exact source SHA
as well as branch. A documentation push therefore cannot replace a source
planner before it schedules runtime jobs. The e627 canceled selector remains
unexecuted, with no false runtime=false pass. Six real-Git tests and YAML semantic
preservation pass. Exactfdff now executes this source-specific selector
successfully, reproduces the exact count/hash and places all8heavy jobs. Their
execution and legitimate docs-only false/security proof still require evidence.
Heavy-job and independent security concurrency remain unchanged. See the
[source-key development record](../../evidence/2026-11-04/ci-selection-source-key-development.json).

Enumerate actual full-SHA jobs and the uploaded selection record before campaign
acceptance. GitHub's [job conditions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idif)
and [dependency outputs](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#needs-context)
control placement; a green workflow with unselected lanes does not qualify those
lanes. No skipped or absent job becomes a pass. A selector failure is a failed
prerequisite, not successful avoidance of testing. No dummy qualification commit
or blind retry. Native private clients retain normal TLS, one explicit source,
private NETRC/caches, and explicit fixture checksum policy. Public checksum
mirroring, other platforms/providers and all remaining product gates stay open.

Legitimate evidence-onlyb7 now executes documentation-false selection: exact
5path/hash match,3logical runtime skips before matrix expansion, and an
independent scoped security job that completes successfully. Both selected
jobs pass;3logical runtime skips remain unqualified. Original scoped source/
binary/history/secret scans and324rules pass. Gitleaks now has matching native
x86 cold/savefdff→exact-key restore/revalidationb7 proof; no timing, fullsecurity
or runtime/client pass. See the [scanner checkpoint](../../evidence/2026-11-05/gitleaks-native-archive-cache-checkpoint.json). See the [placement record](../../evidence/2026-11-05/ci-selection-b7cc74c-documentation-placement.json).

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
| `ci.yml`: selection / 1 | Native Linux amd64; bounded exact Git history | Five-minute per-source placement job; source-true execution/count/hash and8heavy placements verified atfdff. Native checks and documentation-false/security proof remain separate. Not a product test pass. |
| `ci.yml`: source / 3 | Ubuntu 24.04 amd64 and arm64; macOS 15 arm64 | Build, Go unit/race/vet, architecture/API and Python contracts, console reproduction and npm audit. 30-minute job budget. Source checks do not qualify a full macOS server/package journey. |
| `ci.yml`: fuzz / 3 | Same three native hosts | Every checked-in Go fuzz target, bounded five-second smoke per target; 25-minute job. Retain target inventory and failures. This is not a long parser campaign. |
| `ci.yml`: scoped security / 1 | Ubuntu x86 | Pinned source/binary analysis, full reachable Git history secret scan and synthetic rule regressions. 30-minute job. Current324-case named proof is separate from full security/feed/image coverage. |
| `ci.yml`: PostgreSQL and stock clients / 2 | Both native Linux architectures; real PostgreSQL16.15 | Integration/race, bounded timing, durable jobs/leases, integrity and baseline client/recovery journeys; 120-minute job. Full Chromium suite only on x86. ARM browser placement is skipped and never counted as passing. |
| `jvm-clients.yml`: Gradle / 2 | Both native Linux architectures; real PostgreSQL | Gradle9.8.2, exact JDK21 build, eight stages and24 publisher/reference/raw-HTTP digests. 60-minute job. Named v2 profile passes; broader JVM remains open. |
| `jvm-clients.yml`: Ant/Ivy / 2 | Both native Linux architectures; real PostgreSQL | Ant1.10.18/Ivy2.6.0 and exact JDK. Cache-v4 passes666checks/10stages/34wire+6cachebindings on both hosts at0edd, retaining all release/metadata/snapshot/SHA-2 cases. 60-minute job. Broader Ivy remains open. |
| `jvm-clients.yml`: SBT / 4 | SBT1.13.0 and2.0.11, each on native Linux amd64/arm64; real PostgreSQL | Snapshot-v2 passes269checks/8stages/8snapshotcases/18bindings on all4cases at0cff, retaining every release case. Frozen tool-only boot cache/fresh project caches. Five-minute bootstrap, two-minute commands, 60-minute job. |
| `go-modules.yml`: hosted/group and intake / 2 | Native Linux amd64/arm64; pinned Go, real PostgreSQL16.15, trusted loopback TLS | Current29PGfunctions are required normally/race; exact3b qualifies28plus the original312profile. Configured checksum collection needs a new exact replay. Exact4a passes both hosts with13PGfunctions and312checks/all9stages/24wire/16cache. Original1cfailures retained;Exact8f qualifies23PGnormal/race and full312check hosted-group-v2;2advertisement functions compile only. Original failures retained.45-minute job; public proxy remains rejected. |
| `nuget-contract.yml`: libraries / 2 | Both native Linux architectures; exact SDK10.0.403 selection | Original37assertions/unchanged dense corpora pass both at1974, actual runtime10.0.14 and separate DLLhashes. 20-minute job. Does not replace actual NuGet HTTP/restore/restart proof. |
| `oci-clients.yml`: native clients / 2 | Both native Linux architectures; Docker, Podman, Helm, real PostgreSQL | Actual publication/consumption and policy/tenant/recovery cases with inert owned data; 45-minute job. Do not execute the uploaded image. External-provider interoperability is separate. |
| `browser-repair.yml`: focused / 3 on relevant pushes | Native x86 Chromium; five fresh PostgreSQL databases per selected journey | Repair, retention and NuGet each repeat five complete journeys; 45-minute job. Manual dispatch selects one. Stop on failure; no retries/skips count as acceptance. |
| `upgrade-qualification.yml`: controlled upgrades / 2 | Both native Linux architectures; fresh PostgreSQL | Rebuild ten immutable historical pins and require15 reports each; 120-minute job. Relevant pushes, manual dispatch and Monday08:17UTC. Not rolling upgrade, downgrade or backup/restore proof. |

The current union is29jobs across seven workflows, including the selector.
Exactfc39162 selects six workflows/27expected jobs; NuGet library paths were
unchanged. A documentation-only commit can select just the planner and scoped
security, with dependent logical jobs skipped. Enumerate actual jobs after
matrix expansion for every exact source; never assume29, treat an absent or
skipped lane as passing, or substitute an old run. Library jobs run only when their own paths select; a workflow omitted by its
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
  checks and owned Python/HTTP/file/TLS stand-ins, including actual stock Go
  against inert stand-in modules. x86, registry-backed JVM/SDK/Go/PostgreSQL and
  managed browser qualification runs on GitHub. No emulation-based pass.
- Each disposable environment owns `cratectl-*` resources, loopback38443/35432,
  a private generated credential directory and restricted PostgreSQL runtime:
  nonsuperuser, nonowner, no BYPASSRLS. No primary or sibling service changes.
- Pin client distributions and verify their bytes before executing them.
  Executable JVM pins live in `jvm-clients.json`; narrative state lives in
  `jvm-client-plan.json`. Prose/checkpoint edits alone must not restart a client
  lane. Keep owned package payloads inert; run only owned fixture build rules
  and reviewed tool binaries, never uploaded package scripts/classes/models.
- Preserve started main-branch jobs across repair pushes. All seven project
  workflows use job/profile/platform groups, including Go, SBT series and
  focused browser journey. Each group has the default one pending tip. A newer pending
  tip can replace an older pending tip; PR work may still be superseded.
  Pending cancellation supplies no evidence. See
  [GitHub's concurrency contract](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).
  Semantic comparison of the five newly changed workflows proves only concurrency
  differs: all triggers, cases, commands, permissions, budgets and failure handling
  stay equal. Main scheduling has native evidence; the other groups still need
  their own observation. See the [development record](../../evidence/2026-11-04/ci-family-independent-lanes-development.json).
  That historical six-workflow revision selected26union cases. The current
  seven-workflow union is29; enumerate actual source paths and matrix jobs,
  including library jobs only when their own filters select them. The short
  selector now includes source SHA in its key so docs cannot replace a queued
  source planner. Heavy/security lanes keep their original pending-slot rules.
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
| Ant/Ivy and SBT client breadth | Ivy cache-v4 and all4SBTsnapshot-v2 cases pass at0cff, retaining release cases. Complete remaining warm-cache/classifier/parent/BOM/compiledScala/metadata/interruption/outage/lifecycle/JVM combinations. The [JVM plan](jvm-client-plan.json) preserves exact cases and bootstrap/cache limits. |
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
a missing native result. Historically the SBT matrix brought six workflows to
26jobs; current Go and selection additions bring seven workflows to29. That
older SBT/common-exporter change selected24, while exactfc39162 selects27.
Record actual selected and skipped jobs for each full candidate instead of
carrying a historical job count into a later campaign.
