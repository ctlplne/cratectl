# GitHub Actions qualification plan

Updated: 2026-11-02. Owner: `imfeelingtheagi`. Scope remains the complete
`GOAL.md`, capability/journey ledgers and `remaining.json`. This plan places
qualification on suitable hosts; it does not complete an unfinished capability.
The repository is public by explicit owner direction. CI and repair pushes are
authorized; releases, publication and customer changes retain their own authority.

## Accepted checkpoint and its limits

Clean source `6afbd4ad12cdb1d32aa43386a47822bc6e741fdf` passes the owner-directed
milestone: all nine main jobs, both native upgrade jobs, five independent repair
journeys and five independent retention journeys. The full x86 console passes
all 14 workflows with zero unexpected, skipped or flaky results. Both Linux
PostgreSQL race gates pass. Runtime summaries retain actual binary SHA-256 and
clean embedded source/OS/architecture identities. Each architecture rebuilt ten
pinned historical servers and passed 15 upgrade reports. The security summary
contains all 324 synthetic rule cases.

The [checkpoint](../../evidence/2026-11-02/github-browser-6afbd4a-checkpoint.json)
contains exact run URLs, seven safe summaries, hashes and scope limits. Acceptance
uses main run `41521729264`. The earlier same-source main run passed eight jobs
but its macOS fuzz job never acquired a runner; it is rejected and retained in
[the capacity record](../../evidence/2026-11-02/github-ci-6afbd4a-capacity-failure.json).
Cancellation is never converted into a pass.

`DEFECT.0071` and `DEFECT.0073` are repaired and replayed in this named scope.
Browser response bodies could become unavailable after the console consumed
them. Repair now uses displayed durable identity; retention identifies exactly
one newly admitted run through the independent API client after checking the
browser POST/status and hidden dialog. All recovery, focus, authority, exact-byte
and zero-Axe assertions remain required. Earlier diagnostic labels incorrectly
matched source snippets; the correction and original failures remain retained.
The first unavailable private failure's precise cause is not retroactively claimed.

This checkpoint is not full security, packaging, release, native Windows,
independent-host, scale, full accessibility or product readiness. All 450
capabilities / 41 families remain unfinished. `make security` and `make packaging`
still fail with their unfinished-campaign explanations.

## Placement and evidence rules

Use an actual native host for OS/architecture claims, real PostgreSQL for state,
and stock clients for package outcomes. Compatible disposable services prove
only their named integration. Cross-compilation proves compilation. Several
containers on one host do not prove independent-host HA. Skips are not passes.

CI never reads the retained local primary, imports local `.private/` or `.cache/`,
or promotes artifacts. Registry and PostgreSQL fixtures use project-owned
loopback ports 38443 and 35432. Runtime SQL roles are nonsuperuser, nonowner and
without BYPASSRLS. Credentials are generated and masked inside disposable runners.
PR tokens are read-only and have no repository secrets. Package install scripts
remain disabled; package/model contents are never executed by the registry.

Only the field-allowlisted summary is uploaded for 30 days. Raw browser reports,
traces, command output, credentials and private fixture state remain private on
the runner. Export both modified tracked and newly generated reports; a successful
empty summary fails. Validate candidate/run ID, clean build, native platform,
reviewed artifact path and SHA-256 before accepting evidence. Commit the reviewed
summary and its hash under `evidence/` before artifact expiry. Evidence commits
reference the tested source; they do not claim their own commit already passed.

Freeze a coherent candidate until all required gates finish. Collect terminal
job outcomes and actual summaries; never combine different source commits.
Retain first failures. Diagnose error headers, phases and safe rule counts rather
than source frames or guessed matcher labels. Retry a diagnosed infrastructure
failure on unchanged bytes while preserving the rejected run. An observation
timeout alone does not justify restarting a live job.

## Running gates and cadence

| Gate | Actual host or service | Trigger and required result |
| --- | --- | --- |
| Source/unit, three jobs | Ubuntu 24.04 x86-64 and ARM64; macOS 15 ARM64 | Every main push, PR and manual main CI. Build, unit, race, vet, architecture/API checks, console reproduction and npm audit. |
| Bounded fuzz, three jobs | Same three native host types | Same main CI. All 23 checked-in targets, five seconds each, bounded process/target count. Crash smoke only; full parser/security campaign remains open. |
| Scoped security, one job | Ubuntu x86-64 | Same main CI. Pinned govulncheck source/two binaries, Gitleaks current snapshot/full reachable history and 324 synthetic rule cases. Feed/image/full-security coverage remains separate. |
| Native integration/clients, two jobs | Native Linux x86-64 and ARM64; fresh PostgreSQL16.15, registry and filesystem | Same main CI. Integration and PostgreSQL race tests, generic/ORAS/Maven/npm/PyPI compatibility, native lifecycle, blank trusted-TLS install, jobs/leases, inventory/sweeps and matters. x86 additionally requires full14workflow Chromium/Axe. ARM browser is not claimed. |
| Focused browser, one job per selected campaign | Native x86 Linux, real fresh PostgreSQL/registry/Chromium | Relevant UI/driver pushes default to repair; manual choice repair or retention. Exactly five fresh databases and complete journeys; stop at first failure, no retries or skips. Separate concurrency groups prevent one selection cancelling the other. |
| Controlled upgrades, two jobs | Native Linux x86-64 and ARM64 with fresh PostgreSQL | Relevant source/schema/driver pushes, manual and Mondays08:17UTC. Rebuild ten reviewed immutable source pins; verify actual native identities and bytes; require15reports per architecture covering legacy adoption, schemas2–10, repair, integrity and retirement. Not rolling upgrade, downgrade or backup/restore proof. |

At each acceptance checkpoint, dispatch both focused selections and any required
manual campaigns on the same frozen source as main/upgrades. `ci.yml` retains
nine jobs; focused repair, focused retention and upgrades add four more. All 13
must finish successfully for the current regression milestone. Job success alone
cannot replace the report inventory, browser counts or binary identity checks.

GitHub publishes standard `macos-26` ARM64 and Windows x64/ARM64 runner targets
alongside the current matrix; see the [official runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
and [placement review](../../evidence/2026-11-02/github-runner-placement-review.json).
Published labels are available testing options, not executed cratectl evidence
or a capacity guarantee. Native Windows needs private-file ACL implementation
and actual CLI/client tests; lack of a runner is no longer its external input.
Do not replace an ARM test with Intel or a cross-build to obtain a green result.

## Native OCI client gate

`oci-clients.yml` adds two native Linux jobs for Docker/Podman/Helm, using a
fresh restricted PostgreSQL database and the actual registry. The shared
bootstrap has an explicit OCI-only mode; the existing main/browser/upgrade
workflows retain their default full tool set. The new driver and safe version/
binary evidence are implemented but unverified. See
[the development record](../../evidence/2026-11-02/oci-clients-development-preflight.json)
and [operator qualification guide](../operator/oci-client-qualification.md).
The first native run failed on both architectures during setup: its Podman
Debian revision pins would downgrade newer installed packages. The corrected
setup verifies bundled CLI4.9.3 and records the installed revision/architecture
and binary hash. It also retains fixture and verified graph/member digests.
See [the first failure](../../evidence/2026-11-02/oci-clients-first-failure.json)
and `DEFECT.0074`. The1757c89 setup replay passed both installations and
recorded the actual4.9.3+ds1-1ubuntu0.2 packages. Both journeys then failed
at the first Podman login, with cause unknown (`DEFECT.0075`). The next native
replay exports bounded fixed error-marker identifiers; raw command output
remains private. See [the login failure](../../evidence/2026-11-02/oci-clients-1757c89-authentication-failure.json).
Real native client publication and consumption remain unverified.
The79b4d44 replay again stopped at Podman login on both architectures and
matched no reviewed diagnostic markers. Its root cause is still unknown.
Failure artifacts now add encrypted, bounded command/registry logs with a
seven-day retention period. Only the public recipient certificate goes to
GitHub; the decryption key stays in ignored local private state. No plaintext
fallback is allowed. See [private diagnostic operation](../operator/ci-diagnostics.md).
The270f7ca artifacts encrypted with actual GitHub OpenSSL3.0.13 and decrypted
locally with4.0.3 on both architectures. Both errors identify Podman4's50character
runroot limit before registry authentication. The repair uses a short uniquely
owned temporary runroot with inode-bound cleanup. The f499369 replay passed
all native client logins, then failed at Docker manifest lookup. See [the observed error](../../evidence/2026-11-02/oci-clients-270f7ca-runroot-failure.json).
This gate adds required client evidence; it does not replace the accepted13job
regression milestone or complete OCI/platform/readiness scope.

## NuGet library contract

`nuget-contract.yml` moves the new Go/NuGet.Versioning differential contract
to actual Linux x86-64 and ARM64 runners. It compares deterministic synthetic
version strings with the runner SDK's installed reference library, records
the actual SDK/library and byte identities, verifies both native process
architectures and requires clean exact Go source. Its owned C# fixture clears
remote package sources and has no package references. The new Go parser also
joins the existing native fuzz inventory.

This version-identity contract passed all1,129synthetic comparisons on each
native Linux architecture at f499369, using SDK10.0.403 / NuGet.Versioning7.9.0.0.
See [the exact checkpoint](../../evidence/2026-11-02/nuget-version-f499369-checkpoint.json).
It supplies no NuGet feed/client, archive, symbols, tenant/policy,
dependency-resolution, migration or readiness proof. Continue the whole NuGet
and remaining-format journeys after the adapter and storage work lands.

## Remaining offload inventory and execution order

The accepted milestone unblocks the complete product build. Extend real CI
journeys as their corresponding implementation lands; do not spend the entire
build polishing CI while required customer outcomes remain missing.

| Priority / work | GitHub environment and input | Evidence boundary |
| --- | --- | --- |
| Next product journeys: remaining Stage1 clients, other-format lifecycle and repository breadth | Actual Linux architectures and stock Docker/Podman/Helm, JVM clients and later ecosystem clients as implemented; real restricted PostgreSQL and exact package graphs | Publish/install with dependencies, policy/auth denial, current metadata, interruption/restart, deletion/restore. ORAS alone does not qualify every OCI client; raw download does not qualify another format. |
| Pinned public OCI retrieval (`conformance_public_oci.py`) | Separate manual/scheduled Linux campaign; reviewed immutable digest and official HTTPS registry/realm/delivery authorities | One real provider/digest path. Never execute the image; keep a changing external service separate from deterministic PR gates. |
| Longer parser/property/differential campaigns | Native scheduled/manual jobs, reviewed corpora, explicit time/concurrency/memory budgets and minimized failure review | Persist target inventory, seed/corpus identity, versions, results and limits. The five-second smoke is not full coverage; raw generated corpus is not automatically safe to publish. |
| Complete dependency/image/artifact analysis | Pinned Trivy or equivalent with feed provenance/age; source and binary tools continue; scan shipped images when built | Separate source, binary, image, reachability and feed coverage. Missing intelligence never means clean. Full security gate stays negative until its complete campaign exists. |
| Packaging, Compose/Helm and disconnected bundle | Real Docker/Podman/cluster/chart clients on both Linux architectures; shipped pinned artifacts and actual network-isolated target | Fresh install, persistent data, readiness, upgrade/recovery, trust and actual offline contents. Rendering or download links are not an installed/offline result. |
| S3, IdP, scanner and other service adapters | Disposable real compatible services with pinned versions, isolated tenants, fault boundaries and explicit limits | Named adapter outcomes only; stand-ins do not qualify every vendor, customer PKI or production topology. |
| Native Windows and additional macOS journeys | Published native runners, platform-specific private-file/ACL behavior, actual CLI/package clients and real supported services | Cross-builds and Linux containers do not replace native execution. Keep unsupported server/runtime cases explicit. |
| Release evidence, SBOM, signatures and offline verification | Build once per target, hash exact bytes, generate/verify SPDX/CycloneDX/provenance and scoped trust material | No automatic publication. Signing identity and legal/distribution authority remain explicit. Signatures prove signed statement integrity, not an unobserved external effect. |
| Migration, replication, backup/restore, federation and fault recovery | Real compatible source/destination services, bounded datasets and controlled process/network/storage faults | Complete metadata/identity/policy/byte inventories and recovery receipts. One-host smoke is separate from independent-host HA and customer cutover. |
| Standard/large profiles,24hsoak and operating cost | Sized independent hosts, real PostgreSQL/object-store/network topology, scheduled/manual resource budgets and raw measurements | Ordinary shared runners do not establish the specified8vCPU/32GiB profile, independent-host HA or24hqualification. Retain unfavorable observations. |
| Licensed paid comparisons and customer acceptance | Authorized licensed Nexus/JFrog systems and explicit customer/owner environment | External license, access and authority remain real inputs; CI cannot manufacture them. Continue independent implementation while these are unavailable. |

For every new format, backend, schema, platform or release surface, update the
workflow, placement plan and capability/journey evidence together. Identify the
real client/service/host, credentials/data exposed, reproducible fixture, safe
failure diagnosis, runtime/cost budget and exact unfinished acceptance rows.
Add scheduled/manual long campaigns with an explicit cadence and owner-approved
infrastructure; never hide an unimplemented gate behind a successful skip.

Once stable, required PR checks can be enforced under a separate authorized
repository-settings change. Repository protection, release publication and
customer maintenance are not consequences of a green CI run.

## Current native qualification checkpoint

All17jobs pass on clean 6854e80: main9, controlled-upgrades2, nativeOCI2,
repair1with5fresh journeys, retention1with5fresh journeys and NuGet2.
Both real PostgreSQL race gates pass. All14x86Chromium workflows have zero
unexpected, skipped or flaky results. Every runtime binary embeds the clean
exact native source, and both upgrade campaigns rebuild10pinned old servers
and pass15reports. See [the accepted milestone](../../evidence/2026-11-03/github-6854e80-checkpoint.json).

Both native Docker/Podman/Helm journeys complete214checks, including exact
layered/multiarch bytes and chart dependencies across hosted/proxy/group,
tenant/policy/lifecycle and grant/token revocation/restart. The earlier tar
observation and tenant-access fixture failures remain retained with their
original diagnosis limits. No missing old status or file attributes are
retroactively inferred. Native macOS source/CMS regressions pass too.

Both actual SDK10.0.403 Versioning/Packaging7.9.0.0 references agree with Go on
all1,129versions,11Nuspec documents and4owned ZIP32 archive cases per native Linux architecture. This
replays the raw-ID-whitespace repair. See [the library checkpoint](../../evidence/2026-11-03/nuget-6854e80-checkpoint.json).
Archive/feed/client and full NuGet behavior remain required.

The NuGet workflow now also compares four owned stored/deflated ZIP32 archives
with actual `PackageArchiveReader`: identity, selected Nuspec path and exact
UTF8/UTF16 manifest bytes. Local bounded archive/race/fuzz checks pass; managed
compilation and all four archive comparisons pass on both actual native architectures. Malformed archive
regressions run against production Go code without exposing the SDK to generated
hostile packages. No uploaded content executes. See [the archive boundary](../adr/0034-bounded-nuget-archives.md).

All four database workflows now explicitly bind127.0.0.1:35432. Bootstrap
receives the exact owned service container ID and checks Docker's actual port
map before setup. It fails outside a GitHub-hosted runner. Local contract/workflow checks and the actual mandatory preflight pass across
main/OCI/upgrades/browser campaigns on6854e80. Fixed markers and private-log
hashes are retained in [the binding replay](../../evidence/2026-11-03/ci-service-bindings-6854e80-replay.json).
The old three omitted bind addresses remain a configuration observation,
not an observed exposure or incident. Continue product implementation and
the remaining offload inventory above; all450capabilities and negative broad
readiness verdicts remain.

The NuGet library workflow is further extended with63,516owned ID cases,
covering all non-surrogate BMP values plus whole-ID edge cases. The actual SDK
validator and invariant casing are compared with the bounded Go wire-key path;
explicit transport exclusions retain the SDK's separate acceptance result.
The b259472 managed/native comparison passes on both Linux architectures.
Complete durable NuGet feed and stock-client journeys follow this coordinate work; the library gate
does not replace them. See [the ID contract](../adr/0035-nuget-id-lookup-keys.md).

The first actual fba38fd ID comparison compiled and executed on both native
architectures, then failed40cases. The repair freezes named Unicode-derived
word/case tables rather than inheriting Go17 data. The local complete-row hash
matches both retained SDK outputs on the unchanged63,516case corpus. The fresh
clean b259472 native replay also passes both architectures; preserve [the original failures](../../evidence/2026-11-03/nuget-fba38fd-id-unicode-failure.json).

Hosted NuGet implementation now extends the existing native `conformance.py all`
campaign with actual SDK dotnet push and dependency restore, not local x86
emulation. Two application versions and a dependency use fresh consumer caches,
exact package/payload/manifest comparisons, same-coordinate tenants, policy denial
and a real registry restart. Owned fixtures contain no scripts/build targets or
executable assemblies. Real PostgreSQL integration/race adds common publication,
concurrent coordinates, grants/revocation, bounded complete indexes and reference
restore. Safe summaries retain only bounded SDK identity and four fixture hashes,
beside exact native server/CLI source and binary hashes. Both actual native dfc9381 jobs pass the new PostgreSQL/race and stock dotnet
journeys; SDK10.0.403 and exact source/client/fixture identities are retained.
The existing library results keep their own distinct scope.
See [the adapter decision](../adr/0036-hosted-nuget-publication.md).

The next console candidate adds a dedicated NuGet operator workflow, increasing
the complete browser gate from 14 to 15 tests. It exercises restricted hosted
creation, private client templates, original package/manifest bytes, exact-digest
review, holds/delete/restore, grant revocation and named accessibility states on
real PostgreSQL and Chromium. Focused `nuget` selection can repeat the journey
five times with fresh databases on GitHub x86. Syntax/discovery passes locally;
no new browser execution is claimed. Existing 14-test results retain their source
and scope. See [development evidence](../../evidence/2026-11-03/nuget-browser-development.json).

The dfc9381 hosted checkpoint accepts 14 exact-source jobs: main9, OCI2,
upgrades2 and five-fresh repair1. It does not include a new library or fresh
retention run. Both actual SDK10.0.403 client campaigns pass 406 total checks
including new hosted NuGet. All eight safe summaries and native identities are
retained in [the checkpoint](../../evidence/2026-11-03/github-dfc9381-checkpoint.json).
No NuGet-specific Chromium result is present on that source; the next candidate
adds it to the 15-workflow console and explicit focused five-fresh replay.
