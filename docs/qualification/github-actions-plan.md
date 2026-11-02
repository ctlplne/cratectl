# GitHub Actions qualification plan

Updated: 2026-11-02. Owner: `imfeelingtheagi`. Source of scope: `GOAL.md`,
`docs/qualification/remaining.json`, and the capability and journey ledgers.
This plan tracks where qualification should run; it does not mark an unfinished
capability complete. The owner resumed the complete product goal on 2026-11-02.

## Placement rule

Run each test where its claim can actually be observed. Use native GitHub-hosted
Linux x86-64 and ARM64, macOS ARM64, and Windows runners for OS behavior. Use
disposable PostgreSQL and actual stock clients for state and protocol journeys.
Use real compatible object stores, identity providers, scanners, registries and
network topologies when those capabilities are implemented. A container on one
runner is a useful service stand-in, but does not prove independent-host HA,
native Windows/macOS behavior, production PKI, or a customer's environment.
Cross-compilation proves only compilation. A skipped test is never a pass.

CI is an independent, repeatable candidate check. It never migrates the retained
local primary, reads customer data, imports `.private/` or `.cache/`, or promotes
an artifact. Each run records its commit, architecture, tool and service versions,
fixture topology, assertions, defects, and limits. Generated credentials and raw
private logs remain on the disposable runner; a field-allowlisted summary of
generated evidence is retained as a GitHub artifact for 30 days. A reviewed subset
may then be committed under `evidence/` with its exact candidate and limits.
Required checks must fail closed if a dependency or
fixture is missing. PR jobs have a read-only token and no secrets. Publication,
signing identity, and release gates require their own explicit design and authority.

## Current implementation

`.github/workflows/ci.yml` runs on pushes to `main`, pull requests, and manual
dispatch. It currently contains:

| Gate | Actual runner or stand-in | Scope |
| --- | --- | --- |
| Source and unit | Ubuntu 24.04 x86-64 and ARM64; macOS 15 ARM64 | Go build, unit and race tests, vet, architecture and API checks, web build reproduction, npm dependency audit. |
| Bounded Go fuzz | The same three native runner types | All 23 targets passed five-second budgets on native Linux x86-64, Linux ARM64 and macOS ARM64 for `7389def`. That overall run failed at the separate browser gate. This is a crash smoke check, not the full parser/security campaign. |
| Security slice | Ubuntu 24.04 x86-64 | `govulncheck` on Go source and two binaries; Gitleaks on current tracked bytes and reachable history; synthetic exception regression. |
| Native integration | Ubuntu 24.04 x86-64 and ARM64, PostgreSQL 16.15 service with restricted runtime role | `make integration`, including real database tests and SQL timing. The added `make integration-race` gate awaits its first GitHub run. |
| Native clients and operations | Same native Linux jobs, fresh registry on loopback | Generic, OCI/ORAS, Maven, npm, PyPI, current lifecycle, blank TLS install, jobs/leases, inventory/sweeps and cross-reference matters; Chromium console/Axe on x86-64. All six jobs passed on `998c7f8`. |
| Focused repair-browser regression | Separate Ubuntu 24.04 x86-64 runner with real PostgreSQL and Chromium | Campaigns failed; early focus/Axe labels were unreliable because source snippets were classified. The corrected harness avoids Chromium response-body reads across navigation and records error headers/phases. Live replay remains required. Full console still requires 14 workflows. |

The [first run](https://github.com/ctlplne/cratectl/actions/runs/41491829202)
passed five of six jobs. The x86-64 browser step failed after its PostgreSQL and
stock-client stages passed; see `evidence/2026-11-02/github-ci-first-run.json`.
The [second run](https://github.com/ctlplne/cratectl/actions/runs/41495587980)
passed all six jobs, including Chromium; see `evidence/2026-11-02/github-ci-second-run.json`.
The [third run](https://github.com/ctlplne/cratectl/actions/runs/41498257132)
passed both Linux fuzz gates and the complete ARM64 native job. Its x86 Chromium
job failed again, identifying the repair creation/source transition. Both macOS
jobs remained queued at observation. The security summary also omitted a
regenerated tracked report; the exporter now includes modified tracked reports
and rejects empty successful summaries. Both defects require live replay. See
`evidence/2026-11-02/github-ci-third-run.json` and `DEFECT.0071`/`DEFECT.0072`.
The `1678ed5` replay passed all nine main jobs and both controlled-upgrade jobs;
see `evidence/2026-11-02/github-ci-1678ed5-checkpoint.json`. The security artifact
contains all 324 passed cases. The earlier browser failures remain unexplained,
so the separate fresh-database repair replay is still required.
The `make security` and `make packaging` targets intentionally still fail: their
full campaigns are incomplete. Dependabot proposes Go, npm and Actions updates;
the CI matrix must validate each proposal.

## Additional work to move off this Mac

Priority means sequencing, not permission to omit a goal requirement. Each row
needs a green run on the named runner and a linked, scope-limited evidence record.

| Priority | Work and existing driver | CI environment and prerequisite | Acceptance boundary |
| --- | --- | --- | --- |
| Now | Blank native TLS install (`conformance_installation.py`) | Native Linux with fresh PostgreSQL, stock npm and generated local CA; use isolated database | Fresh install, trusted TLS, lock interruption and first publish/deny; not production PKI or packaged install. |
| Now | Jobs, upload leases, inventory, integrity sweeps (`conformance_jobs.py`, `conformance_leases.py`, `conformance_inventory.py`, `conformance_sweeps.py`) | Native Linux x86-64 and ARM64, real processes, fresh PostgreSQL and filesystem | Process death, durable retry, held transfer and exact bytes; one host and filesystem only. |
| Now | Cross-reference hold matters (`conformance_hold_matters.py`) | Same native Linux runners, stock ORAS, isolated database and actual timing faults | Current schema and named legal-hold cases; broader policy and physical GC remain open. |
| Now | Secret-rule regression (`test_secret_rules.py`) | Security job's pinned native Gitleaks binary; synthetic fixtures only | Narrow exceptions detect credential-shaped counterexamples in both directory and Git modes. |
| Passed in named scope | Schema and retained-version upgrades (`conformance_schema.py`, `conformance_lifecycle.py`, `conformance_repairs.py`, `conformance_schedules.py`, `conformance_retention.py`, `conformance_retention_schedules.py`) | `upgrade-qualification.yml` rebuilt all ten sources in `upgrade-baselines.json` and passed 15 reports on each native Linux architecture for `1678ed5`; see `github-controlled-upgrades-checkpoint.json`. | Controlled migration and recovery for named old/new pairs; no rolling-version, downgrade, backup/restore or primary-database claim. |
| Next | Pinned external OCI retrieval (`conformance_public_oci.py`) | Separate scheduled/manual Linux job with approved immutable digest, HTTPS authorities and source document; hold network fixtures stable | One actual provider/digest path. Do not turn a changing public service into an unqualified PR gate. |
| Next | Deeper Go fuzz and parser/property campaigns | Extend the bounded native smoke job with reviewed corpora, longer scheduled budgets, differential/property tests and failure minimization; retain minimized corpus only after review | Only exercised parser boundaries; failure/timeout and corpus identity recorded. |
| Next | Source/image/binary dependency and secret analysis | Pinned Trivy or equivalent with feed timestamp; `govulncheck`, npm audit and Gitleaks continue; scan built images when images exist | Distinguish source, binary, image and feed coverage. A clean source scan is not a clean image or malware verdict. |
| When built | Docker/Podman OCI journeys and Compose/Helm/package/offline installer gates | GitHub Linux x86-64 and ARM64 with real engines and chart clients; validate shipped, pinned images and manifests. Network-isolated target for the actual offline bundle. | Actual package/install/upgrade/restore behavior; `make packaging` becomes green only when the full release packaging campaign exists. |
| When built | S3, scanner, identity, replication, migration and failure modes | Disposable compatible services and real stock clients; enforce pinned versions, separate tenant state and fault boundaries | A stand-in proves its named integration only. Independent hosts or paid comparator licenses remain separate gates. |
| When built | Native Windows CLI, private-file ACLs and package clients; macOS native client/browser work | GitHub Windows and macOS runners with stock OS tools, real services and OS-specific assertions | Linux containers and cross-builds cannot substitute for these native results. |
| When built | SBOM, signatures, provenance, offline verification, release and supply-chain evidence | Build once per target architecture, hash artifacts, generate/verify SPDX and CycloneDX, sign and independently verify with scoped identity; no automatic publish | Signed statement integrity and reproducible artifact identity, not unobserved external effects or legal release approval. |
| Later | Standard/large profile, multi-host HA, restore, 24-hour soak and cost | Dedicated, sized independent hosts and real database/object-store/network topology; scheduled/manual campaigns with budgets and retained raw measurements | GitHub's ordinary shared runner is not the specified 8-vCPU/32-GiB standard profile or independent-host large profile. Label smaller smoke runs accordingly. |
| External | Licensed Nexus/JFrog hands-on comparison, customer PKI/IdP/upgrade, owner-approved Additional Use Grant | Licensed benchmark systems or explicit owner/customer environment | Keep these blocked inputs visible; CI cannot create authority or evidence it does not possess. |

## Execution order and design checks

1. Diagnose and repair the recurring x86 repair-browser failure using safe
   matcher names and precise source locations. Replay the actual journey on
   GitHub; later green runs alone do not explain an earlier failure.
2. Validate the evidence exporter repair against the actual same-date tracked
   security report. The `1678ed5` GitHub artifact now contains all 324 passed
   cases; see `github-ci-1678ed5-security-summary.json`.
3. Keep the now-passing macOS source/fuzz gates in the native matrix. The
   five-second target budget is a smoke test, not full parser qualification.
4. Run `Controlled upgrade qualification` on both Linux architectures. It rebuilds
   the ten pinned historical sources and exercises legacy adoption, schema 2–10
   lifecycle upgrades, repair, recurring integrity and retirement. Missing or
   dirty sources, wrong native architecture and mismatched identities fail.
   This campaign passed on `1678ed5`; continue its regression gate as schema
   and lifecycle behavior change.
5. Add OS and integration matrices when the corresponding implementation and
   fixtures exist. Put long/fault/paid/external campaigns on explicit scheduled
   or manual workflows and document their cadence, cost, and inputs.
6. Add release artifact generation and independent verification only after
   packaging, license text, trust and approval requirements are resolved. No CI
   success alone changes readiness or publishes a release.
7. Once the matrix is stable, make its required PR checks enforceable on `main`
   under a separate owner-authorized repository settings change. Avoid making
   unfinished `make security` or `make packaging` appear green through skips.

Review on each new format, backend, platform, schema, or release surface: which
real client/service/host proves it; what data and credentials the runner sees;
whether the fixture is reproducible; whether a failure can be diagnosed from
safe retained evidence; and which `remaining.json` capability or journey still
needs evidence. Update this plan, CI workflow and ledgers together.
