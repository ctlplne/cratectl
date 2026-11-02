# cratectl product build and qualification goal

- Owner: imfeelingtheagi
- Product: cratectl, a ctlplne studio product
- Workspace: /Users/shankar/Desktop/ctlplne-cratectl
- Created: 2026-10-28
- Updated: 2026-10-28
- GitHub: https://github.com/ctlplne/cratectl
- Origin: https://github.com/ctlplne/cratectl.git
- Branch: main
- Visibility: Public by owner direction on 2026-11-02; CI publication is authorized for this repository.
- Status: Execution contract for the active build. Resume the existing implementation when instructed.

## Owner-directed history reset (2026-10-28)

The owner explicitly authorized deleting/recreating the private GitHub repository
and resetting local Git history while preserving the implementation. This reset
supersedes the prior prohibition only for that operation. Git author and committer
must be `imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`.
The prior commit anchors below belong to archived history. Fresh qualification
must identify the new history's actual source commit. All product scope remains.
See `evidence/2026-10-28/history-reset.json`.

## 0 Resume the existing repository

The local repository and ctlplne/cratectl GitHub repository already exist. The owner authorized public visibility on 2026-11-02. The local origin points to the URL above. Continue on main; do not initialize another repository, replace origin, create a branch, reset history, or overwrite in-progress work.

Read AGENTS.md, this goal, STATUS.md, and docs/qualification/remaining.json before continuing. Then inspect the actual Git status, current commit, capability and journey ledgers, active jobs and owned resources. The current checkout and reproducible evidence determine progress. Treat stale prose as a lead to reconcile, not as permission to repeat completed setup or invent a pass.

The recorded starting commit is fa727a9. The contract checkpoint observed during this update is 2a3347b. These are historical anchors, not the current candidate for every future run; record the actual commit and artifact digests each time. Architecture, threat-model and qualification records have been started, and foundation implementation is in progress. Existing source files and conformance records do not by themselves establish verified capability.

Preserve existing tracked changes, untracked implementation, evidence, ignored .private/ credentials and .cache/ state. Reuse the current matrices and close their gaps instead of regenerating the project or replacing the backlog. The immediate work is to complete the Stage 1 native-client journeys and tenant-scoped durable publication against real PostgreSQL, guided by the live remaining-work record. All later stages remain committed scope.

The agent is authorized to make focused local commits on main. The owner authorized the 2026-11-02 CI push and public visibility change. Future pushes, releases, package/image publication and other remote configuration changes remain owner controlled. Local commits must remain possible without GitHub connectivity. If remote authentication fails, continue authorized local work and report the precise remote action that needs attention.

## 1 Mission and ambition

Build cratectl into an excellent, self-hosted artifact repository and software supply-chain control plane. An artifact is a packaged piece of software: a container image, library, operating-system package, model, installer, or release bundle. cratectl must let customers store, retrieve, inspect, govern, promote, replicate, distribute, and retire those artifacts using the clients they already use.

The ambition is functional parity with the relevant paid, self-managed Nexus Repository and JFrog offerings, followed by demonstrated improvements in operator effort, security, portability, deployment simplicity, performance, and operating cost. A basic registry, a working upload endpoint, a polished demo, or a list of planned integrations does not meet this goal.

Build complete customer outcomes. A developer must be able to publish a package, another machine must install it through an ordinary package client, policy must govern the exact bytes served, an operator must explain and recover failures, and a customer must be able to migrate into and out of cratectl.

Use staged implementation to control dependencies. Stages do not reduce the destination to an MVP. The first working formats establish reusable foundations; the remaining committed scope remains required. Do not relabel a missing incumbent capability as unnecessary to declare parity.

All explanations, UI copy, documentation, and reports must be deeply technical and ELI5: explain the actual mechanism in plain language, define unfamiliar terms, and make the operator's next action clear.

## 2 Business model and the free core

The core is source-available under BUSL-1.1, free for the production uses authorized by its Additional Use Grant, with each release converting to MPL-2.0 four years after publication. Client SDKs and protocol integration libraries should use the studio's MPL-2.0 client model. Reuse the owner's approved ctlplne licensing structure and record the exact cratectl grant before distribution. Pending final legal text does not block local engineering.

The product strategy is to make the complete production workflow freely operable, including capabilities incumbents place in commercial editions. The baseline parity scope in this goal belongs in core.

In particular, do not license-gate package formats, normal publishing and consumption, identity-provider integration, RBAC, tenant isolation, audit and export rights, policy enforcement, scanning integrations, quarantine, staging and promotion, signatures and attestations, replication, HA, recovery, migration, or disconnected operation.

Do not impose license caps on users, tenants, repositories, components, package versions, requests, transfers, storage, or connected source volume. Resource quotas, admission control, and bounded queues are required safety controls; operators configure them for their infrastructure. A safety control must never disguise an edition limit.

Do not require a vendor account, trial key, hosted control plane, remote entitlement check, usage export, or telemetry consent to run core. Core must install, restart, upgrade, serve artifacts, and recover with the vendor unavailable.

Commercial revenue can come from support, long-term maintenance, migration assistance, managed operation, and genuinely additional Enterprise services. Optional commercial code belongs under ee/. Core must not import ee/ except for narrowly defined, build-tagged attach seams with core-only twins. A core-only build must compile and execute the entire baseline without linking ee/. Any future commercial feature must describe its additional customer outcome; it cannot reclaim a baseline capability from core.

Offline commercial license verification, when commercial features exist, uses local signatures and fails without disabling core. Do not build an elaborate commercial portal before the repository workflow works.

Do not copy proprietary vendor code, private detection rules, licensed intelligence, customer data, or unsupported internal interfaces. Build original functional equivalents and use dependencies and feeds under their applicable terms. BSL is a licensing choice; it is not a substitute for product quality.

## 3 Competitive baseline and parity accounting

Benchmark the relevant self-managed products, not only their free editions:

- Sonatype Nexus Repository Community, Pro, and Pro+, including Repository Firewall and the documented role of connected IQ services.
- JFrog Artifactory paid self-managed editions, with Xray, applicable Advanced Security capabilities, Federation, Distribution and edge delivery, build metadata, evidence, and AppTrust release governance.
- Harbor and Pulp as strong free alternatives. An incumbent license price does not establish differentiation over an existing free implementation.

Use current official documentation and exact available versions when execution begins. The source list in section 23 seeds the work; refresh it before asserting current coverage. Historical feature names and discontinued products must not silently stand in for their successors. Do not clone an incumbent UI or internal topology; achieve equivalent or better customer outcomes.

Create a machine-readable parity matrix before substantial implementation. Every row must identify:

- A stable capability ID, customer job, incumbent product and edition, source URL, observation date, and version where known.
- The exact behavior and relevant protocol operation. Split hosted, proxy, group, replication, search, authorization, and lifecycle support rather than hiding them in one checkbox.
- cratectl's implementation, UI/CLI/API surfaces, core ownership, dependencies, and acceptance journey.
- Required stock clients and versions, test data, permission and tenancy cases, success and failure evidence.
- State: planned, implementing, implemented but unverified, verified, blocked by an external input, or superseded by an explicitly equivalent outcome.
- Candidate commit/image identity, evidence path, limits of the result, and next action.

An implementation label is not a verification result. Library code, mock responses, a generic file store, a screenshot, or an advertised route is not proof that a native package client can complete its workflow.

Maintain the union of relevant documented capabilities as the committed backlog. Identify contradictory vendor documentation rather than guessing. An externally blocked benchmark comparison is separate from cratectl's implementation status. Lack of a paid competitor license can block a hands-on comparison; it does not block implementing a documented workflow with stock clients.

Only the owner can remove committed scope. A capability with no equivalent must remain visibly open. An alternative design counts as parity only when its end-to-end operator outcome is demonstrated.

## 4 Scope and product boundaries

cratectl owns artifact contents, coordinates, versions, repository metadata, provenance, dependency and build relationships, policy decisions, release state, distribution, and repository operations.

Keep trstctl and probectl independent:

- trstctl may supply signing or machine credentials through an optional integration. cratectl must also work with standard identity providers, signing tools, and customer-managed trust without trstctl.
- probectl may observe connectivity and service health. cratectl must expose usable native health, metrics, logs, and job evidence without probectl.
- A missing sibling product must not remove baseline capability.
- Do not edit, start, stop, migrate, or clean up either sibling workspace or its services for this project.

Build the repository and its control plane. Deploying arbitrary business applications, replacing a general CI runner, operating a full endpoint-security suite, and becoming a general-purpose data warehouse are separate products. The repository still needs build-system integrations, scanner execution, release delivery, and complete operational automation within its own scope.

## 5 Required repository behavior

Support hosted repositories for customer-published packages, proxy repositories that retrieve from configured upstreams, and group or virtual repositories that provide one client endpoint over a controlled set of sources. Implement the modes each format actually supports; record native limitations explicitly.

Repository behavior must include:

- Correct package coordinates, version rules, metadata, indexes, dependency resolution, search, and native authentication.
- Streaming and resumable transfer where the protocol allows it, correct HTTP range and conditional requests, checksums, ETags, error codes, and cancellation.
- Per-format immutability and redeployment rules. Blobs are immutable; mutable tags and indexes follow native semantics with versioned, authorized changes. Maven snapshots and npm dist-tags must work correctly.
- Repository templates, properties, labels, owners, import/export, access selectors, and search across authorized content.
- Configured source precedence, upstream allowlists, namespace ownership, dependency-confusion controls, and explicit fallback policy.
- Cache freshness, conditional refresh, negative caching, stale-content policy, upstream outage behavior, and operator-visible revalidation.
- Lifecycle policies for retention, legal or operator holds, archive/restore, storage tiers, safe deletion, repair, and garbage collection.
- Bulk operations with preview, progress, cancellation semantics, retry, partial results, and durable operation IDs.
- Native client configuration snippets that are copyable, scoped, secure, and explain the permissions granted.

A proxy miss is a governed upstream retrieval, not permission to bypass the configured source, scan state, or tenant. A group endpoint must not expose content its requester could not obtain from its underlying repositories.

## 6 Package and artifact compatibility

Build a format and operation matrix from the union of current Nexus and Artifactory documentation. The following is the starting inventory, not a permission to omit newly identified relevant formats:

| Family | Initial required clients and semantics |
| --- | --- |
| Containers and OCI | Docker, Podman, ORAS, build tools; OCI Distribution, manifests, indexes, multi-architecture images, layers, referrers, signatures, SBOM attachments, Helm OCI |
| JVM | Maven, Gradle, Ivy, SBT; releases, snapshots, classifiers, parent POMs, checksums, metadata and repository grouping |
| JavaScript | npm, pnpm, Yarn; scopes, lockfiles, publishing, dist-tags, integrity, metadata and upstream fallback policy |
| Python | pip, uv, twine; simple indexes, wheels, source distributions, normalized names, hashes, metadata, yanking and applicable modern index standards |
| .NET | NuGet and dotnet; feeds, packages, symbols where supported, push authentication and search |
| Go | Go module clients; proxy protocol, versions, pseudo-versions, private modules, checksum behavior and explicit public-service dependencies |
| Rust | Cargo; sparse indexes and any required legacy behavior, publishing, ownership, yanking, checksums and registry authentication |
| Linux | APT/Debian, RPM/Yum/DNF, Alpine/APK, and opkg; signed metadata, repository indexes, architectures, suites, distributions and offline installation |
| Kubernetes | Helm HTTP repositories and OCI charts; chart indexes, provenance and dependency retrieval |
| C and C++ | Conan and applicable versions, including revisions, metadata, binaries and native client workflows |
| PHP | Composer; package metadata, distributions, authentication and proxying |
| Ruby | RubyGems and Bundler; indexes, gems and dependency resolution |
| Scientific packages | Conda, R/CRAN; platform-specific metadata, dependency selection and native installation |
| Apple platforms | CocoaPods and Swift package registries; toolchain-appropriate publication and resolution |
| Dart | Pub and Flutter package clients |
| Infrastructure and automation | Terraform/OpenTofu module and provider registries, state-backend parity where benchmarked, Ansible/Galaxy, Chef, Puppet and Vagrant |
| Additional ecosystems | Eclipse p2, Bower, Hex, Bazel modules, Git LFS and relevant editor-extension/package feeds found in the current baseline |
| Models and datasets | Hugging Face-style model and dataset workflows, revisions, large-file handling, gating, provenance and ordinary client consumption |
| Generic artifacts | Arbitrary files and installers, immutable digests, metadata, access policy and controlled distribution |
| AI and agent packages | Current documented agent-plugin and AI-editor package formats; distribute and govern the packages without silently executing their contents |

Create separate rows for equivalent names and shared underlying protocols so format counts cannot inflate coverage. A generic download route is not native support for npm, PyPI, Maven, OCI, or another ecosystem.

For every supported format, publish and consume a nontrivial package with dependencies using stock clients. Exercise supported hosted/proxy/group modes, private and public sources, version updates, concurrency, retries, interrupted transfer, cache refresh, authorization failures, tenant collisions, deletion and restore, restart, and policy denial.

For OS-native or licensed clients unavailable on the current host, complete independent implementation and conformance work, then record the exact external runtime needed. Containerized Linux does not qualify native Windows or macOS behavior.

## 7 Software supply-chain security

Ship a coherent intake and release security workflow in core:

1. Identify the exact package and immutable bytes being assessed.
2. Discover and normalize dependencies and available source/build provenance.
3. Generate or ingest SPDX and CycloneDX SBOMs and standard vulnerability statements such as VEX.
4. Evaluate signatures, trusted publishers, provenance, vulnerabilities, license obligations, configured age and maturity rules, namespace ownership, and malicious-content signals.
5. Quarantine, allow, deny, or require review under an explicit policy.
6. Bind the decision to the artifact digest, policy version, intelligence snapshot, and evidence.
7. Re-evaluate affected artifacts when policy or intelligence changes.
8. Enforce the resulting state across download, promotion, group endpoints, direct links, cache paths, replication and export.

Use maintained scanning engines where suitable, with pinned versions, sandboxed workers, resource budgets, provenance, and an adapter contract. Do not build a superficial scanner merely to own every line of code.

Provide dependency graph and reverse-impact queries, vulnerability and license-policy results, reachability/exploitability information where the evidence supports it, false-positive handling, scoped time-limited waivers, rescanning, remediation guidance, and owner notification. Distinguish package-level findings from application-specific exploitability. Do not label an absent scanner result as clean.

Intelligence updates must be importable offline with authenticated manifests, versions, timestamps, provenance and rollback protection. Expose feed age, missing ecosystems, licensing requirements, and the policy for stale or unavailable intelligence. A scanner integration without its required database is not an air-gapped scanning result.

Compare against Nexus Firewall and relevant Xray/Advanced Security outcomes, including vulnerability, malicious package, secret, license, provenance and applicable code-analysis capabilities. Maintain separate rows for capabilities requiring a maintained commercial intelligence source, trained detector, build context, or external evidence. Free public feeds do not establish equivalent detection coverage.

Use a labeled, legally usable corpus and independently grounded expected results to measure false positives, false negatives, freshness, coverage and resource use. Use benign fixtures or safely contained test strings for dangerous-content journeys. Do not download or execute live malware to improve a demonstration.

Block arbitrary package scripts and model deserialization from running in the registry process. Any analysis that genuinely requires execution belongs in a separately isolated, disposable environment with explicit authority.

## 8 Build provenance and release governance

Treat a build and an application release as first-class objects. Record the exact source revision, build identity, dependencies, outputs, digests, environment metadata and associated attestations without collecting secrets.

Support standard CI integrations and machine identities, build-info ingestion, dependency/build graphs, signed evidence, and verification using ordinary tools. Support Sigstore/Cosign/Notation and relevant in-toto/SLSA and package-signing workflows through a defined crypto/trust boundary. Private trust roots and offline verification must work.

A release is an immutable manifest of exact artifacts and required evidence. Support stages, approvals, policy gates, separation of duties, expiring waivers, promotion, rollback to a prior permitted release, and continued monitoring after release. Re-check authorization and relevant policy at execution, not only at preview.

Promoting a release must preserve its bytes and evidence. Rebinding tags or copying metadata is not sufficient proof. Report pending, denied, failed, partially distributed and verified-complete states distinctly.

Implement controlled distribution to remote and disconnected sites, with signed manifests, resumable transfer, integrity verification, destination acknowledgments, bandwidth limits, staged rollout, and clear revocation or withdrawal semantics. A destination receipt proves receipt or publication at that destination; it does not prove that an already downloaded copy stopped executing.

Include equivalent outcomes to applicable AppTrust, evidence-management and Distribution/edge workflows in the parity matrix. Incumbent packaging across multiple products does not remove the workflow from scope.

## 9 Architecture and durable state

Start from these defaults and record their rationale in architecture decision records before significant implementation:

- Go services and workers using a currently supported, pinned stable toolchain.
- PostgreSQL for durable control state, tenant isolation, operation records, the event journal and job/outbox coordination.
- S3-compatible object storage for production artifact bytes, with local filesystem storage for supported single-node evaluation and explicitly qualified deployments.
- React, TypeScript and Vite for the console, using the ctlplne family design language and accessible components.
- OpenAPI-described management APIs, a maintained CLI, declarative configuration and automation interfaces.
- A typed format-adapter interface and bounded worker contracts. Protocol adapters must not fork authorization, storage integrity, audit or policy implementations.
- Control, transfer, indexing, scanning, migration, replication and maintenance workloads separated by bounded queues and resource budgets.

Keep the initial dependency set deliberate. Do not introduce Redis, a second metadata database, a message broker, an external search engine, or a Kubernetes requirement simply because an incumbent has one. Add infrastructure only after an architecture record demonstrates the requirement and its recovery, isolation, licensing and operating consequences. Do not sacrifice required product outcomes to avoid a justified dependency.

Use an append-only transactional event journal for authoritative state changes. The default is a PostgreSQL journal whose mutation event, idempotency record, and external-work intent commit together. Build read/search projections from committed events. If another event transport is selected, prove atomic handoff and replay; do not invent a distributed transaction between storage systems.

Artifact bytes and metadata need an explicit publication protocol:

- Stream into a staged object under a bounded upload lease.
- Verify declared length, format-required metadata and digests.
- Confirm durable object storage before publishing references.
- Commit the publication event and authoritative reference transition atomically in PostgreSQL.
- Build indexes and other projections from that event.
- Reconcile crashes and abandoned uploads without deleting referenced, leased or concurrently published content.

Do not acknowledge publication when the bytes exist only in RAM, in an uncommitted multipart upload, or on a worker-local temporary disk that cannot survive the promised failure.

Design concurrency using explicit object versions, compare-and-swap or equivalent transactions, lease fencing and first-writer rules. Exercise races between publish, tag changes, policy updates, scans, quarantine, replication, cleanup and restore.

Search and inventory are projections. A failed indexer must not produce unauthorized downloads or claim an artifact never existed. Expose projection lag and rebuild state.

## 10 Security and tenant boundaries

Tenant isolation is a storage and service boundary from the first migration. PostgreSQL tables, queries, jobs, events, object references, cache keys, search indexes, scan results, tokens and distribution records must carry and enforce tenant scope. RLS or an equivalently proven storage boundary must prevent an omitted application check from exposing another tenant.

Use tenant-scoped storage namespaces and deduplication by default. A content hash must not become a cross-tenant existence oracle. Cross-tenant deduplication requires an explicit design and side-channel tests before it can be enabled.

Enforce authorization on package metadata, search, manifests, layers, checksums, SBOMs, build graphs, tags, signatures, direct download URLs and every management operation. Unauthorized metadata can expose a private package even when the blob endpoint refuses access.

Provide OIDC/SAML, LDAP where required for parity, SCIM, local emergency access, MFA/passkey options where applicable, scoped service identities and tokens, expiry, rotation, revocation and narrow repository/content permissions. Keep browser sessions and native package-client credentials distinct where their semantics differ.

Provider administration is a separate privilege domain. An administrator must not gain silent access to tenant artifact contents. Exceptional access needs explicit authority, a deadline and a separate audit trail.

All cryptographic primitives, including streaming hashes and signature verification, route through internal/crypto. Signing and long-lived private-key use belong behind a narrow, isolated signer or external custody interface. A native signer runs in a separate process with a minimal audited transport, reached through authenticated local IPC or mTLS; it has no HTTP server, SQL driver or general plugin execution. Verify its dependency closure. Do not make trstctl mandatory. Keep sensitive key bytes in short-lived byte buffers, use available locking and dump protections, zero them when done, and never put keys or tokens into events, URLs, telemetry, reports, source control or screenshots.

Use TLS by default on network listeners and authenticated service/agent channels. Bootstrap must provide a documented trust path without making insecure TLS bypass the normal installation procedure. No default production password.

Treat every uploaded archive, package manifest, model, image, filename, index and upstream response as hostile input. Bound compressed and expanded sizes, nesting, memory, CPU, file count, regex work, parser depth and execution time. Defend against traversal, links escaping extraction roots, request smuggling, inconsistent path decoding, header injection, malicious serialized models and parser differentials.

Upstream retrieval must defend against SSRF, credential forwarding, redirect abuse and DNS rebinding. Private upstreams are explicitly authorized network destinations; do not break normal private-registry use by blanket-blocking all private addresses. Bind credentials to approved destinations and avoid fallback that changes source or authority silently.

## 11 Idempotency and external effects

First-party mutating management APIs accept and honor Idempotency-Key and return the original result on replay. Native package protocols must retain client compatibility: use their upload IDs, digests, coordinates, conditional requests and publication semantics instead of requiring an invented header stock clients cannot send.

Record durable intent before external effects. Mutation-driven webhooks, scans, replication, feed import, notifications and distribution use a transactional outbox or equivalent recoverable job handoff. Define delivery keys and receiver idempotency rather than claiming exactly-once behavior from a retry loop.

For proxy downloads, record or reconcile cache-fill work using a durable, fenced retrieval lease without forcing every cache hit through a heavyweight mutation workflow. Correctly coalesce concurrent misses and recover a worker failure. Cache hits still enforce the current authorization and applicable content policy.

Queues must be bounded, tenant-aware and fair. Upload/download traffic, security analysis, metadata indexing, garbage collection and migrations must not starve one another. Expose saturation and reject or defer with protocol-correct, actionable responses.

Cancellation, timeout and retry must distinguish work that stopped, work still running remotely, and work whose outcome is unknown. Do not write a success-shaped receipt for an attempted effect.

## 12 Storage lifecycle and integrity

Support local and S3-compatible storage, encryption at rest, customer-managed key integration, signed or authenticated storage access, multipart uploads, quotas, object versioning and supported immutable-retention controls.

Continuously verify content integrity using scheduled checks and readback sampling with known coverage. Detect missing objects, corrupt bytes, inconsistent references and unsupported storage behavior. Repair must identify the source of truth and preserve the audit record.

Deletion and garbage collection require live references, retention rules, holds, pending transfers, leased uploads, release manifests, remote replicas and concurrent publishes to be considered together. Preview destructive maintenance and preserve an auditable tombstone or inventory record as appropriate. An interrupted GC run must be safely restartable.

A deduplication bug must not allow one tenant's cleanup to delete another tenant's data. A stale replica or restored metadata database must not immediately delete valid newer objects.

Backup and restore must cover metadata, journal checkpoints, storage objects, policy, trust configuration and key references consistently. Test partial backups, mismatched restore points, missing key material, object-store outages and interrupted restore. Rebuild projections and reconcile object inventory using supported product interfaces.

## 13 Replication high availability and disaster recovery

Provide supported single-node and clustered deployments. Design the serving path so a management/UI failure does not unnecessarily stop already authorized artifact resolution, while preserving defined authorization and policy freshness guarantees.

Support push and pull replication, topology and loop protection, per-tenant/repository selection, rate limits, integrity checking, resumable state, deletion/tombstone policy and conflict handling. Do not implement multi-writer federation using silent last-writer-wins behavior for incompatible artifacts or policy changes.

Declare the consistency contract for tags, metadata, policy decisions, replica status and revocation. Show replication lag, conflicts and stale-policy state.

Exercise node failure, worker crash, database failover, storage interruption, process restart during transfers, network partitions, lost acknowledgments and repeated recovery. RPO means the amount of recoverable data loss; RTO means the time to restore a working service. Measure both against a named topology.

Multi-host HA requires independent hosts or a genuinely representative external environment. Several containers or pods on one machine do not prove it. Missing hardware remains a qualification blocker, not a reason to stop implementing and testing independent work.

## 14 Migration and exit

Provide product-driven migration from Nexus and Artifactory using supported exports, public APIs or explicitly authorized storage access. Add importers for relevant Harbor/Pulp cases where they improve practical adoption.

Migration must inventory source versions, repository types, formats, package coordinates, metadata, users/groups/roles, retention and policy, builds, signatures, evidence, storage and unsupported features. Produce a dry-run plan with conflicts, capacity needs, source limitations and the cutover/recovery procedure.

Support initial copy, incremental synchronization, resumable checkpoints, reconciliation, controlled cutover and supported rollback. Keep source systems unchanged until an explicitly authorized cutover step. Never infer that similarly named tenants or repositories are the same authority.

Preserve package identities, version semantics, dependency resolution, digests, signatures, relevant timestamps and client compatibility. Translate permissions and policy explicitly; never broaden access to make migration succeed. Verify both sampled native-client journeys and the complete migration inventory.

Keep export and exit rights in core. A customer must be able to export package bytes, metadata, permissions, policy, provenance, releases and verification material in documented forms. A vendor outage or commercial-license expiry cannot hold their artifacts hostage.

Measure migration time, intervention, downtime, failures and operator effort. A migration slide or a script that copies blobs without metadata is not a completed product workflow.

## 15 User experience and automation

The operator journey begins with a blank installation, not seeded data. Deliver a useful first repository and a successful native publish/install through documented UI or CLI steps. Measure time and manual decisions.

Provide a coherent console for repositories and formats; packages and versions; search and dependency/build graphs; security and quarantine; policy and approvals; releases and distribution; migrations; jobs; storage and cleanup; replication; identity and permissions; audit; health and administration.

Every screen must have meaningful empty, loading, denied, stale, partial, error and recovery states. A user must be able to identify the affected package, digest, repository, target and next action without reading source code.

Management operations must be available through documented APIs and CLI, with structured output, filtering, pagination, dry-run and stable error contracts. Provide declarative configuration and a Terraform/OpenTofu provider for the operational resources that customers need to manage as code. Import and reconciliation must make drift visible without overwriting unapproved state.

Use the existing ctlplne visual language as a reference without modifying sibling repositories. Include keyboard operation, accessible labels, screen-reader semantics, contrast and responsive layouts. Verify applicable WCAG 2.2 AA behavior in real browsers.

AI assistance is optional and evidence-bound. It must respect tenant scope and permissions, cite exact package/policy/job evidence, support local models, and require explicit consent before data can leave the deployment. Core operations must work without an LLM. MCP interfaces must expose the same scoped product operations, not a bypass around approvals.

Ship a documented blank Docker Compose evaluation stack, production Helm deployment, control-plane and CLI binaries, and supported Linux amd64/arm64 artifacts. Test configuration rendering, bootstrap, upgrades, persistent storage, readiness and rollback/recovery through the shipped packages. Keep native macOS/Windows CLI and package-client qualification explicit. Supply a disconnected installation bundle with pinned images/binaries, checksums, signatures, trust material, scanner intelligence where permitted, charts and offline documentation. Verify the actual bundle on a network-isolated target; a collection of download links is not an offline installer.

## 16 Observability audit and evidence

Expose service health, request/transfer metrics, latency, queue saturation, tenant fairness, cache hit/miss behavior, scanner/feed health, storage integrity, replication lag, projection lag, policy denials and recovery status through standard local interfaces.

Support OpenTelemetry and ordinary metrics/log consumers without a mandatory vendor backend. Avoid unbounded label cardinality or artifact content in telemetry.

Maintain durable, tamper-evident audit records for mutations, authorization/policy changes, publication, deletion, quarantine, release promotion, distribution, administrative access and other security-relevant effects. Define retention and batching for high-volume read/download records so audit completeness does not depend on an unbounded in-memory buffer.

Export audit and release evidence with enough trust material for independent offline verification. A signature proves the signed statement's integrity and issuer; distinguish that from the truth of an unobserved external effect.

An operator must be able to answer: what exact artifact was served, from which authority and source, under which policy, with which intelligence snapshot, to which authorized identity, and what the receiving system actually acknowledged.

## 17 Performance and operating cost targets

Treat these as initial qualification targets, not claims about a product that has not been built. Record actual hardware, OS, network, database/object-store topology, dataset, clients, concurrency and scanner/feed versions for every result.

Define reproducible small, standard and large profiles. The standard target is an 8-vCPU, 32-GiB application host with fast local storage or a declared object backend, plus explicitly sized dependencies. Start with at least 1 million artifact-version records, 100 tenants, mixed package sizes and a realistic dependency graph.

On that profile, target:

- Warm authorized metadata resolution at 1,000 requests/second with p95 below 100 ms and p99 below 250 ms on the declared network.
- Large-object transfer at least 80 percent of the measured throughput of an equivalent direct authenticated path to the same storage backend, with scanner/intake work outside the already-approved cache-hit path.
- Memory bounded by configured buffers, concurrency and metadata budgets rather than total artifact size. Increasing one streamed object from 1 GiB to 10 GiB must not cause proportional application-memory growth.
- A 24-hour mixed-workload soak without unexplained errors, object corruption, unbounded backlog, tenant starvation or resource growth.
- Concurrent publish, install, scan, replication and maintenance with documented fair-share and admission behavior.

Define large-profile targets and sizing before implementing the clustered path: at least 10 million version records, 1,000 tenants and 1,000 concurrent clients, exercised across independent serving nodes and durable dependencies. Record the external capacity required when it is unavailable locally.

Measure empty install cost, steady-state idle cost, peak memory/CPU, database growth, storage amplification, transfer amplification, restore duration and operator maintenance effort. Compare end-to-end customer cost, including customer-run infrastructure and support, rather than treating a zero software price as zero total cost.

Run format-specific and fault-specific budgets; an aggregate throughput number cannot hide a broken client, scanning bypass or slow tenant. Do not weaken budgets, omit unfavorable samples or change the dataset silently. Any revised target needs an explicit owner decision, while other work continues.

## 18 Required engineering and security checks

Write meaningful tests before or alongside implementation. Establish standard local commands for build, lint, unit, integration, race/concurrency, frontend, conformance, security and packaging. Document equivalent commands if repository conventions evolve.

Use real PostgreSQL and real storage backends for state, RLS, publication, outbox, restore and replication integration tests. Use stock clients and real compatible services for protocol proof. Mocks support unit contracts, not lifecycle qualification.

Add architecture checks for crypto imports, tenant-scoped data access, core/ee boundaries, mutation idempotency, bounded work lanes, secret handling and signer dependency closure where applicable. Correct false positives with narrow rule fixtures, not blanket ignores.

Fuzz every parser and normalization boundary reached by untrusted input. Add property/differential tests for coordinates, metadata and protocol behavior. Retain a versioned conformance suite that independent users and plugin authors can run.

Security testing must cover broken object-level authorization, cross-tenant storage/cache/search leakage, token and signed-link expiry/revocation, replay, redirect and SSRF behavior, archive handling, signature/trust substitution, policy races, quarantine bypass, secret exposure, plugin/scanner isolation and excessive resource use.

Run appropriate Go and JavaScript dependency analysis, source analysis, Gitleaks over current changes and history, and image/artifact scanning with Trivy or an available equivalent. Record tool versions, feed age, scanned inputs, native results, reachability analysis and unfinished coverage. Fix introduced failures and reachable high-impact defects. Do not suppress a real finding to obtain a green report.

Verify core and any EE build configurations, API/CLI compatibility, generated clients and docs, frontend behavior and accessibility, fresh install, upgrade, downgrade/recovery policy, backup/restore, offline packaging, signatures, SBOMs and provenance. GitHub CI supplements local execution; checks needing a different OS or host remain unverified until they run there.

A gate that was skipped or partially executed is not passed. Record pre-existing failures and keep them open while making independent progress.

## 19 Execution stages

### Stage 0 Establish the contract

Review the existing folder, instructions, Git state, host resources and available tools. The repository is already initialized and connected to ctlplne/cratectl. Preserve current work and the original starting-commit record; record a fresh execution checkpoint without resetting progress.

Review the existing root AGENTS.md, architecture decisions, licensing structure, package/client conventions, threat model, parity matrix, journey matrix, format matrix and status record. Complete missing contract work in place. Preserve stable IDs and evidence paths. Refresh benchmark versions and source links when needed. Identify external licenses, hardware and native runtimes needed without making them prerequisites for independent local implementation.

Make initial architecture decisions concrete. Write the first native-client acceptance tests and security invariants. Continue into implementation; document creation alone does not satisfy an execution run.

### Stage 1 Prove the foundations through complete workflows

Build blank install, tenant/auth boundaries, durable journal and jobs, object publication, audit, basic console/API/CLI and storage recovery.

Implement OCI, Maven, npm and PyPI as early structural coverage: container graphs, JVM metadata, JavaScript publishing and Python indexes exercise different protocol shapes. Complete publish/install/proxy/policy/restart/failure journeys for them before treating the foundations as sound.

These formats are the first execution order, not the final format scope. Maintain every other format row as required work.

### Stage 2 Complete repository breadth and adoption

Extend the proven adapter and storage contracts across the committed format inventory. Build group repositories, metadata/search, properties, permissions, migration importers, cache behavior, content lifecycle, storage administration and ordinary operational automation.

Run complete stock-client journeys and migration rehearsals as each format lands. Do not defer all integration testing to a final sweep.

### Stage 3 Complete security and release governance

Finish intelligence distribution, scanners, dependency/build graphs, SBOMs, signatures, provenance, policy, quarantine, waivers, ongoing reassessment, evidence, application releases and staged distribution.

Replay every serving path against policy changes and threat findings. Keep the full paid benchmark scope visible, including capabilities requiring external detectors or data.

### Stage 4 Complete production operations

Finish clustered serving, replication/federation, edge/disconnected operation, HA/DR, full backup/restore, upgrades, native packaging and the large profile.

Prove resource isolation under mixed workload and failures. Complete the operator console, automation surfaces and troubleshooting documentation as part of these journeys.

### Stage 5 Qualify parity and demonstrate improvements

Exercise every committed matrix row on a named candidate. Compare complete workflows against available licensed incumbents and the documented baseline. Close defects, replay original failures and retain the limits of each comparison.

Perform security, performance, recovery and customer migration campaigns. Select improvements from section 21 and measure them. Produce separate readiness verdicts for assisted design partners, ordinary operators, and broad enterprise release.

## 20 Work loop and autonomy

For each capability or defect: observe the current behavior, capture the first failure, implement the focused change with meaningful regression coverage, run affected checks, replay the actual customer journey, update docs and evidence, and commit locally.

Use main for all autonomous commits. Never create per-run or per-defect branches. Never push, publish packages/images, create releases, change remote settings, or modify production/customer environments without an explicit owner request.

Proceed with reversible local setup, disposable owned services, available tests and routine implementation choices. Ask only for an unavailable input or consequential authority that blocks the next dependent action. Continue independent work while an external dependency is missing.

Use isolated project resources with explicit names, ports and ownership. Track installations and resource use. Clean up only resources created for this project, by exact identity. Preserve evidence, retained volumes, sibling projects and unrelated workloads.

Place durable project records under this workspace. Keep private test credentials in a private directory with restrictive permissions; records contain references, never values. Use temporary directories only for disposable intermediate work.

Run focused checks per change and broader gates at coherent integration points. Do not rerun a costly unchanged gate merely for reassurance; rerun when code, dependencies or evidence justify it. Re-run the required final gates on the final candidate.

Maintain a concise status record, durable capability and defect ledgers, and evidence linked to commits and artifact digests. After interruption or context compaction, resume from those records and verify running work before restarting it. Do not reconstruct a retired harness as a prerequisite.

A genuine external blocker names the missing input, the affected acceptance rows, work already completed, remaining local work and exact action needed. Do not classify a difficult implementation or an unattempted local journey as blocked.

## 21 Where cratectl should surpass incumbents

Implement improvements within the core product, then measure them. Do not claim superiority from feature count or architecture alone.

| Improvement target | Required demonstration |
| --- | --- |
| Complete free production workflow | Install an unlicensed core-only build and complete publishing, consumption, governance, audit, replication, recovery and migration without a commercial entitlement |
| Easier adoption | Measure blank install, first publish/install, client configuration, identity setup and repository migration against named baselines |
| Honest operational state | Every visible completion state matches independently observed bytes, metadata, policy, destination state and recovery evidence |
| Customer-controlled sovereignty | Observe disconnected install, licensing, package use, scanning with imported intelligence, upgrades, audit verification and recovery without undocumented egress |
| Better migration and exit | Preserve native client outcomes, policy, identities, metadata and digests through migration and export with measured intervention and downtime |
| Safer maintenance | Demonstrate interrupted cleanup, policy changes, rolling upgrades, replica conflict and restore without corruption, unauthorized access or silent data loss |
| Better economic predictability | Show a complete customer cost model with no core per-user/component/request licensing and measured infrastructure/support costs |
| Measured performance | Reproduce latency, throughput, resource and recovery comparisons on declared equivalent environments, retaining unfavorable results |
| Inspectable security evidence | Independently verify release and audit bundles offline and trace every assertion to its actual scope and origin |

Treat improvement hypotheses as work to prove. Preserve tradeoffs: a stricter policy may reduce availability, and more analysis may cost compute. Explain those choices to the operator.

## 22 Completion and readiness

The full product goal is complete only when every applicable committed capability and journey is implemented and verified on a named candidate, observed defects have been repaired and replayed, required final gates pass, and mandatory qualification has no unresolved blocker. Only the owner can change that scope.

An external block permits an honest interim handoff with the exact missing input and unfinished acceptance rows. It does not complete the product goal, confer full parity, or establish broad enterprise readiness. Continue independent work and preserve the next actions. No available work may be relabeled untested, no required feature may be quietly deferred, and no blocked comparison may be reported as passed. Follow the active runtime's rules for recording an actually blocked goal rather than inventing completion.

Publish separate verdicts for:

1. Assisted design-partner use on explicitly tested deployments.
2. Ordinary operator adoption from a blank installation.
3. Enterprise/release qualification, including scale, security, recovery, native runtimes and external integrations.

Each verdict identifies the exact commit and artifact digests, deployment topology, completed journeys, supported client versions, open defects, external blockers and unverified comparisons.

Full parity claims require all applicable committed capabilities to be verified. Superiority claims require a named comparator and reproducible evidence of the claimed improvement. An emulator cannot qualify a vendor system; cross-compilation cannot qualify a native runtime; unit tests cannot qualify customer migration; and a one-host cluster cannot qualify multi-host HA.

Deliver source and build instructions, operator and developer documentation, conformance suites, migration/export tools, sample configuration, signed release artifacts when publishing is authorized, SBOMs/provenance, benchmark procedures, and a clear remaining-work record.

At handoff, leave the local repository on main with focused commits and a clear starting-commit-to-main review range. Preserve evidence and stop idle project-created services while retaining data needed for reproduction. Do not silently begin a new product, a hosted service, or a broader campaign.

## 23 Official benchmark sources

Refresh these sources at execution start and retain exact edition/version observations. The links identify benchmark behavior; the cratectl requirements above are the owner's product target and are not a claim of an existing implementation.

### Sonatype

- [Nexus Repository editions and capabilities](https://help.sonatype.com/en/nexus-repository-tiers-and-feature-availability.html)
- [Nexus Repository feature matrix](https://help.sonatype.com/en/nexus-repository-feature-matrix.html)
- [Supported formats and repository modes](https://help.sonatype.com/en/formats.html)
- [Community Edition limits and onboarding](https://help.sonatype.com/en/ce-onboarding.html)
- [Repository Firewall quarantine](https://help.sonatype.com/en/firewall-quarantine.html)
- [Format-aware content selectors](https://help.sonatype.com/en/content-selectors.html)
- [Native-client authentication with service account tokens](https://help.sonatype.com/en/service-account-tokens.html)

### JFrog

- [Self-managed feature comparison](https://docs.jfrog.com/installation/docs/feature-comparison-matrix-for-self-mangaged-jpds)
- [Self-managed product license matrix](https://docs.jfrog.com/installation/docs/license-matrix-pro-x-enterprise-x-enterprise)
- [Supported package types](https://docs.jfrog.com/artifactory/docs/supported-package-types)
- [Repository configuration](https://docs.jfrog.com/artifactory/docs/managing-configuration-entities)
- [AppTrust release governance](https://docs.jfrog.com/governance/docs/jfrog-apptrust)
- [Promotion through the application lifecycle](https://docs.jfrog.com/governance/docs/promote-an-application-version)
- [Evidence management](https://docs.jfrog.com/governance/docs/evidence-management)

### Free alternatives

- [Harbor](https://goharbor.io/)
- [Pulp](https://pulpproject.org/)

Use the applicable official protocol specifications, package-client documentation and maintained conformance projects alongside these product sources. Pin versions in tests and refresh them deliberately.

