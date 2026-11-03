# Native OCI client qualification

State: implemented but unverified. The new GitHub `Native OCI clients` workflow
must run successfully on native Linux x86-64 and ARM64 before a client result is
claimed. Existing ORAS evidence does not qualify Docker, Podman or Helm.

The workflow starts an isolated PostgreSQL service on loopback35432, builds
candidate registry/CLI binaries in `.cache/ci-build`, then runs
`scripts/conformance_oci_clients.py --require-clean-build`. The registry listens
on loopback38443 and uses a separate fresh database, restricted runtime role and
private filesystem objects. A separate tenant/repository in that same process
is the real HTTP upstream. This does not prove an independent vendor registry
or a multi-host deployment. The retained local primary and active binaries are
outside the workflow.

Docker and buildx use the disposable GitHub runner's engine and tools; their
actual versions and Docker/Podman/Helm binary hashes are retained in the safe
summary. Helm4.3.1 archives are checked against the hashes in its
[official release](https://github.com/helm/helm/releases/tag/v4.3.1).
Podman CLI4.9.3 is verified on each architecture. Its installed Ubuntu package
revision/architecture and binary hash are recorded; the fixture does not force
an older Debian revision over the runner's security updates. GitHub's official
[x86 inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
and [ARM64 inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Arm64-Readme.md)
identify the CLI version. A missing or different CLI version fails the gate.
No compatibility with an unexecuted version is inferred.

The fixture builds scratch images with two owned text-file layers using only
COPY instructions. Foreign-platform fixture bytes also use COPY only. It never
starts an image, entrypoint, package script or chart hook. Docker and Podman
create named stopped containers solely to copy installed filesystem bytes and
verify the native platform selection. The copied files are read through bounded
file descriptors that reject symlink components, hardlinks, special files and
changing or oversized observations. Containers and Docker image references are
removed by exact fixture names; Podman uses a separate private VFS store. The
workflow never changes Docker daemon configuration or prunes global state.
Podman4 limits the runroot path to50characters. The fixture allocates a new
mode0700 `/tmp/cratectl-podman-*` directory below that limit for each run. It
checks the exact allocated path/device/inode before privileged removal. The
graph store remains under the run's private workspace; this temporary runtime
directory contains no retained registry or primary data.

The driver requires native publication and consumption of layered images,
multi-architecture selection, exact upstream graph bytes, concurrent first proxy
retrieval, Podman-to-Docker publication, Helm chart/dependency retrieval, two
versions, tenant coordinate collisions, reader publication denial, denied root
and layer policy, underlying group grant revocation, credential revocation and
registry restart. It checks the actual runtime SQL role, forced tenant RLS,
held retirement denial and client reads after logical deletion/restoration.
Positive observations precede negative checks. Independent
HTTP status controls prevent a random client error counting as an authorization
or policy pass. New destinations and private credentials avoid inherited user
configuration; client processes receive neither database DSN.

This is the explicit loopback HTTP test profile. Native client production trust,
independent machines/providers, interruption and outage coverage for every
client, other build tools, signatures/attachments, complete lifecycle/GC,
platforms, scale and all remaining goal scope stay required. No image execution,
Helm installation into Kubernetes or broad readiness is claimed.

Raw credentials and command logs remain private. CI uploads
the reviewed summary for30days: counts, hashes, clean native build identity,
reviewed versions/package revisions, client binary hashes, fixture hashes and
verified immutable graph/member identities. Failed commands expose a
fixed phase/label/category rather than raw private output. Preserve first
failures and commit reviewed summaries with the exact candidate and limits.
The existing main CI, focused browser and upgrade gates remain separate.
Failed jobs can also publish bounded encrypted command/registry diagnostics
for seven days. Only the public recipient certificate is present on GitHub;
the decryption key stays in ignored local private state. See
[private diagnostic operation](ci-diagnostics.md). There is no plaintext fallback.

The actual270f7ca artifacts from both architectures decrypted successfully and
showed the50character runroot failure before registry login. Its source,
metadata hashes, safe error and limits are retained in
[the runroot failure](../../evidence/2026-11-02/oci-clients-270f7ca-runroot-failure.json).
The short-path repair then replayed through all client logins on both native
architectures at f499369. Docker manifest creation failed later with a generic
lookup error; its cause remains unconfirmed. A separately reproduced multi-field
Accept serving defect is repaired locally and has new real PostgreSQL/CAS
coverage awaiting GitHub execution. Manifest debug output stays encrypted.
See [that failure](../../evidence/2026-11-02/oci-clients-f499369-manifest-failure.json).
Earlier unknown-cause failure records are preserved; no complete client journey
is verified.

The first native run failed on both architectures before any client journey.
The original Podman Debian revision pins would have downgraded installed
packages; APT refused. Both failed/empty summaries and the setup diagnostics are
retained in [the first failure](../../evidence/2026-11-02/oci-clients-first-failure.json).
The corrected setup and stronger subject evidence still require native replay.
