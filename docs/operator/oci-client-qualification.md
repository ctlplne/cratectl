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
Podman4.9.3 uses explicit Ubuntu24.04 package versions for each architecture;
see the [Ubuntu package inventory](https://packages.ubuntu.com/noble/podman).
An unavailable pinned dependency fails the gate and needs a reviewed refresh.
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

Raw credentials and command logs remain under ignored `.private/`. CI uploads
only the reviewed summary for30days: counts, hashes, clean native build identity,
reviewed version strings and client binary digests. Failed commands expose a
fixed phase/label/category rather than raw private output. Preserve first
failures and commit reviewed summaries with the exact candidate and limits.
The existing main CI, focused browser and upgrade gates remain separate.
