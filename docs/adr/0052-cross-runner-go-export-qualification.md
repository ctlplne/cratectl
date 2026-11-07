# 0052: Verify a hosted Go export on a separate native runner

Date: 2026-11-07. State: implemented; new native workflow unverified.

The existing signed-manifest journey creates and consumes one hosted version on
one host. It does not establish that a second machine can verify and use the
collected bytes without reaching the source registry.

The new `go-export-portability.yml` workflow uses two actual GitHub-hosted Linux
VM jobs: an amd64 producer with real PostgreSQL and an arm64 consumer without a
database service. Both build the exact clean candidate natively. The original
93-function Go normal/race lanes and all broader qualification remain required.

The producer runs the existing actual PostgreSQL/CAS export, external OpenSSL,
candidate CLI and pinned Go1.27.3 fixture, retaining every existing assertion.
Only this exact owned CI test may retain the synthetic capsule. Its exhaustive
eight-member list contains three package representations, the canonical policy
manifest, complete journal, checkpoint statement, signature and public key.
It excludes credentials, configs, command logs, SDK caches and signer private
keys. The declared tenant/repository/module/version are fixed test identities.
This capsule is a test corpus, not a new customer export/import format.

The producer records capsule, public-key and runner fingerprints in job outputs.
The consumer downloads the exact artifact ID, refuses a transport digest
mismatch and checks those separately supplied fingerprints before passing the
public key to the actual CLI. A key next to a downloaded signature is not itself
trust. This job-output channel is an explicit owned workflow trust assumption;
it does not implement or qualify a production external signer/provider service.
The CLI must independently authenticate the complete signed journal and original
export creation event before accepting the manifest and package bytes.

After online build and artifact transfer, consumer commands run in fresh empty
kernel network namespaces. `sudo unshare --net` creates only a child namespace;
`setpriv` immediately restores the original nonroot job UID/GID before executing
the command. The host network is untouched. A mandatory observation verifies a
different namespace, only the loopback interface, no IPv4 routes, no nonloopback
IPv6 route and the original UID/GID. Utility byte hashes and the observation
hash are retained. Every subsequent CLI, OpenSSL control and stock Go command
uses this wrapper. Unsupported isolation fails; it is never a skip or a pass.
This proves the named verification/consumption commands can run without a
registry network, while bootstrap and artifact transfer remain online.

The consumer creates owner-private files and a separate inert `go.mod` so SDK
bookkeeping cannot change the candidate source. Go uses a new private cache,
one verified file GOPROXY, local toolchain, disabled helper/VCS/checksum/network
fallback and the pinned native SDK. It must report the exact module/version,
ZIP/mod h1 and original inert asset. It never compiles or executes package code.
Native `go clean -modcache` preserves ordinary read-only cache semantics.

Mandatory controls reject an existing output, changed canonical policy manifest,
changed valid ZIP, truncated journal, changed checkpoint statement/signature,
wrong public key and wrong export ID. Rejections require the actual CLI exit1,
no stdout receipt and no new destination proxy. Private stdout is separate from
stderr; setup/exec failures cannot count as expected rejection. Command time,
stream capture and file output are bounded. All sixteen outer stages (three
producer/thirteen consumer) must complete. They do not replace the assertions
inside the native producer test or the broader normal/race suites.

Public summaries retain only reviewed scalars, stages and byte identities.
The last two original private command streams can be sealed to the existing
owner CMS recipient on failure. Large streams retain exact length/hash and
bounded head/tail; no plaintext publication fallback is allowed. Only exact
command-log paths are selectable, never private inputs or keys.

No product schema or runtime interface changes. All fifteen definitions stay
frozen. Full dependency/authority/permission/provenance closure, destination
current-policy/scanning import, other formats/providers/platforms, complete
offline installation/intelligence, backup/GC, HA and scale remain required.
The independent three-host strict Go checksum-client failure DEFECT0126 and
unknown browser intermittent DEFECT0122 remain open. Broad readiness is false.

Implementation references: the [official artifact action](https://github.com/actions/download-artifact)
documents exact artifact-ID downloads and explicit digest-mismatch failure;
[GitHub's artifact guide](https://docs.github.com/en/actions/tutorials/store-and-share-data)
describes transfer between dependent jobs. Those mechanisms transport test
bytes; the product's independent signature/journal verification remains a
separate requirement.
