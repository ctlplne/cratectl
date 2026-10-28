# Governed npm upstream metadata and group resolution

An upstream package metadata document (a packument) advertises versions, tags,
dependencies and tarball URLs. Forwarding it unchanged lets clients bypass the
registry and lets a later refresh change the bytes behind a lockfile URL.

The proxy caches a bounded, normalized catalog through the existing durable,
fenced retrieval lease. One transaction publishes the catalog reference and its
immutable source descriptors. Each descriptor records the package, version,
approved tarball URL, expected integrity and package metadata. Its key is SHA-256
of its canonical JSON with an empty key field. Changes create another descriptor;
old lockfile URLs keep their original binding across refresh and restart.

The native response rewrites tarball URLs to local paths identifying the source
repository and descriptor key. The server resolves that durable descriptor on
download, rechecks repository access, fetches only its approved URL, verifies the
strongest supported SRI algorithm, inspects the archive and checks the package's
dependency/platform fields against the advertised metadata. Bytes are staged
durably before a reference, event and outbox intent commit. No archive is extracted
or executed. A successful integrity check is not a scan or policy approval.

Supported source integrity algorithms are SHA-256, SHA-384 and SHA-512. Multiple
digests at the strongest available algorithm are alternatives. Explicit
`allow_legacy_npm_shasum` permits SHA-1 compatibility for older packages; the
`require_checksum` option disables that fallback. Actual cached bytes retain
their own SHA-256 identity and current repository-digest policy decision.

Download URLs must match the metadata source or an explicit `download_sources`
entry. Credentials, DNS/IP authorization and the operator private-network ceiling
apply independently to each source. Longest approved base path selects the
credential binding. Redirects remain within that chosen authority and base path;
cross-authority redirects and query-bearing/signed URLs remain unsupported.
Scoped catalog requests encode the package-name slash. Decoded URL paths must
remain canonical, valid UTF-8 and free of double-encoded traversal.

Catalog discovery is separate from package approval. In a review-required source
or group, metadata shows only versions whose own descriptor/archive binding has
been validated and whose exact digest is allowed. Conventional tarball paths can
perform durable quarantined intake; operators then review the recorded digest.
Known invalid or actively negative-cached tarballs remain blocked coordinates.
Transient failures may use previously cached bytes only under the explicit stale
policy. Integrity, authority and package-graph failures never authorize stale data.

A group first applies longest-prefix namespace ownership, then fills its selected
proxy catalogs. One PostgreSQL snapshot rereads group/member grants, source
catalogs, hosted versions, tags and digest decisions. Version collisions belong
to the earliest configured member, including denied or quarantined coordinates.
A later source cannot replace that blocked version. Tags also retain the first
declaring authority and are shown only when they target a visible version selected
from that same source. Missing packages can fall back; authorization and source
failures cannot. All configured selected members require read access.

Version, tag and total metadata budgets reject oversized complete views instead
of returning partial dependency indexes. Historical descriptors and staged bytes
still need the planned lifecycle/GC/recovery system. Fair background workers,
full npm/pnpm/Yarn behavior, signatures, unpublish, source migration, cross-origin
redirects, every fault campaign and production qualification remain open.

Protocol references, observed 2026-10-28:

- [npm package metadata](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md)
- [npm public registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md)
- [W3C Subresource Integrity](https://www.w3.org/TR/sri/)
