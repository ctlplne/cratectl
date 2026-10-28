# OCI proxy graph publication and group reads

Accepted 2026-10-28. Extend the structured intake contract from ADR 0007 to
read-through OCI repositories without creating another authorization or storage
path. Existing immutable bytes and current digest decisions remain authoritative.

A retrieval lease identifies one requested manifest, blob or discovery catalog.
Fetch a manifest's strong dependencies recursively from the configured upstream
base, verify SHA-256, declared size and manifest media type, and stage all bytes
durably before committing any references. A single generation/token-fenced
PostgreSQL transaction publishes canonical objects, the requested alias, mutable
tags, journal event and outbox intent. Expired/superseded work and incomplete
graphs roll back together. Recheck current graph policy within that transaction.
Unassessed content can be durably quarantined; no scanner result is inferred.

Tag catalogs retain source bindings and tombstone tags removed by a complete
refresh. Immutable digest pins retain their exact stored bytes after tag changes.
Referrer discovery fetches and validates attachment graphs and their association
to the requested subject. Derived catalogs use bounded metadata and the same
lease fence. A known subject's current graph policy still governs attachments.

One fill uses the shared global/tenant retrieval admission controls and a
120-second execution limit under its 150-second fenced lease. Bound graph nodes,
depth, metadata and aggregate staged bytes; do not unpack layers, execute package
code or follow descriptor URLs. ADR 0009 refines root 304 handling: reuse verified root bytes, then renew
its complete dependency graph and individual member cache records. Explicit stale policy can retain a graph after classified temporary
upstream failures, while every subsequent read still checks current local policy.
Authentication, integrity and authority failures cannot grant stale use.

Groups apply namespace ownership before source selection. Check all selected
source grants and the first source's current tag/digest graph in one read
snapshot. A known blocked collision cannot fall through. Group review applies to
every dependency, including when an underlying source does not require review.
After byte verification, select again and reject a changed source or tag binding.
Discovery merges permitted native tags/referrers with first-source collision
ownership and complete-result budgets.

Optional token authentication uses an explicitly configured realm URL, its own
network/credential binding and an exact service audience. A challenge cannot
authorize another realm, audience or scope. Derive only repository pull scope
from the configured upstream path; never forward downstream credentials. Bound
challenge/token inputs, keep issued tokens only within that image's fill, and
retry the original request once after an approved exchange. The origin validates
the opaque token; cratectl does not pretend to verify its issuer signature.

Native ORAS proof and real PostgreSQL race tests cover the listed operations.
Token authority tests use owned HTTP fixtures. This does not qualify every
registry, live third-party token service, multi-platform/client combination or
fault case. Cross-authority/signed CDN redirects, descriptor URL retrieval,
referrer fallback/pagination, full client conformance, lifecycle/migration and
production/scale campaigns remain open. Current graph depth/node/metadata limits
also need operator configuration and larger-graph qualification. All broad rows
remain implementing or planned.

Primary references observed 2026-10-28:

- [OCI Distribution 1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
- [CNCF Distribution token authentication](https://distribution.github.io/distribution/spec/auth/token/)
