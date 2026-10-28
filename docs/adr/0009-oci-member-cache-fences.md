# OCI graph member freshness and publication ordering

Accepted 2026-10-28. Extend ADR 0008 so a cached parent cannot make an expired,
invalidated or missing dependency appear current.

Every staged canonical manifest and blob receives its own retrieval record in the
same transaction as graph publication. Retain that response's validators and
bounded fresh/stale windows, plus the parent fill's path and generation. The
requested root also retains the most restrictive graph window. Direct digest
requests use the shared retrieval path; graph selection checks every required
member in the current authorization/policy snapshot. An expired member forces one
bounded root revalidation, including discovery catalogs. A graph left over from
older development code without member records must be revalidated.

A root 304 validates only its representation. Reuse verified exact stored root
bytes, parse them again, fetch dependencies, then publish the revalidated graph
atomically. Mutable manifests send only strong ETags: weak ETags and modification
timestamps do not establish the byte identity required for a digest. Reject a 304
when no validator was sent. Revalidated tag-list membership still requires
fetching the named manifests, because an unchanged list does not freeze tag
bindings. Paginated tag responses do not retain a first-page-only validator.
Referrer pagination currently fails closed instead of caching a partial index.

A successful max-age=0 fill admits only its current request through an internal
receipt containing source, root path and generation. SQL rechecks the root state
and member validation receipts. A later request revalidates again. The receipt
cannot survive member/root invalidation, a negative cache entry, active fetching,
current denial, source grant revocation or a newer root generation. Outage
receipts separately require a classified temporary root failure and each
member's own stale window. A root window cannot widen a member's window.

Cross-path races need durable ordering. Under the existing tenant write lock,
retrieval acquisition, completion, invalidation and tag changes use the sequence
of their journal event. Completion refuses to overwrite member invalidation,
fetching or expired/failed state newer than its acquisition. A newer ready and
fresh member is retained. Tag/catalog changes similarly reject older conflicting
bindings, removals and missing-tag responses. All related object, cache, tag,
event and job changes commit or roll back together. Wall-clock timestamps remain
operator diagnostics; they never order competing publications. Tests simulate
backward timestamps in owned database rows without changing the host clock.

Real PostgreSQL regressions cover positive and stale receipts, negative caches,
member invalidation during parent intake, retained newer fresh validation and
older tag fills after catalog changes. Stock ORAS proof includes independently
inspectable cache bindings, direct and parent-driven revalidation, zero-freshness
pull/discovery and restart. These are bounded development proofs. Approved CDN
and signed delivery, complete lifecycle/removal, every token service/client,
referrer pagination and production migration/fault/scale qualification remain
required. No full format or readiness verdict becomes verified.

Primary reference observed 2026-10-28:

- [HTTP Semantics, weak versus strong validators, RFC 9110 §8.8.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.1)
