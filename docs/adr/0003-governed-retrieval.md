# ADR 0003: governed proxy retrieval and group authority

Accepted 2026-10-28. A proxy miss creates a tenant-scoped PostgreSQL retrieval
lease before making an upstream request. A generation and opaque lease token
fence completion: a crashed or superseded worker cannot publish over a newer
retrieval. Fresh hits read state without creating another mutation. Concurrent
misses wait for the same lease, within the request deadline and admission budget.

The upstream is a configured authority, not an arbitrary client URL. Its URL
cannot contain credentials, query or fragment. Operators explicitly authorize
network CIDRs; DNS results are checked and the connection is dialed to a checked
IP while TLS keeps the original hostname. Environment HTTP proxies are disabled.
Redirects are bounded and must remain within the same authority and base path.
Operator-owned credentials are keyed by tenant/reference and bound to the
approved URL authority/base path and authentication scheme. An independent
operator private-network ceiling limits repository CIDRs. Only a configured
private credential reference supplies upstream authentication;
downstream credentials are never forwarded. HTTP is an explicit loopback-only
test exception. Private HTTPS upstreams remain supported with authorized CIDRs.

Bytes stream to durable tenant storage before the cache reference, validators,
lease result and journal event commit together. Changed bytes lose old approval;
unchanged bytes keep their digest decision. Freshness and negative-cache windows
are operator configuration. Stale serving is opt-in, time-bounded and restricted
to transient failures; it never overrides current denial or required review.
Maven proxy intake checks an upstream checksum when available, with an explicit
required-checksum policy. Local checksums describe the exact governed bytes.

Groups select configured members in order. Only not-found permits fallback;
denial, integrity failure and unavailable sources stop the request. Namespace
owners pin a prefix to one member even when that member has no matching package.
The caller must have read authority on the group and on every consulted source.
A group may require stronger review than its source, and cannot weaken source
policy. The final response rechecks source and group authority after integrity
verification. Repository grants are evaluated by common store methods, including
metadata, inventory and OCI graphs, rather than only at an HTTP routing layer.

First implementation order: generic and Maven raw protocol operations, real
PostgreSQL lease/permission tests and stock Maven resolution. Creation must reject
unimplemented proxy/group formats. npm, PyPI and OCI native metadata rewriting,
complete native mode campaigns, cache administration and larger scale remain
required work, not implied by this shared engine. Configuration is immutable in
this initial API; versioned reconfiguration remains required backlog.

References: RFC 9111 (https://www.rfc-editor.org/rfc/rfc9111.html) and Go Transport
contract (https://pkg.go.dev/net/http#Transport), observed 2026-10-28. This product
cache always enforces its own authority and policy; it is not an unrestricted
shared HTTP cache.
