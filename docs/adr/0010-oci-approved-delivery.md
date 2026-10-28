# Approved OCI delivery redirects and opaque query credentials

Accepted 2026-10-28. Complete the existing OCI upstream transport path for
registries that deliver content through a separate CDN or object service. Keep
ADR 0008's atomic graph publication and ADR 0009's member freshness/policy fences.

OCI proxy repositories can configure `download_sources` with exact HTTP(S)
authority/base path, network CIDRs and an optional independently bound credential
reference. Signed query use additionally requires `allow_signed_query: true` on
the selected OCI origin or download source. Token realms never accept this flag.
Ordinary npm/PyPI durable download URLs retain their query rejection.

Each registry request receives redirects without automatic HTTP following. For
each 301/302/303/307/308, bound and parse one Location, reject ambiguous paths,
userinfo, fragments and HTTPS downgrade, then choose the longest matching
configured authority/path. A more specific source owns the request even when it
rejects query use; its rejection cannot fall through to a broader credential.
Build a fresh GET with only selected response validators and Accept metadata.
Apply that destination's configured credential, never the previous hop's
Authorization, registry pull bearer, realm credential, downstream token, Cookie
or Referer. A CDN's challenge cannot start a registry token exchange.

Each destination reuses the common DNS/network transport: validate every resolved
address against both its source CIDRs and the operator private-network ceiling,
then dial the approved address. Disable environment proxies. HTTP remains limited
to literal loopback fixtures; normal delivery uses system-trusted HTTPS. Realm
redirects remain rejected. Authentication and signed-query opt-ins do not confer
another authority or path.

Query strings are opaque credentials for the delivering service to validate;
cratectl does not claim to verify provider signatures. Validate bounded query
syntax and control characters without changing byte order, escaping or repeated
parameters. Do not persist Location or the query URL in cache/source bindings,
artifact metadata, events or job intent. Sanitize delivery transport errors so a
wrapped URL error cannot print the signed query. Final bytes still need the
requested SHA-256, descriptor length and media/graph validation before references
can commit. Temporary signed URL expiry never becomes a durable source identity;
a later refresh asks the registry for a new delivery URL.

Operator budgets default to five redirect hops, 16 KiB URL bytes, 8 KiB query
bytes and 64 parameter pairs. CLI controls can disable redirects or change those
budgets within the HTTP header safety ceiling. Bounds apply before network use;
the existing fill deadline, concurrency, graph byte and metadata budgets remain.
A transport/TLS failure never silently grants stale use; classified temporary
HTTP failures still require the existing per-member stale policy.

Owned transport tests cover separate origin/CDN credentials, opaque query byte
preservation, issued registry bearer isolation, unapproved second hops, loops,
path/query/network rejection, HTTPS downgrade and operator budgets. A separate
conformance test package runs stock ORAS against real PostgreSQL and the owned
registry port. It proves proxy/group exact-byte pulls, root 304/member renewal
with a newly issued query, no partial references after integrity/query rejection,
current digest denial and absence of ephemeral credentials in durable data.
Native-client subprocesses never belong to the HTTP server package.

A separate explicit-source script also exercises an immutable Linux arm64
BusyBox image through real Docker Hub, its anonymous token realm and documented
CloudFront signed delivery. It includes a missing-query-permission negative
control, proxy/group OCI layouts, process restart, member refresh and current
root denial. Exact candidate, digests and results belong to its retained report.

This does not qualify other S3/GCS/Azure/CDN signatures, every registry/private
credential/token-service/client/platform, custom private PKI, descriptor URL
fallback, all TLS/DNS/network faults, source lifecycle, full conformance, HA,
migration or production scale.
Those remain required. No broad capability or readiness row is closed.

Primary reference observed 2026-10-28:

- [CNCF Distribution HTTP API V2: pulling a layer and 307 delivery](https://distribution.github.io/distribution/spec/api/#pulling-a-layer)
