# OCI complete discovery and native pages

Complete a source catalog before publishing any of its graph references. Tag and
referrer discovery follow one unambiguous `next` link across bounded pages. Parse
all Link fields, respecting URI and quoted-parameter commas. Reject ambiguous
next relations, changed link contexts, cycles, repeated entries and exhausted
page, metadata, graph or entry budgets. A later failure cannot replace the cached
catalog with a partial result. Previously complete stale data remains eligible
only under the existing classified-failure and per-member cache rules.

An opaque cursor at the exact original catalog scheme, authority and path does
not need general signed-query permission. Any other path or delivery authority
uses ADR 0010's explicit approved source and signed-query opt-in. Select the most
specific configured source before testing permission, use only its credential,
and preserve raw query bytes. Each hop retains DNS/CIDR/private-network ceilings,
URL/query bounds and downgrade rejection. Cursors and signed links remain
ephemeral; durable bindings identify the canonical repository resource.

Fetch catalog metadata unconditionally. A first-page ETag cannot validate an
entire collection: another page could change or a 304 could omit Link. Manifest
and blob conditional revalidation remains available. The complete normalized
catalog is committed through the original retrieval lease, current grants and
publication transaction after every advertised manifest and dependency validates.

If the referrers API returns 404, read the legacy `sha256-HEX` tag as an index of
referrers. A missing fallback index produces an empty derived catalog. Other
errors do not trigger fallback, and malformed or mismatched referrers fail the
walk. Validate each referent's actual subject and current policy. A known denied
subject blocks discovery, including empty pages and legacy fallback.

Serve native tag and referrer pages from the complete permitted view with `n`
and exclusive `last`, relative next links, HEAD and representation ETags. Preserve
artifact-type filter context. Zero-sized and exhausted pages have no next link.
Tags use case-insensitive lexical order with exact-string ties; referrers use
digest order. Every page request evaluates current grants and graph policy.
Concurrent changes can alter later pages; these cursors do not freeze a historical
snapshot. Share a bounded graph check within each source view. Budget exhaustion
is an explicit metadata-limit failure, never an omitted policy-denied candidate.

Defaults are 32 upstream pages (`--oci-catalog-pages`, maximum 4096) and 1000
downstream entries (`--oci-page-size`, maximum 100000). Requested page size is
clamped to that downstream maximum. Existing entry, byte and graph limits can
fail a complete view before paging; pagination does not permit an unbounded
catalog or remove those safety ceilings.

Owned HTTP fixtures and stock ORAS with real PostgreSQL cover signed and opaque
source pages, downstream tag/referrer traversal, filtering, fallback, current
subject/referrer denial and no partial publication after a later-page failure.
Parser tests cover Link grammar, invalid markers, cycles and bounds. Clean
binary and public-provider replays are recorded separately in qualification.

Descriptor URL retrieval, lifecycle/deletion/restore, all provider/private
credential/client/platform combinations, full mutable-catalog concurrency and
fault/scale campaigns remain required. This decision supersedes the pagination
limitations in ADRs 0008 and 0009; it does not close broad capability rows.

Primary references observed 2026-10-28:

- [OCI Distribution 1.1.1: content discovery and unavailable-referrers fallback](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
- [RFC 8288: Link serialization](https://www.rfc-editor.org/rfc/rfc8288.html)
