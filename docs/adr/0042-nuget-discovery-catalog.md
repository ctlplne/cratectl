# 0042: Bounded NuGet discovery from retained manifests

Hosted publication derives a compact `nuspec-catalog-v1` inside the existing
artifact metadata. It records selected scalar properties, full version,
prerelease/SemVer 2 eligibility and a version ordering key. Its source SHA256
binds it to the retained original Nuspec. The projection supplies discovery
data only. Repository grants, digest decisions, review requirements and native
retirement are evaluated through the common store in one PostgreSQL snapshot.
No new durable table or schema version is introduced.

The ordering key uses fixed-width numeric core components and signed Int32
prerelease numbers, matching the existing qualified comparator. PostgreSQL uses
the C collation for these keys. Ties retain separate coordinate identities.
The actual SDK oracle independently compares both semantic and byte-key order
against the existing 3,025 owned pairs. This extension is unverified until the
new clean-source native jobs run.

`SearchQueryService/3.0.0-beta` (with the base and RC aliases) performs literal case-insensitive substring matching
on the latest eligible version's ID, title, description and tags. Stable and
SemVer 1 versions are the defaults; clients can opt into prereleases and
SemVer 2. Search excludes unlisted and currently ineligible versions before
selecting the latest version. `totalHits` counts IDs before pagination, including
empty pages beyond the last result. Queries are at most 256 UTF8 bytes;
skip is bounded at 100,000 and take at 1,000. SQL returns only compact catalogs
and bounded version keys, never every package's XML. Download totals are not
tracked: required per-version download fields use zero. No publisher ownership,
verified-prefix, scanner-clean or vulnerability-completeness claim is emitted.

`RegistrationsBaseUrl/3.6.0` includes SemVer 2 and always uses deterministic gzip.
Each package ID has bounded inline pages of at most 64 versions, numeric bounds,
discoverable leaves and resolvable catalog URLs. ETags identify the compressed
representation. HEAD, conditional requests and byte ranges share those bytes.
Original declarations supply dependency IDs, ranges and target frameworks.
An original floating range is retained to avoid changing its minimum through
formatting. The standalone `*` is represented by its equivalent nonfloating
interval because registration prohibits that spelling. Native framework and
dependency interpretation still needs its own actual HTTP-client evidence;
the earlier Nuspec round-trip proof does not establish JSON interoperability.

Unlisted versions remain in registration with `listed:false` and the conventional
1900 publication timestamp, and remain available for pinned package restores.
The original artifact creation time and bytes are unchanged. Search omits those
versions. Denial, required review, revoked credentials/grants and retirement
still govern discovery and content. Registration preflights SQL-returned
metadata sizes before loading manifests; both input and encoded output must
fit the configured native budgets. Errors never return partial indexes.

Earlier immutable packages may lack the catalog. Search fails with the explicit
`nuget_catalog_rebuild_required` error instead of silently omitting them. An
administrator previews and applies bounded keyset batches through
`POST /api/v1/repositories/REPOSITORY/nuget/reindex`. Every applied batch uses a
reason and idempotency key. Derived metadata, the audit event, event-job intent
and retry receipt commit together under the common tenant fence. A full outbox,
invalid source or exceeded byte budget rolls back the whole batch. Preview is
read only. Other metadata, listing, current policy, immutable bytes and creation
time remain intact, including held/retired records. Operators can stop between
batches and resume with the returned path; repeat traversal from the beginning
to include concurrent insertions before a previous cursor. No primary rebuild
or migration is performed automatically.

The new real PostgreSQL/race regressions and stock dotnet search, restore and
installed SDK `PackageMetadataResource` HTTP calls run on actual Linux ARM64
and x86 GitHub runners. Local ARM unit/race checks use stand-ins. The owned
metadata probe links SDK-provided libraries without NuGet package dependencies
and never loads or runs package payloads. Safe CI summaries retain the probe
and Protocol DLL hashes/version without credentials or private logs.

This is a hosted modern-feed slice. Legacy registration hives, richer framework
and license metadata, arbitrary floating/group edge cases in HTTP feeds,
autocomplete, package-type search, symbols/signatures, proxy/group, production
TLS, other client platforms, fault/scale qualification and every other goal
requirement remain open. No broad format or release verdict changes.

Primary specifications reviewed 2026-11-03:

- https://learn.microsoft.com/en-us/nuget/api/registration-base-url-resource
- https://learn.microsoft.com/en-us/nuget/api/search-query-service-resource
- https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-package-search
- https://github.com/NuGet/NuGet.Client/tree/dev/src/NuGet.Core/NuGet.Protocol
