# Native NuGet listing without retiring immutable packages

NuGet's native delete operation is implemented as unlisting. Existing consumers
must still restore an exact version. The native POST operation relists that same
version. This differs from the common reviewed retirement/verified-restore flow,
which blocks serving a retired reference until explicitly restored.

The existing forced-RLS artifact metadata stores one optional boolean `listed`.
Its absence means listed, preserving previously published packages. Only this
field changes; raw Nuspec bytes, their digest, package digest/size, publication
time, policy decisions and unknown metadata fields remain unchanged. A bounded
SQL projection and the existing manifest-binding validator reject inconsistent
records. There is no new table or schema migration.

Native DELETE and POST use `/nuget/REPO/api/v2/package/ID/VERSION`, accepting the
same coordinate normalization as publication. A single bounded API key supplies
the entire identity. Basic/Bearer credentials never fill in authority missing
from that key. The common transaction rechecks credentials and current repository
write grants under the tenant write fence. It serializes with publication,
retirement and holds. A retired reference cannot be relisted. An active hold
blocks a listing transition; a request for the already-current state succeeds.

The listing change, audit event and durable event-job intent commit together.
Retrying either operation succeeds without changing immutable content. Each
accepted attempt records whether a transition occurred. Exhausting the event
queue rolls back the metadata change and event. The flat version index and exact
package/Nuspec reads continue to include unlisted content, with ordinary current
authorization, review, policy and byte verification.

Unit cases cover API-key scope/ambiguity, read-route separation, empty bodies,
method boundaries, backward-compatible defaults and invalid state. A new
non-skipping PostgreSQL regression covers exact bytes/state, idempotent requests,
restricted grants and revocation, concurrent mutations, holds, tombstones,
tenant collisions, handler recreation and atomic outbox rollback. The stock
dotnet journey adds real `nuget delete`, reader rejection, retries, fresh-cache
pinned dependency restore, raw native POST relist and current-denial enforcement.
Both actual native Linux PostgreSQL/race gates and stock SDK10.0.403 campaigns
now pass on 83ca290. Each broader client campaign has 436 checks, including
listing/digest witnesses and pinned dependency restore across actual registry
restart. Exact source, native binaries, SDK and fixture hashes are retained in
`evidence/2026-11-03/nuget-83ca290-checkpoint.json`. This is distinct from complete
discovery and lifecycle qualification.

This implements the native mutation and durable listing state. Search must omit
unlisted versions. Registration must retain their permitted version/dependency
metadata with `listed: false`, so pinned consumers can still resolve dependencies.
Both resources remain required. Administrative inventory must expose retained state to authorized
operators. This change does not claim complete discovery, metadata, lifecycle,
signature, symbol, proxy/group, TLS, platform, format or release readiness. All
original GOAL.md scope remains required.

References:

- [NuGet push/delete/relist resource](https://learn.microsoft.com/en-us/nuget/api/package-publish-resource)
- [Stock dotnet delete command](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-nuget-delete)
- [Search excludes unlisted packages](https://learn.microsoft.com/en-us/nuget/api/search-query-service-resource)
- [Registration retains listing state and package metadata](https://learn.microsoft.com/en-us/nuget/api/registration-base-url-resource)
