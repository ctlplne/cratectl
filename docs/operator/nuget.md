# NuGet development path

Hosted NuGet push, version indexes and package/Nuspec retrieval are implemented.
Actual native Linux PostgreSQL/race and stock dotnet journeys pass on clean
[dfc9381](../../evidence/2026-11-03/nuget-dfc9381-checkpoint.json), using SDK10.0.403
and owned inert package/dependency fixtures. These runtime journeys use an
explicit isolated loopback HTTP test profile. The complete NuGet family, native
production TLS and other client platforms remain unqualified. The named NuGet
Chromium operator flow passes on
[9e6d980](../../evidence/2026-11-03/nuget-browser-9e6d980-checkpoint.json), including
five fresh repetitions; other browsers and complete accessibility remain open.
The earlier library checkpoint retains its separate scope.

Create a hosted `nuget` repository through the repository API or console. The
feed URL is `https://REGISTRY/nuget/REPOSITORY/index.json`. Use a reader service
credential for restore and a writer service credential for push. Trust the
operator's CA through the client's normal trust configuration.

Save a private `NuGet.Config`, readable only by its owner:

```xml
<configuration>
  <packageSources>
    <clear />
    <add key="cratectl" value="https://REGISTRY/nuget/REPOSITORY/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <cratectl>
      <add key="Username" value="token" />
      <add key="ClearTextPassword" value="%CRATECTL_READER_TOKEN%" />
    </cratectl>
  </packageSourceCredentials>
</configuration>
```

Supply the environment variables from your private secret provider. The pinned
SDK can read the publish key directly from `NUGET_API_KEY`.
[NuGet publish authentication](https://learn.microsoft.com/en-us/nuget/nuget-org/publish-a-package)

```sh
dotnet restore --configfile /private/path/NuGet.Config
NUGET_API_KEY="$CRATECTL_WRITER_TOKEN" dotnet nuget push PACKAGE.nupkg \
  --source https://REGISTRY/nuget/REPOSITORY/index.json --skip-duplicate
```

## Flat-container proxy

Set `format` to `nuget` and `mode` to `proxy`. Set `settings.upstream.url` to
the upstream's `PackageBaseAddress/3.0.0` base URL from its service index. Then
point `dotnet restore` at the cratectl feed URL above. The cratectl service index
advertises its own flat-container URLs. Search, registration and symbols remain
open in this proxy scope.
[NuGet PackageBaseAddress](https://learn.microsoft.com/nuget/api/package-base-address-resource)

To verify an upstream service index during cache fills, set
`settings.nuget_service_index` to `true` and set `settings.upstream.url` to
the exact V3 service-index URL. Add its approved package base as the single
`settings.download_sources` entry with its own address allowlist and credential
reference when needed. A changed advertised address fails before the proxy
contacts the package source. Update the settings through the source
configuration API after independently verifying the new address.
[NuGet service index](https://learn.microsoft.com/en-us/nuget/api/service-index)

With `settings.cache.require_checksum` enabled, the upstream must supply a
base64 SHA-512 sidecar at the package URL plus `.sha512`. The proxy bounds and
validates each package, checks the archive's package ID and normalized version,
and serves the Nuspec embedded in the retained package. An integrity failure or
an attempt by the same source revision to replace an admitted coordinate blocks
that transfer. An upstream checksum confirms content integrity for transport.
Archive and checksum validation leave the digest unassessed for review.

For a repository requiring review, request the exact native `.nupkg` URL to
stage a cold package for review. The request is denied until an authorized
operator approves that digest. A version is advertised only while its catalog
and approved package receipts are current. Current cached denials, retired
references and known failed or missing package coordinates are omitted from the
projected index. The common cache and digest-decision APIs apply to proxy
references.

## Ordered groups

Set `mode` to `group` with ordered NuGet `settings.members`. The first member
with a current catalog or a retained package reference owns that package ID.
Use a canonical lowercase ID followed by `/` in `settings.namespace_owners`
to send that ID directly to a particular member. Different members can supply
different dependencies through the same group endpoint.

The group applies its own review requirement and the selected member's review
and grants. A consulted higher-priority proxy must have a current native
catalog before the group can publish a version list or admit exact bytes. An
outage, denial, or retirement stays attached to the package's selected source.
An explicit upstream absence allows fallback only when the higher-priority
member has no retained reference for that package at the current source
revision. Each group uses the same `/nuget/REPOSITORY/index.json` client URL
and exposes flat-container restore.

## Hosted publication and discovery

The API key is authoritative for native push and unlist/relist, even when the client's source
configuration also supplies Basic credentials. It is ignored on read and
management routes. Duplicate coordinates return 409; publishing cannot restore
a retired reference. A repository requiring review hides unassessed versions
and blocks package and manifest reads until an exact-digest decision permits
them. An archive passing inspection remains unassessed for security purposes.

Materialized references use `nuget-packages/ID_KEY/VERSION_KEY.nupkg`. Inspect
the exact digest in the package inventory before common hold/delete/restore
operations. Restore checks retained bytes and preserves the current security
decision.

Native unlist/relist has named actual PostgreSQL/race and stock-dotnet proof on
[83ca290](../../evidence/2026-11-03/nuget-83ca290-checkpoint.json), using the same
owned inert packages and isolated loopback HTTP profile. `dotnet nuget delete`
records the version as unlisted:

```sh
dotnet nuget delete PACKAGE_ID VERSION --non-interactive \
  --source https://REGISTRY/nuget/REPOSITORY/index.json --api-key=" $CRATECTL_WRITER_TOKEN"
```

The space before the key keeps dash-leading values out of the pinned delete
command's option parser. The HTTP parser removes this optional field whitespace
before authenticating the exact key.

The flat version index, original package and original Nuspec remain available to
authorized pinned consumers. Current review/policy decisions still govern reads.
The native relist operation is an empty authenticated `POST` to
`/nuget/REPOSITORY/api/v2/package/PACKAGE_ID/VERSION`. Repeated unlist/relist requests
succeed. An active hold blocks a listing transition; a retired reference must go
through the common verified restore operation. Relisting cannot resurrect it.
Modern registration/search are implemented but await their new actual GitHub
PostgreSQL and stock-client qualification. Search omits unlisted versions;
registration retains permitted dependency metadata with `listed: false` for
pinned consumers. The administrative inventory exposes retained state to
authorized operators.

Discover packages with the ordinary client:

```sh
dotnet package search PACKAGE_TERM --configfile /private/path/NuGet.Config \
  --source https://REGISTRY/nuget/REPOSITORY/index.json --format json
```

Search matches a literal case-insensitive substring in the latest eligible
version's ID, title, description and tags. It defaults to stable SemVer 1
versions; `--prerelease` includes prereleases and modern clients opt into SemVer 2.
The native query endpoint accepts `q`, `skip`, `take`, `prerelease` and
`semVerLevel`. It reports total package-ID matches before pagination. Required
per-version download counts use zero because cumulative downloads are not yet
tracked. It does not claim publisher ownership or security approval.

The service index advertises gzip `RegistrationsBaseUrl/3.6.0`, containing
SemVer 2 versions, and `SearchQueryService/3.0.0-beta` (with the base and RC aliases). Registration pages retain
declared framework/dependency data with numeric version ordering. Legacy
registration hives and package-type search remain unfinished.

Older packages may return `nuget_catalog_rebuild_required` during search. An
administrator can open **Repositories → Rebuild discovery** for a hosted NuGet
repository. Enter a reason and batch size, then select **Preview batch**. Review
the examined/changed counts before **Rebuild this batch**. Each batch is atomic;
the preview is an observation and apply reads current state again. Confirmed
receipts expose the exact resume path. Use **Continue to next batch** until the
end, then **Check again from beginning** to include earlier concurrent publishes.
Closing between confirmed batches preserves completed work. If a response is
lost, use **Retry same request**; save its displayed request identity and body
before closing without confirmation. The console keeps no durable browser copy.
This console maintenance journey passes in the full native suite and five fresh
GitHub PostgreSQL/Chromium repetitions on
[09e641c](../../evidence/2026-11-03/github-09e641c-checkpoint.json).

An administrator previews a batch by POSTing this JSON to
`/api/v1/repositories/REPOSITORY/nuget/reindex` with their normal Bearer credential:

```json
{"limit":100,"after_path":"","dry_run":true,"reason":"Rebuild discovery from retained validated manifests"}
```

Save that JSON privately and use the normal management CLI:

```sh
cratectl --config /private/path/admin-client.json --method POST \
  --path /api/v1/repositories/REPOSITORY/nuget/reindex \
  --body-file /private/path/nuget-preview.json
```

For apply, save `dry_run:false` in a separate private request file and add
`--idempotency-key YOUR_UNIQUE_BATCH_KEY`. Retain that exact file and key until
the batch is confirmed; every next batch needs its own key.

Inspect `examined`, `changed`, `after_path` and `more`. Apply the same batch with
`dry_run:false` and a new 8–128 character `Idempotency-Key`. Retry an applied
batch with the same key and request bytes. Use the returned `after_path` with a
new key for the next batch while `more` is true. Repeat from the beginning to
include packages inserted before an earlier cursor. Reduce `limit` if the
metadata byte budget is exceeded. A failure rolls back the whole batch; a full
event queue requires worker/queue recovery before retry. A malformed retained
manifest requires inspection of that immutable package. Rebuilding changes only
derived discovery metadata; it preserves bytes, listing, creation time and
current security decisions. Stopping between batches leaves completed receipts
durable. No schema migration or automatic primary rebuild is required.

The dependency-set repair advances the derived catalog profile from v1 to v2.
Older projections must use the same explicit rebuild procedure above. Pinned
package bytes remain intact; the change does not approve an artifact or change
its current review/security decision. The new dependency projection still
requires native GitHub replay before a broader compatibility claim.

Operator budgets are `--nuget-upload-bytes` (64 MiB default, maximum 1 GiB),
`--nuget-expanded-bytes` (256 MiB default, maximum 1 TiB), and
`--nuget-file-budget` (10,000 default, maximum 16,384). The global object-store
upload ceiling also applies. Request overhead is limited to an additional 1 MiB;
manifests remain limited to 1 MiB and physical ZIP directory bytes to 16 MiB.
Complete indexes use the native version and metadata budgets. An over-budget
index fails with 503 rather than omitting versions.

Only hosted ZIP32/store/deflate packages within the documented ID transport
profile are admitted. Proxy/group, legacy registration, richer search, symbols, full signature
and dependency metadata handling, Unicode identity aliases and other clients
and native platforms remain required work. Do not infer full format support or
release readiness from the presence of these endpoints.

Version-precedence work now adds stable numeric core/release ordering and a
cancellation-aware sort, beneath the existing caller limits and a 100,000-key /
64 MiB hard safety ceiling. The comparator and 1/2/10 PostgreSQL regression pass
on both native Linux architectures at
[189a6ae](../../evidence/2026-11-03/nuget-189a6ae-checkpoint.json).
Stored version keys and package bytes are unchanged.
