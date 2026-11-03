# Hosted NuGet development path

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

Supply the environment variables from your private secret provider:

```sh
dotnet restore --configfile /private/path/NuGet.Config
dotnet nuget push PACKAGE.nupkg --source https://REGISTRY/nuget/REPOSITORY/index.json \
  --api-key "$CRATECTL_WRITER_TOKEN" --skip-duplicate
```

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
  --source https://REGISTRY/nuget/REPOSITORY/index.json --api-key "$CRATECTL_WRITER_TOKEN"
```

The flat version index, original package and original Nuspec remain available to
authorized pinned consumers. Current review/policy decisions still govern reads.
The native relist operation is an empty authenticated `POST` to
`/nuget/REPOSITORY/api/v2/package/PACKAGE_ID/VERSION`. Repeated unlist/relist requests
succeed. An active hold blocks a listing transition; a retired reference must go
through the common verified restore operation. Relisting cannot resurrect it.
Registration/search remain unfinished; their discovery projections must exclude
unlisted versions while the administrative inventory continues to expose retained
state to authorized operators.

Operator budgets are `--nuget-upload-bytes` (64 MiB default, maximum 1 GiB),
`--nuget-expanded-bytes` (256 MiB default, maximum 1 TiB), and
`--nuget-file-budget` (10,000 default, maximum 16,384). The global object-store
upload ceiling also applies. Request overhead is limited to an additional 1 MiB;
manifests remain limited to 1 MiB and physical ZIP directory bytes to 16 MiB.
Complete indexes use the native version and metadata budgets. An over-budget
index fails with 503 rather than omitting versions.

Only hosted ZIP32/store/deflate packages within the documented ID transport
profile are admitted. Proxy/group, registration/search, symbols, full signature
and dependency metadata handling, Unicode identity aliases and other clients
and native platforms remain required work. Do not infer full format support or
release readiness from the presence of these endpoints.

Version-precedence work now adds stable numeric core/release ordering and a
cancellation-aware sort, beneath the existing caller limits and a 100,000-key /
64 MiB hard safety ceiling. The comparator and 1/2/10 PostgreSQL regression pass
on both native Linux architectures at
[189a6ae](../../evidence/2026-11-03/nuget-189a6ae-checkpoint.json).
Stored version keys and package bytes are unchanged.
