# Hosted NuGet development path

Hosted NuGet push, version indexes and package/Nuspec retrieval are implemented.
Actual PostgreSQL and stock dotnet acceptance for this adapter is pending. The
earlier native library checkpoint proves coordinate/archive fixture contracts;
it does not prove this feed or the complete NuGet family.

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

The API key is authoritative for native push, even when the client's source
configuration also supplies Basic credentials. It is ignored on read and
management routes. Duplicate coordinates return 409; publishing cannot restore
a retired reference. A repository requiring review hides unassessed versions
and blocks package and manifest reads until an exact-digest decision permits
them. An archive passing inspection remains unassessed for security purposes.

Materialized references use `nuget-packages/ID_KEY/VERSION_KEY.nupkg`. Inspect
the exact digest in the package inventory before common hold/delete/restore
operations. Restore checks retained bytes and preserves the current security
decision. Native NuGet delete/unlist/relist remains unfinished.

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
