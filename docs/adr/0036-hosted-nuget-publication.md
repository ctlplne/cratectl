# Hosted NuGet publication and flat-container reads

NuGet publication uses the common tenant identity, repository grants, immutable
blob store, policy decisions, journal and durable work queues. No new database
table or migration is needed. The hosted adapter has named native PostgreSQL/race and stock dotnet proof on
[dfc9381](../../evidence/2026-11-03/nuget-dfc9381-checkpoint.json). This covers the
owned hosted fixtures on both Linux architectures. NuGet-specific Chromium,
production TLS, complete format semantics and other clients/platforms stay open.

The V3 service index is `/nuget/REPOSITORY/index.json`. Its absolute resource
URLs come from the configured public URL. They never inherit the request Host.
It advertises `PackageBaseAddress/3.0.0` at `flat/` and the implemented push path
at `api/v2/package`. Search, registration, symbols and native delete/relist are
unfinished. Proxy/group repository creation remains rejected for NuGet.

Native push is PUT multipart form data. The first raw part is the package;
filenames and part headers never select a coordinate or change package bytes.
Later parts are ignored semantically, with a total limit of 128 parts and a
bounded request body including epilogue. An incomplete body cannot publish a
reference. A truncated body returns 400; byte ceilings return 413.

`X-NuGet-ApiKey` selects the complete publication identity only on this exact
native PUT route. It must occur once. A simultaneous Basic/Bearer credential
does not add privileges or change that identity. Read and management routes
continue to authenticate through ordinary Basic/Bearer credentials. The selected
token is authenticated and rechecked by the common store; reader credentials
cannot publish. Browser and native credentials are never combined.

Intake stages and syncs the package into tenant-scoped content-addressed storage,
opens and verifies those exact bytes, and runs the bounded ZIP32 inspector.
Declared ID/version text is retained separately from frozen invariant lookup
keys. Original Nuspec bytes, path and SHA-256 are retained with the parent
artifact's metadata. The internal reference is
`nuget-packages/ID_KEY/VERSION_KEY.nupkg`; avoiding redundant coordinate text
keeps every accepted coordinate within the common 2,048-byte path budget.

`PublishNuGet` rechecks hosted format, current writer grants and tombstones under
the tenant mutation lock. A coordinate already present returns 409, including
identical bytes, so stock `--skip-duplicate` works. A fresh reference, integrity
job intent and journal event commit in one PostgreSQL transaction. The event
contains the exact path/digest/size, without copying the complete manifest.
Unreferenced staged bytes remain subject to future safe reconciliation; failures
never become visible package references.

Version indexes project bounded keys in one authorized database snapshot. They
exclude current denials, required-but-missing review and retired references.
An exceeded index budget fails instead of returning a partial list. Package
downloads use the common resolver and current policy guard after verifying the
parent CAS bytes. Nuspec downloads verify that same parent and recheck current
authority before serving original manifest bytes. HEAD, ranges and conditional
requests use the standard HTTP serving path. Missing scan evidence remains
unassessed; archive inspection never approves a signature or a security scan.

Retained-reference management can hold, delete and verify/restore the materialized
NuGet package through the common lifecycle path. Native unlisting/relisting,
format-specific retention, full holds/legal journeys and garbage collection
remain unfinished. Package metadata, dependency and signature semantics, Unicode
identity aliases, ZIP64/split formats, search, symbols, other native platforms,
proxy/group behavior and all other goal requirements remain committed.

The native GitHub harness adds stock dotnet push and restore for two application
versions and a transitive dependency, fresh consumer caches, exact package and
inert payload observations, same-coordinate tenant collisions, current policy
denial and an actual registry process restart. Packages contain no build targets,
scripts or executable assemblies. PostgreSQL integration/race tests also cover
concurrent first writers, revocation, complete index limits and reference restore.
Local compilation or unit stand-ins do not qualify these actual journeys.
Both native dfc9381 jobs run them successfully with SDK10.0.403; exact source,
client/binary/four-fixture digests are retained in the named checkpoint. A separate
NuGet operator browser test is now added to the forthcoming 15-workflow console;
its local discovery executes zero tests and is not a browser pass.

Protocol references:

- [Service index](https://learn.microsoft.com/en-us/nuget/api/service-index)
- [Package content](https://learn.microsoft.com/en-us/nuget/api/package-base-address-resource)
- [Push and delete](https://learn.microsoft.com/en-us/nuget/api/package-publish-resource)
