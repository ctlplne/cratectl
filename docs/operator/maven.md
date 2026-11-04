# Maven repositories and native discovery

Create `format: maven` repositories through the ordinary management API or
console. Publish to a hosted endpoint with Maven's deploy plugin; configure
ordinary Maven repository/server credentials for the same repository ID.

```xml
<repository>
  <id>cratectl</id>
  <url>https://registry.example/r/java-group/</url>
  <snapshots><enabled>true</enabled></snapshots>
</repository>
```

Put the credential in a private Maven settings file through your secret
provisioning process. Give publishers writer/admin authority and consumers read
authority. Restricted groups also require grants on every consulted source.
The [proxy/group guide](proxy-and-group.md) describes approved upstreams, private
credential bindings, freshness, checksum intake and namespace ownership.

Artifact files have immutable SHA-256 identities. A release coordinate cannot be
overwritten with different bytes. Maven's unique snapshots use timestamped
filenames under a `-SNAPSHOT` version directory; repeat publication creates a new
timestamp/build. Current metadata maps each extension/classifier pair separately,
so a later `sources` publication does not replace the ordinary JAR or POM mapping.
Nonunique snapshot policy and discovery are implemented; native replay is pending.
In a hosted Maven repository, **Snapshot policy** controls literal filenames such
as `tool-1.0-SNAPSHOT.jar`. The default **Keep existing bytes** rejects a changed
publication. **Allow base-version snapshot replacement** enables only these
literal snapshot paths. A hold still prevents replacement, and changed bytes
need their own current exact-digest decision when review is required. Releases
and timestamped snapshots keep their existing bytes.

Create with `settings: {"maven_snapshot_policy":"redeploy_nonunique"}` or use
the [configuration workflow](source-configuration.md) to preview and apply a
change at the current revision. Set `immutable` to stop further replacement;
the current snapshot remains. Configuration changes are administrator-only and
retain before/after history. A writer's upload rechecks the current policy after
staging, so an old opt-in cannot authorize a later replacement.

Literal snapshots have generated extension/classifier mappings and `localCopy`
metadata. Use independent client caches when checking before/after bytes. This
implementation does not yet establish every warm-cache, concurrent publisher or
interrupted multi-file publication outcome. Immutable objects and earlier
preservation receipts stay retained; no physical collection happens here.

Native `maven-metadata.xml` responses describe current discovery rather than a
literal copy of one client's upload. The submitted XML remains an immutable CAS
object behind its journaled reference. Artifact-level hosted discovery also
reads current POM references, so a stale metadata replacement cannot erase a
version published concurrently. Groups merge all eligible sources and apply
longest-prefix namespace ownership to each resulting version/artifact path.
Versions are listed deterministically; Maven applies its own version ordering to
ranges. Latest/release hints follow eligible publication metadata. Proxy hints retain the
producer's last-updated time and aliases; downloading an older POM does not make
it the latest publication. Equal source timestamps keep configured precedence.

Snapshot mappings use the newest update/timestamp/build for each extension and
classifier. Equal collisions retain configured source precedence. A known denied
collision cannot be replaced by a lower source or an older snapshot. Plugin
prefix discovery follows source order. A source authorization error, invalid XML,
checksum failure or unavailable upstream stops the response; only not-found
permits ordinary path fallback.

All discovery rechecks current grants, references and digest decisions after
reading and combining stored bytes. A changed snapshot is retried at most three
times. A group can require stronger review. Review-required discovery includes
only known approved POMs/mappings; an uncached upstream catalog entry is not an
approval. Every actual package request still checks its exact digest policy.
Current metadata ETags and SHA-256/SHA-384/SHA-512/SHA-1/MD5 sidecars describe the exact
synthesized response; policy checks also precede conditional/HEAD/range replies.
SHA-1/MD5 exist only for Maven compatibility, not as the security identity.

Metadata and replaceable snapshot checksum uploads validate bytes that this actor actually published to
this repository/path. Five durable checksum receipts commit with the metadata
reference, event and job intent in the existing forced-RLS mutation table. This
allows a delayed publisher sidecar after another publisher replaces the pointer.
It does not change the current download checksum. Unknown checksums and receipts
from another actor or repository fail. Use independent Maven local repositories
for independent concurrent publishers; two JVMs modifying the same metadata cache
can change a file while the other client uploads or hashes it.

XML parsing rejects directives/external entities, duplicate scalar/record values,
coordinate/path mismatches, cross-version snapshot mappings and excessive nesting.
`--native-version-budget` bounds aggregate input references/catalog records;
`--native-metadata-bytes` bounds inspected metadata and the complete response.
An exceeded budget returns a metadata-budget error, never a silently shortened
version list. Inspect the source and configured capacity before increasing it.

Native Maven proof does not qualify Gradle, Ivy, SBT, every plugin workflow,
metadata signatures, nonunique snapshots, recursive groups, complete lifecycle,
large-directory/multi-host performance, migration or release readiness. These
remain required in the format and qualification ledgers.

The separate [Gradle client profile](gradle.md) now implements native publication,
module/POM resolution and recovery cases for GitHub execution. Its named v2 profile passes on both native Linux architectures; the existing
Maven evidence remains separate. The [Ant/Ivy profile](ivy.md) has passed its
repaired client identity gate, but publication and the remaining stages still
need native replay after checksum configuration/service changes.

Protocol references: [Apache metadata](https://maven.apache.org/repositories/metadata.html),
[metadata model](https://maven.apache.org/ref/3-LATEST/maven-repository-metadata/repository-metadata.html)
and [layout](https://maven.apache.org/repositories/layout.html).


Ivy names its stronger algorithms `SHA-256`, `SHA-384` and `SHA-512` and uses
those exact suffixes in checksum URLs. Maven repositories normalize these to
the same parent-derived checksum path as `.sha256`, `.sha384` and `.sha512`.
GET/HEAD, conditional responses, publisher checksum validation and metadata
receipts use current parent permissions, policy and tenant scope. A checksum
PUT validates the parent bytes; it does not create a separately approved object.
SHA-384 is a compatibility checksum; SHA-256 remains the immutable blob identity.

An older opaque reference under one of those checksum names remains in storage
and inventory for deliberate operator reconciliation. The native checksum URL
now derives from the current parent, even if that old sidecar has its own
allowed decision. No old bytes are deleted by this change. The new alias,
legacy-sidecar and SHA-384 receipt regressions are implemented but await real
PostgreSQL/native-client qualification on the next source.
