# Maven metadata is a policy-governed derived response

Maven groups currently choose the first metadata file and lose versions from
later members. Implement the Apache G/A/V metadata model rather than treating
an XML file as an immutable package. Retain the submitted immutable bytes and
their journaled mutable pointer; render a deterministic native view from current
sources, artifact references and digest decisions. Sidecars describe the rendered
bytes. Publication sidecars still validate the exact submitted parent bytes.
Four actor/repository/path/checksum-scoped publication receipts use the existing
forced-RLS mutation table. They commit with the pointer, event and job intent.
A delayed sidecar can validate its publisher's previously accepted metadata bytes
after a concurrent replacement, without claiming those bytes are today's view.
Unknown/cross-actor/cross-repository checksums still fail. GET always hashes the
current synthesized bytes. No additional schema or external service is needed.

Use bounded XML parsing with no directives/entities, bounded depth, elements,
coordinates and records. Validate path/coordinate binding and snapshot mappings.
Hosted artifact-level versions also derive from stored POMs, so simultaneous
client metadata replacements cannot erase an existing version. Version ordering
in the list is deterministic; Maven clients apply their own native comparison.
Latest/release hints use eligible publication metadata. Proxy producer timestamps
and aliases govern these hints; cached POM creation records download time and
must not reorder source publications. Equal source timestamps retain configured
precedence. Explicit hints also work when a producer omits its version list.

Groups merge version lists, plugin prefixes and snapshot extension/classifier
maps. Snapshot maps choose the newest updated timestamp/build; equal collisions
keep configured source precedence. Apply longest-prefix namespace ownership to
the resulting artifact/version paths. Current source denial or upstream failure
does not permit fallback. Known blocked collisions stay blocked.

Proxy discovery can advertise uncached versions only when review is not required;
discovery never approves bytes. Current cached digest decisions and group/source
review still govern the view and every download. Fill proxy catalogs through the
existing fenced/checksummed raw retrieval, then reread current grants, source
configuration, catalog identities and artifact decisions in one RLS transaction.
Recheck that snapshot after reading/merging CAS bytes before serving a conditional,
range or checksum response. No schema change is required.
Retry a changed read snapshot at most three times; permission/policy failures
propagate immediately and sustained contention returns explicit busy admission.

Keep the native version/metadata budgets configurable. An exceeded aggregate
record/byte budget fails explicitly, never returns a truncated catalog. Raw
downloads, immutable releases, unique timestamped snapshots and all other formats
retain the common authorization/publication path. Recursive groups, nonunique
snapshot redeployment policy, complete format/client/lifecycle/scale campaigns
and production readiness remain committed work.

Primary protocol references: Apache Maven's [metadata guide](https://maven.apache.org/repositories/metadata.html),
[model](https://maven.apache.org/ref/3-LATEST/maven-repository-metadata/repository-metadata.html)
and [layout](https://maven.apache.org/repositories/layout.html), observed 2026-10-29.
