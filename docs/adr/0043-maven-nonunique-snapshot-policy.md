# Explicit policy for nonunique Maven snapshots

Status: named native PostgreSQL/Ivy journeys pass on both architectures at9b00f7e;
expanded browser qualification remains separate. See
[the native checkpoint](../../evidence/2026-11-04/jvm-9b00f7e-checkpoint.json).

A literal base-version filename such as `tool-1.1-SNAPSHOT.jar` can already be
stored once, but discovery omitted its POM and snapshot mapping. Capture that
failure before changing the renderer. Timestamp/build-number snapshots and
release coordinates keep their existing immutability.

Hosted Maven settings gain `maven_snapshot_policy`: omitted or `immutable`
keeps existing bytes; explicit `redeploy_nonunique` permits replacement only
when the group/artifact/base-version directory and literal filename agree.
Classifier and compound-extension paths are bounded. Checksum URLs remain
parent-derived representations, rather than mutable independent references.
The policy is invalid on other formats or repository modes.

Publication syncs immutable CAS bytes first. The common tenant-locked mutation
then rereads the current repository, write grant, lifecycle and policy. It can
replace the reference only while opt-in is still active. Holds prevent changed
bytes, same-byte retries keep the preservation identity, tombstones cannot be
resurrected, and a permitted replacement advances any existing lifecycle revision.
Its event retains previous/new identities; prior hold receipts stay unchanged.
An old digest decision does not approve the replacement digest. Current decisions
already bound to those exact bytes in this repository remain applicable.

Five actor/repository/path/checksum receipts commit with the accepted reference,
integrity intent and journal/outbox. They permit a delayed sidecar from its actual
publisher without making that historical checksum the current GET representation.
A full queue rolls the entire database mutation back. Staged unreferenced bytes
do not acquire a serving reference. Physical garbage collection remains separate
unfinished work; this change performs none.

The existing revision-controlled settings workflow also admits hosted Maven.
It provides administrator-only preview, expected revision, immutable history,
idempotent apply and rollback. Hosted policy changes do not need an upstream
refresh; future publication rechecks the current policy rather than trusting
intake-time settings. No schema migration or primary maintenance is needed.

Discovery derives literal snapshot POMs, extension/classifier mappings, update
times and `localCopy` from current references. The common first-source, current
review, grant and read-admission checks remain in force. Nonunique names identify
moving bytes; independent fresh client caches demonstrate each tested revision.
Complete warm-cache, concurrent publisher, interruption and outage semantics
still require their own journeys.

Ivy's new `maven-snapshots-v3` preserves every release and metadata-v2 case and
adds eight ordered snapshot cases, nine stages and 34 independent byte bindings.
The first snapshot's identities are observed before its replacement. Stock Ivy
publishes literal filenames and fresh consumers resolve the real transitive
graph. A separately prepared fresh publication tests revocation at native PUT.
Real PostgreSQL tests cover hold/revision/history, review reset, current policy,
tenant separation, delayed checksums and queue rollback. The Chromium source
administration journey also exercises creation, preview, apply and disabling.
These new journeys remain unverified until exact-source CI artifacts are accepted.

Protocol references: Apache Maven [layout](https://maven.apache.org/repositories/layout.html),
[remote snapshot transformation](https://maven.apache.org/repositories/remote.html),
the [snapshot model](https://maven.apache.org/ref/3.9.1/maven-repository-metadata/apidocs/org/apache/maven/artifact/repository/metadata/Snapshot.html),
and Ivy [publication](https://ant.apache.org/ivy/history/2.6.0/use/publish.html).
Normal Maven deployment creates timestamped snapshots; it does not stand in for
the separate literal-filename Ivy publication claim. Full JVM and product scope
remain required.
