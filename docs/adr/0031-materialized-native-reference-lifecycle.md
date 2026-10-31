# 0031: lifecycle for materialized native references

Status: implementation in progress; no new qualification claim.

The shared lifecycle currently rejects every non-OCI reference. Extending only
the download check would leave native package metadata advertising retired
content and could allow a group to fall through to another source. Materialized
generic, Maven, npm and PyPI references must use the common retained deletion,
hold, current-revision, journal/idempotency and verified-byte restoration path.
Each format's native metadata must preserve a blocked first-source identity while
omitting deleted candidates from client-visible selection.
Source-pinned native URLs enforce the same current-catalog scope: an old proxy
descriptor's tombstone stays local to that reference after replacement/removal,
rather than becoming a permanent denial of the native version or filename.

Mutable catalogs and generated metadata are projections rather than packaged
content. They are excluded from per-reference lifecycle operations: npm/PyPI
catalog records and Maven `maven-metadata.xml` keep their native update behavior.
OCI continues to require canonical digest paths and validated graph semantics.
Hosted package files retain first-writer immutability. Native tags and yanks keep
their own semantics and are not resurrected or rebound by restoring bytes.

A proxy may refresh a materialized path. Publication must recheck current holds
and tombstones in the same transaction as replacing its reference. A changed
digest cannot cross an active hold or resurrect a tombstone. After protection is
released or expires, a permitted replacement advances the lifecycle revision and
records the old/new identity in its publication event. Earlier hold snapshots
remain immutable; an old preview cannot act on the replacement bytes. No hold
receipt is invented for a new digest at the same path.

This extends single-reference lifecycle first. Independent cases/matters still
require canonical OCI identity until other formats have their own complete
versioned subject/membership contract. Multi-file package retirement, format-aware
retention selection, broader legal policy, physical GC, release/replica/restore
protections and all later committed scope remain required. A raw download is not
proof of native package compatibility; stock-client journeys must demonstrate the
metadata, deletion and restore behavior before qualification.

Development uses isolated databases and candidate binary directories. The owned
primary remains schema10 while its separate schema11 maintenance approval is
pending. No primary migration or active-binary replacement follows from this work.
