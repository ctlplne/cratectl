# ADR 0002: quarantine intake and graph policy

Accepted 2026-10-28 after native ORAS publication exposed DEFECT.0004. A complete
OCI artifact is a graph: a manifest describes a config and layers, and an index
can describe other manifests. Quarantine must permit assembling that graph
without pretending it is approved for consumption.

Publishers may validate durable, unassessed references while assembling intake.
A known denied reference is rejected. The native publication response means
that bytes and their manifest reference are durable; it does not mean approved.
The server stores validated graph edges with the immutable manifest reference.

Serving, tag listing and non-admin inventory use one shared graph reader. The
reader checks the root and every child against current decisions and repository
policy, in one repeatable-read PostgreSQL snapshot. A denied or missing child,
cycle, excessive depth or missing graph metadata fails closed. Administrators
can still see quarantined inventory to explain and review exact digests.
A large object's integrity read is followed by another policy/reference check
before headers. A decision admits that transfer; later changes affect subsequent
requests. Immediate cancellation of already admitted transfers is not claimed.

Initial safety limits: depth 32 and a traversal budget of 4096 object identities.
These limits need operator configuration and larger graph qualification before
production readiness. They are resource controls, never edition restrictions.

Pre-graph development manifests have no retained edges and therefore fail
closed. A supported backfill/re-import/upgrade recovery workflow remains open;
no production upgrade compatibility is claimed for those development records.
ADR 0007 adds structural intake, weak subject associations, referrer discovery
and a same-byte development re-import path. Full multi-architecture campaigns,
signatures and scanner policy remain required work. A manual graph approval
remains a manual decision.
