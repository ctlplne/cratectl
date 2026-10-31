# 0029: independent preservation cases for immutable references

Status: implemented; scoped clean qualification passed on isolated schema-10
databases. See `evidence/2026-10-31/hold-cases-checkpoint.json`; primary9 and
its qualified runtime remain unchanged.

A replaceable reason cannot represent simultaneous preservation decisions. If
two administrators are investigating the same bytes, completing one review must
not remove the other's protection. The original per-reference hold remains a
separate legacy slot so existing clients retain their established behavior.

Each named case binds one tenant, repository, canonical OCI digest path and exact
digest. Its revision belongs to that binding. Two cases may both be created at
revision zero; a stale revision for the same case fails. Placement updates or
reopens that case. Release retains its preservation reason and expiry and records
the release reason separately. No endpoint releases every case implicitly.

The common lifecycle reader observes the union of the active legacy slot and all
unreleased, unexpired cases. Native digest/blob/tag deletion, retained restore,
retention previews and worker execution consult this same reader. Every case
change also advances the reference's lifecycle revision, invalidating older
destructive previews. Downloads continue through existing authorization, source
and security policy. A hold does not grant serving authority.

Migration 10 adds the forced-RLS tenant table and bounded lookup indexes. It
changes none of receipts 1–9 or the original journal bytes. Case state, lifecycle
fence, immutable event, outbox intent and idempotency response share the tenant
write transaction. Queue rejection rolls them all back. Current administrator
authority applies to new changes and exact replay, including retained suspended
or removed repositories. Another current administrator can recover a case after
the original credential is revoked.

Inventory uses immutable first-creation event sequence as its position, so
editing a case does not move it across a continuation. Encrypted continuations
bind tenant, actor, role, credential, endpoint and exact filters. Each SQL result
has at most 101 candidates; output pages have at most 100 records and a byte
budget. Oversized first records fail explicitly. Pages remain live observations:
expiry, release and concurrent insertions can change membership. History reads
actual immutable case events, preserving their original case and aggregate
snapshots. Expiry invents no release receipt. The legacy inventory continues to
describe its own slot while its aggregate `held` field includes named cases.

The same interfaces are available through the management CLI and Storage →
Reference holds. The case editor reads the exact digest and case revision,
previews its change, and uses the common uncertain-response/idempotent retry
flow. Original-slot actions explain that named cases remain independent.

This foundation covers canonical OCI references. Mutable coordinates in other
formats require their own binding/retirement protections before holds can be
advertised for them. Tenant-wide legal matters, cross-reference case membership,
bulk admission/release, approval/separation-of-duties workflows, physical GC,
replicas/releases, production recovery and all other goal requirements remain
committed. No legal-compliance or release-readiness claim follows from this ADR.

The primary remains schema 9 with the previously qualified schema-9 binaries.
Schema-10 development and qualification use isolated owned databases. Controlled
primary maintenance requires the complete matching runtime qualification first;
schema-9 binaries must never run against a migrated schema-10 primary.
