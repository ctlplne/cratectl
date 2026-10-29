# 0023: Version source settings and retain catalog observations

Status: accepted for local implementation; qualification is recorded separately.

A proxy URL, credential reference or group membership change must not make the
old source's fresh bytes, validators or download links authoritative for the new
source. Changing back must not revive an old in-flight writer.

Schema 4 adds a monotonic `source_revision` to repositories and source-bound
retrievals, artifacts, OCI tag advertisements and immutable native locator
receipts. Existing schema-3 content starts at revision 0. Migration definitions
1–3 remain byte-for-byte frozen. Configuration history has forced tenant RLS;
the runtime can select and append receipts, but cannot update or delete them.

Only an administrator can preview or replace proxy/group settings. A replacement
requires the explicit current revision and reason. History, settings, retrieval
fences, journal, durable job intent and idempotency response share one tenant
write transaction. Ready cache invalidation uses revision comparisons rather
than an unbounded rewrite. Pending fills are enumerated under explicit count and
byte budgets before fencing. A budget or outbox failure rolls back the change.
Rollback and refresh of identical settings both create new revisions. Replaying
a committed operation confirms the original response without changing the
current settings; current administrator authorization still applies.

New-source fills discard old validators and stale windows. A 304 can reuse only
an artifact already bound to the current revision. An invalid 304 terminates its
lease with a classified failure so an immediate forced retry can proceed. Native
npm/PyPI locators and batched metadata views select current-revision receipts.
Final body/HEAD/conditional admission checks the selected source and group
revisions again. A changed request fails closed instead of falling through to a
lower source. Old CAS bytes and locator receipts remain retained.

Credential values remain in the private, startup-loaded provider. Preview checks
reference/destination/scheme bindings locally and performs no connectivity probe.
For same-reference value rotation, suspend the source, reload the private provider
during controlled restart, apply identical settings to advance the revision, then
resume and validate through an ordinary client. Hot provider reload and managed
secret lifecycle are separate, unfinished work.

OCI catalog intake distinguishes observations from serving authority. It can
retain advertisements for locally retired or denied objects while excluding them
from discovery results. Known retired metadata can prove immutable descriptor
structure without redownloading a deleted child; it cannot authorize serving or
restore a tombstone. Ordinary direct publication remains strict. An advertised
retired higher-priority tag shadows a lower source. A proxy advertisement marked
absent by the current upstream is remote absence, rather than a hosted tag
deletion, and does not shadow lower sources. Prior-source advertisements cannot
govern the new source before revalidation.

This adds no physical deletion, reclamation, recursive groups, compatible rolling
upgrade, hot secret reload or general production-readiness claim.
