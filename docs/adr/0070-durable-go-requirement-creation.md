# 0070: Commit original requirement evidence with the shared export lifecycle

Status: implemented but unverified. Native PostgreSQL/HTTP/CLI/upgrade gates are
required; collector and signed offline caller integration remain unfinished.

Append schema 18, checksum
`6c60ac3e1228e57b54cdd99397ef4bccfb91cbd942b3437e41a63441b9ad1035`.
All first 17 definitions/checksums remain unchanged. Qualified schema-17 source
bb6f728 is the seventeenth historical binary pin; GitHub independently rebuilds
its native daemon on both Linux architectures. The new declared old-schema SQL
test complements that actual old-daemon gate rather than substituting for it.

Two forced-RLS tables retain immutable graph and ordered examined-source object
references. Runtime grants allow SELECT/INSERT only; the schema safety function
checks exact tenant policies and refuses effective update/delete/truncate/
reference/trigger privileges, including column-level update grants. No old table
definition or 8 MiB selected-manifest bound is widened or rewritten.

The original selected-root parent supplies shared generation, deadlines, quota,
expiry and payload pin release. Creation stages all metadata before entering a
tenant-fenced transaction. It compares every original canonical source manifest,
including unselected lower versions, then the complete selection. It atomically
inserts the shared parent/roots/items, graph/source references and exact creation
event/idempotency receipt/job intent. Queue admission failure rolls back all rows.
Replay binds the exact project, repository/revision, lifetime and payload budget.

Every existing selected-root delivery/renewal/acknowledgment and the new graph
metadata delivery guard also checks all original examined inputs. A historical
allowed record never grants current source access. A newly allowed decision with
a different version does not silently refresh frozen evidence. Cancellation and
expiry retain administrator access checks and release the shared active payload
pins without erasing audit originals. Inventory counts graph/main/index/source
manifest/.mod references permanently; physical GC remains unimplemented.

A production-envelope regression exposed the previous proof binder's synthetic
four-field assumption: appendEventIntent emits six fields. The first failing
regression is retained. The repaired binder requires the exact production fields,
matching envelope/session actor and canonical event time; no four-field substitute
is accepted. This development failure is distinct from a native incident.

The new route uses the existing bounded management CLI. Status and leased
range/HEAD/conditional reads preserve distinct complete-parent and selection
identities. Original event binding still requires the complete independently
signed journal/key/head at the caller; the route does not invent such proof.
The native CLI case replays original metadata after registry shutdown without
claiming complete signed offline collection or package/platform closure.

The upgrade workflow adds exactly the schema-17 historical iteration and title.
The verifier supports schema 17's exact frozen workflow hash only when the current
file differs by precisely those two edits. It records both hashes and continues
checking original jobs against their original step/report/binary inventory.
Schema-18 sources must supply all 17 pins and 22 upgrade reports per Linux host;
old 16-pin campaigns cannot qualify them. The exact frozen summary extractor permits only the matching count/schema
bound increase; every other closed contract stays byte-identical for ancestor
acceptance. No job restart repairs observation
or compatibility, and no skipped/unselected profile counts as passed.

Full collection/offline verification, package/platform closure, authority/source
precedence, scanning/import/operator outcomes, providers/platforms/GC/installation/
backup/HA/scale and all owner-amended GOAL4.1 scope remain required.
