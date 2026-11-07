# 0053: Bound export expiry lookup through retained history

Date: 2026-11-07. State: named source16 native cases verified at470ca74; full operations scope incomplete.

See [95Go normal/race](../../evidence/2026-11-07/go-module-470ca74-native-checkpoint.json), [native upgrades](../../evidence/2026-11-07/github-470ca74-upgrades-checkpoint.json) and [separate-host portable profile](../../evidence/2026-11-07/go-export-portability-470ca74-checkpoint.json). Full273PG and whole31job campaign acceptance remain separate; original ARM Ant/Ivy bootstrap fails before client qualification.

An export keeps its manifest after expiry so an operator can explain the original
transfer. The previous worker query returned one session but could inspect and
sort retained history on every idle visit. A tenant with many old or future
sessions could therefore spend increasing database work discovering nothing due.

Schema 16 appends a partial B-tree index on `(tenant, expires_at, id)` containing
only `open` and `acknowledged` sessions. The worker reads the first nonterminal
session in deadline order and compares that single result with PostgreSQL time.
If it is still in the future, no later session can be due. The transaction exits
without changing a generation, journal event, job or reference. It continues to
use the dedicated current worker credential, forced tenant RLS and common
mutation fence. A due transition retains the existing atomic state/event/job
commit and queue-failure rollback. No physical deletion is added.

Admission checks the actual index relation, valid/ready/live state, access method,
key order, ascending options, absence of included columns and exact partial
predicate. A missing or differently shaped index refuses admission. All first
15 migration definitions remain unchanged; the new step is frozen separately.
Installing the index uses controlled stopped-registry maintenance under the
existing migration admission lock. This is not a concurrent index build or a
rolling-upgrade compatibility claim. No primary maintenance is performed.

The new query regression uses an explicitly declared SQL occupancy fixture:
32,768 terminal and 4,096 future sessions in one tenant, plus 1,024 due sessions
in another. Its event chains use the common digest primitive and bounded batches;
its object references clone only owned inert fixture bytes. These rows measure
query work and reference accounting, not API creation throughput or independently
bound export manifests for every row. With the default planner and the actual
nonowner, nonsuperuser runtime without BYPASSRLS, `EXPLAIN (ANALYZE, BUFFERS)` must
use the partial index, return one row, omit history scans/sorts and stay within
64 shared buffer hits/reads. Repeated idle visits must preserve all rows,
receipts, generations, events, jobs and roots. Aging the real original session
then expires only that session once, retaining the other active roots and tenant.
Timestamp aging is a declared fault fixture, not a real clock-shift experiment.

A separate declared schema-15 SQL fixture snapshots every tenant table and all
15 receipts, migrates, verifies unchanged bytes, checks no-op replay and rejects
missing or malformed indexes. The existing schema-14 and legacy backfill cases
remain. The historical native lane additionally rebuilds the qualified fca2d4a
schema-15 daemon. That real daemon publishes and approves Go bytes, creates and
acknowledges an export before stopping. Schema 16 must retain its original
manifest/package bytes, session/deadlines/roots, byte-identical idempotency
receipts and journal prefix. Original OCI and earlier upgrade assertions remain.

Local ARM build/unit/race/lint, normal/race tagged compilation and vet provide
development evidence. Execute 273 full PostgreSQL functions and 95 named Go
functions normally and under race on both actual GitHub Linux architectures,
plus 15 historical binaries/20 upgrade reports per host. Preserve the existing
stock clients, 55 fuzz targets, 19 main Chromium workflows/151 checks, focused
profiles and cross-runner export controls. Neither fixture establishes broad
scale, real clock faults, complete closure/import, backup/restore, physical GC
or readiness. All remaining GOAL scope stays required.
