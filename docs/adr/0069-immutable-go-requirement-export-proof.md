# 0069: Retain every original requirement input with an export

Status: canonical proof, parent manifest, creation-event binding and store
preparation implemented locally. Durable creation, retention, collection and
offline caller integration remain required. Complete GOAL4.1 scope is unchanged.

The requirement preview checks metadata but creates no immutable graph record.
A later automatic export must preserve the exact project and every examined
go.mod, including lower versions absent from the selected build list. A selected
payload list or a `complete` boolean cannot reproduce that decision independently.

`gomodule.RequirementProof` identifies the original main file, all examined source
go.mod files and derived logical/source selections. The canonical index is bounded
before typed allocation and carries no signature, permission or closure grant.
Independent verification checks exact original sizes/hashes, rebuilds the MVS/
pruning graph and compares the separately authenticated selection. Missing,
changed, denied, canceled, extra or unexamined input yields no partial result.

Semantic comparison treats `v1.0.0` and `v1.0.0+incompatible` as tied while Go
preserves both canonical identities. A lexical tie-break orders distinct originals
without changing semantic version selection. The original failing regression is
retained; this is a development-format defect, not a native incident.

`GoRequirementExportManifest` is a distinct profile. It embeds the existing
explicit selected-root manifest and references the main file, requirement index
and each original source-policy manifest/.mod. All source manifests use the same
tenant, final clock and journal head. When a selected version was also examined,
its repository, revision and .mod identity must agree across both paths. Separate
valid byte strings cannot substitute another source authority. The original
cross-link failures are retained as development evidence.

`PlanGoRequirementExport` independently rebuilds the index from consumed original
bytes and private source plans. `PlanGoExportSetAfterReads` rechecks every examined
input and selected root in one final repeatable-read transaction. Original source
metadata already compared in that snapshot is copied with its common observation
fields. The plan emits private copies of every main/index/source/selection/parent
metadata byte string to stage and sync before any reference is committed. Selected
member plans retain the existing physical ZIP/mod/info inspection path. Planning
and staging alone create no session, event, receipt, job or durable pin.

The new creation-event binding requires the exact parent, selection, main and
index references, counts, first generation, original sequence, bounded preparation
age and unchanged initial lifecycle state. A later renewal or signature-shaped
field cannot become an original creation. The caller must first verify the whole
original journal against an independently selected signer and head. An isolated
matching event is not a signature or current admission.

Bounds: 1 MiB per original go.mod, 32 MiB combined requirement input, 1,024 examined
sources, 256 selected versions, a 2 MiB index, 32 KiB per source manifest and a
16 MiB parent. Source-manifest metadata is separately capped at 32 MiB. Inputs and
array cardinalities are checked before unbounded work. The old explicit-set
profile, its 8 MiB manifest limit and all 17 migration definitions remain unchanged.

## Complete the durable workflow

Append a new migration only after retaining a qualified schema-17 historical
binary and upgrade proof. The existing selected-root parent can retain its exact
8 MiB selection reference. Add immutable forced-RLS graph metadata and source
reference tables keyed to that parent's tenant/id; keep the distinct 16 MiB graph
parent reference there. This avoids altering old manifest bounds or old row bytes.
Runtime permissions must remain nonsuperuser/nonowner/no-BYPASSRLS, with immutable
reference columns and bounded ordered queries.

Stage and sync every metadata original first. Under the tenant mutation fence,
recheck each source-policy/byte identity and the selection before atomically
writing the shared session, graph/source references, one original creation event,
idempotency receipt and job intent. Queue failure must roll back all references.
Replay must bind the exact project/repository/revision/budget request. Every renew,
delivery and heartbeat, including legacy access to a graph's selected roots, must
enforce current authority for all examined inputs. A later denied lower version
must fence the entire graph. No SQL transaction may hold external I/O open.

Extend inventory/reference accounting and terminal release deliberately. Retain
original proof metadata as audit data; release active selected payload pins only
through the existing terminal-state rules. Project files can contain private
comments; treat them as tenant artifact data, never diagnostic/public evidence.
No runtime credential/configuration or signing key is appended to the export.

Implement resumable collection and offline verification for the new profile. Bind
the complete signed journal and exact original creation first, then verify every
parent/index/main/source manifest/.mod and selected payload. Independently replay
the requirement graph before building the native proxy. Unknown files, missing
inputs, changed originals, concurrent policy changes and uncertain acknowledgements
must produce explicit refusals/recovery while preserving prior bytes and receipts.

Finally qualify actual native SDK differentials, competing versions, replacements,
exclusions, workspace/immutable local inputs, package imports/platform closure,
private/proxy/group source precedence and authority. Current scanner/import/
server-session/operator outcomes, all 14 export cases/seven environments and the
full 450 capabilities/41 families/later goal remain required. Existing closure,
checksum-authority and destination-admission flags stay false. No signing service,
CA, vault or external credential lifecycle is introduced.
