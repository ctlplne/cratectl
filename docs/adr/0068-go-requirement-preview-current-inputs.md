# 0068: Revalidate every examined Go requirement input

Status: implemented with local gates; native qualification pending. Complete
automatic package/platform export and all GOAL4.1 scope remain required.

The metadata resolver in ADR0067 can examine a lower module version that does
not appear in the final selected build list. Rechecking only selected roots after
reading files would omit that input's current permission, policy and identity.

`POST /api/v1/go/export-sets/requirements/preview` accepts one complete main
go.mod, one exact hosted repository/source revision, lifetime and artifact budget.
The existing administrator gate, tenant identity, forced RLS and source policy
apply. The server's common transfer slots bound concurrent requests. Metadata
loads are serial and reuse the existing complete Go bundle admission path.

Each load obtains an original source plan in a short read transaction, closes the
transaction, then reads only the bounded original .mod from CAS. It verifies the
stored size/digest before parsing and checks the consumed bytes again. A cached
source can serve multiple logical replacements; the final guard retains each
distinct physical source once. No transaction remains open across file I/O.

`Store.PlanGoExportSetAfterReads` accepts only original private store plans bound
to the same tenant/actor. In one current repeatable-read/read-only transaction it
rechecks every examined source's complete metadata/policy identity, including
unselected versions, then prepares every selected root with one clock/head.
Changed decision versions cannot silently refresh an earlier input. A missing,
denied or changed input, canceled request or exhausted budget yields no preview.
It creates no pins, session, journal entry, receipt or job.

The response identifies the original main file, examined logical/source versions,
original .mod hashes/sizes, toolchain requirements, proposed explicit selection
and unsigned common manifest. It keeps package/platform closure, checksum
authority, physical-payload verification and destination admission false. The
preview is an inspection step: a later explicit common-set creation checks the
selected roots again. A complete automatic creation still needs every examined
input under the mutation fence and immutable graph inputs in authenticated proof.

The [existing management CLI](../go-requirement-preview.md) supplies the private
request through its bounded body-file interface. Its actual TLS/native journey
must compare the eight-module preview selection with the original stock-SDK
selection and prove the source journal unchanged. Additional PostgreSQL cases
cover missing physical metadata, a pruned but selected late denial, an unselected
lower version's denial with its higher version still allowed, and a later new
allowance changing the original decision version. These cases have compiled and
passed vet locally only; real PostgreSQL/SDK qualification belongs on GitHub.

Local ARM build/unit/race/lint and four focused admission functions pass. The
future source contains 286 PostgreSQL/108 named Go functions and 63 fuzz targets.
Every actually selected native workflow, both Linux normal/race profiles and
all original stock-client/upgrade/34-stage portability controls remain required.
No skip, stand-in or earlier source establishes a native pass for this API.

Budgets are distinct from older explicit-set requests: 2 MiB encoded request,
1 MiB per original go.mod, 256 selected modules, 1,024 examined versions,
16,384 edges, 32 MiB parsed metadata and 16 MiB encoded response. Original store
plan metadata is separately capped at 32 MiB. The whole request has two minutes;
the final store transaction has 30 seconds. Existing explicit-set limits stay.

Proxy/group routing, private-source authority, workspace/local immutable input
resolution, package imports/platform closure, signed graph attribution, creation
fences, scanning/import/server sessions and complete operator outcomes remain
required. Existing migration definitions and the stopped primary are unchanged.
