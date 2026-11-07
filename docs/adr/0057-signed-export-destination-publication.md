# 0057: Import signed hosted bytes through normal destination publication

Date: 2026-11-07. State: implemented; native qualification pending.

`go-export-import` independently verifies the original complete signed journal,
selected signer and canonical export manifest before contacting the destination.
It uses the existing private offline preparation to copy, hash and inspect all
three original representations. The source is one hosted module version. The
original info bytes must be exactly reproducible by normal hosted publication;
optional/extended/alternate info representations are refused before a request,
not rewritten. Full dependency and authority closure remain required.

The operator selects a destination client configuration, hosted repository,
stable mutation key and new private attempt directory. Before the request, save
a durable nonsecret intent binding source proof attribution/export/representations
to destination authority/repository/key. Send only the exact ZIP, its checksum,
original timestamp and mutation key through normal hosted PUT. The destination
uses its common current authorization, forced RLS, immutable staging, inspection,
publication transaction, journal, receipt and job intent. No source approval,
scan cleanliness, repository grant or legal policy is sent as destination authority.
Missing destination scan evidence stays unassessed; current review policy governs
serving separately.

Require HTTP201 and its canonical publication tuple with all three exact source
digests. Reject oversized, ambiguous, changed, compressed, redirected or failed
responses. Only then atomically publish a private import receipt using ADR0056.
The receipt records publication, not current serving admission, scan cleanliness,
checksum authority or dependency closure. No automatic retries or approval.

A lost response can follow a committed destination transaction. Preserve every
attempt directory and its original intent. Explicit retry uses the same key and
source inputs with a new private directory; normal destination idempotency
rechecks the current write grant before returning its original receipt. A corrupt
existing local intent or receipt is never replaced. Local evidence remains
separate from a future durable server import/provenance session, bulk progress,
restart continuation, source-proof retention and full import workflow.

Sixteen local HTTP/filesystem stand-in cases cover exact upload/intent/receipt,
changed info/ZIP/shared files, irreproducible info, existing intent, denial,
coordinate conflict, lost response, redirect/compression and ambiguous/oversized
receipts. ARM build/unit/race/lint and normal/race tagged compilation/vet pass.
The existing native collector test adds a scoped publisher, real committed
publication followed by deliberate actual-socket closure, explicit replay with no
extra journal event, three unassessed/unserved destination references, current
grant revocation and preservation of a conflicting coordinate. Original signed
collector/metadata/stock SDK checks remain. These native cases are compiled only
locally and require actual GitHub qualification; no local native campaign.

No schema or primary changes. Require all274PG/96Go normal/race,56fuzz/19main151
and every original selected stock/upgrade/portable profile. No new import browser
workflow, complete scan integration, full closure, server import provenance,
Windows, provider, backup/GC/HA or scale claim. All450capabilities/41families/later
GOAL4.1 scope and broad readiness remain incomplete.

The console now supplies an explicit destination-publication instruction dialog.
It requires a valid destination repository before producing a copyable command;
private destination config, stable mutation key and fresh attempt directory are
chosen on the operator's machine. Use the independently selected original signer,
never the adjacent bundled key by default. The browser contacts no destination.
Completed historical files remain usable after source expiry without restoring
download access or granting destination approval. This is an instruction surface,
not a durable server import/provenance session or progress monitor.

DEFECT0134's controlled JavaScript probe found null source coordinates accepted
by the old binding guard and then rejected by a throwing command constructor.
Strict bounded source types and safe rendering now withhold commands for invalid
records/lists.35JavaScript and9shell/argv stand-in checks pass. The existing
Chromium UI response-stand-in workflow adds import/invalid-record controls and
retains every original assertion;19mainworkflows/151expected checks remain. Actual
new Chromium qualification is pending, distinct from local build/lint/unit proof.

Native qualification now additionally requires trusted loopback TLS for the
collector/importer and refusal of an unrelated valid CA before any application
request. HTTP/1.1 is explicit for the existing actual post-commit socket-close
fault; this supplies no HTTP/2 qualification. Fresh stock Go consumers must fail
while destination bytes are unassessed, consume exact original h1/inert bytes
after explicit destination manual decisions through the current CLI/API, refuse
wrong TLS trust and later policy/read-grant denial. Each gets a separate private
cache/NETRC; no warm client cache can stand in for a new serving decision. Manual
review is distinct from scanner cleanliness. These additions are compiled/vetted/
linted locally only; actual native replay, full import/provenance/closure and
all original profile/platform requirements remain open.
