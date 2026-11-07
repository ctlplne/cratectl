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
