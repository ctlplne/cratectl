# Inspect a checksum authority incident

This inspection surface is available for retained, privately configured Go proxy
records. Public Go proxy creation and protocol routing remain gated. It does not
establish complete Go proxy support or release readiness.

A checksum authority signs a log of module hashes. An authenticated fork means
the same configured key signed conflicting history. cratectl retains the original
bounded observations and its separately retained signed checkpoints, and blocks
that exact key throughout the tenant. Retrying, changing the source or restoring
the repository cannot reset that block. Selecting an externally trusted new key
is an explicit trust decision; cratectl does not issue keys or signing identities.

An **unverified observation** means the retained data did not authenticate a fork.
It can be an unavailable authority, malformed response, missing proof or an
explicit storage-policy/known-credential omission. It is neither a clean verdict
nor package approval. A false `blocked` state is not a recent authority contact
or health check. Ordinary package review, lifecycle and current proof policy
still apply to serving.

In the console, open **Checksum inspection** on a retained Go proxy repository.
Readers with repository access can inspect the safe checkpoint/key state. Current
tenant administrators can page failure summaries and obtain private export
commands. Inspection does not automatically download raw bodies or mutate trust.
Administrators can explicitly open the separate legacy incident recovery flow
described below; preview and acknowledgment are required before recording review.
It refuses commands and pagination when an identifier exceeds JavaScript's exact
integer range; use the CLI/API for exact 64-bit values. Refresh observations after
source changes. A stale source revision must not select different trust silently.

Read current state with the repository's exact observed source revision:

```sh
cratectl --config "$CRATECTL_CLIENT_CONFIG" \
  --path '/api/v1/repositories/REPOSITORY/go/checksum?source_revision=0'
```

Tenant administrators can list original failure identities. Follow `next_after`
only while `more` is true. Each page contains at most 100 summaries; bodies and
signed pins are excluded. This is live traversal, not a snapshot or scale verdict.

```sh
cratectl --config "$CRATECTL_CLIENT_CONFIG" \
  --path '/api/v1/repositories/REPOSITORY/go/checksum/failures?after=0&limit=25'
```

Select the exact `root_path`, historical `source_revision` and `generation` from
one summary. URL-encode the root path. The attachment contains the original
canonical record and may include sensitive source data. Save it privately and
use `--raw-response` to preserve its hashed bytes. The ordinary CLI adds a newline
to management responses for terminal readability; that changes canonical evidence.

```sh
umask 077
cratectl --config "$CRATECTL_CLIENT_CONFIG" --raw-response \
  --path '/api/v1/repositories/REPOSITORY/go/checksum/failures/evidence?root_path=ENCODED_ZIP_ROOT&source_revision=0&generation=2' \
  > go-checksum-failure.json

cratectl go-checksum-verify \
  --evidence-file ./go-checksum-failure.json \
  --key-file "$CRATECTL_CHECKSUM_PUBLIC_KEY" \
  --expected-sha256 "$CRATECTL_TRUSTED_EVIDENCE_SHA256"
```

Supply the public verifier key through an independently trusted channel. Supply
the expected evidence SHA-256 from a trusted audit journal or export manifest;
the download's header and adjacent summary alone do not independently authenticate
its cratectl tenant/repository attribution. The authority's signatures prove log
misbehavior; they do not sign cratectl's attribution fields. The additional
journal-bound mode below connects these separate trust paths. Full signed export
bundles and durable external signing/provider adapters remain required work.

## Derive attribution from a complete externally signed journal

Implementation status: development unit/race tests pass; actual typed PostgreSQL,
external-tool and native CLI/browser qualification is pending for this extension.
Public generated fixtures are unit inputs, not a native registry proof.

First follow [journal export](journal-export.md) to collect the complete private
range and authenticate its checkpoint with a separately trusted external signer
public key. Retain the original canonical statement, raw signature and public
key. Do not take either public key from an untrusted download alone: the journal
signer attributes cratectl history; the checksum authority signs module-log
history. They perform different jobs.

Select the exact event `sequence` from the administrator failure summary. The
selected original event must be inside the supplied range. Then run:

```sh
cratectl go-checksum-verify \
  --evidence-file ./go-checksum-failure.json \
  --key-file "$CRATECTL_CHECKSUM_PUBLIC_KEY" \
  --journal-file "$CRATECTL_PRIVATE_JOURNAL_FILE" \
  --journal-tenant "$CRATECTL_TRUSTED_TENANT" \
  --journal-event-sequence "$CRATECTL_FAILURE_EVENT_SEQUENCE" \
  --journal-through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \
  --journal-through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" \
  --checkpoint-file ./checkpoint.json \
  --checkpoint-signature-file ./checkpoint.sig \
  --checkpoint-key-file "$CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE"
```

For an incremental range, also provide `--journal-after` and
`--journal-after-hash` from its trusted start checkpoint. The target must be
strictly after that start and no later than the terminal checkpoint. Journal
input defaults to 1 GiB/five minutes; `--journal-max-bytes` may be 1–64 GiB and
`--journal-timeout` may be positive through one hour. The same per-event/page/
frame limits apply as in the general journal verifier.

The command verifies the external signature, every journal page through EOF,
and only then exposes the exact selected event internally. It requires the
original `proxy.retrieval.failed` event's typed evidence digest, tenant,
repository, module ZIP root, generation, source revision, failed state and
classification to match the canonical failure record. It also independently
verifies the original checksum authority observations and pins. A valid prefix
cannot supply attribution if a later page is absent, modified or unreadable.
Bare historical fork labels without an original digest remain unattributed.

Manual `--expected-sha256` mode remains available. If it is supplied together
with journal mode, both must agree. Automatic mode requires all three external
checkpoint files; an unsigned observed head cannot silently replace them.
Partial/orphan flags, wrong signer/authority keys, mismatched identity/digest,
noncanonical records and incomplete ranges fail without a partial receipt.

A valid result includes a small `journal_attribution` receipt containing the
exact event sequence/hash, complete input-file hash and checkpoint signature
proof. It omits original payloads, package paths and upstream response bodies.
An attributed but unverified observation still returns nonzero. Neither a
signed journal nor a proved authority fork approves package bytes, clears a
block, proves event truth/latest history or changes any server state.

In **Checksum inspection → Evidence commands**, the optional signed-journal
instructions preserve the exact selected event. Commands are unavailable for
unsafe integer identities, failed/loading history or a selection no longer in
the loaded page. Actual current authorization remains enforced by the API;
offline verification does not contact the server.

## Verification results and retained history

The verifier performs no network or database access. It requires an owner-private
regular evidence file of at most 2 MiB and separately supplied public key. It
checks exact SHA-256, canonical encoding, original bounded observations and both
retained signed pins. A proved fork produces a bounded JSON result and exit zero.
A valid but unverified observation produces its classification and a nonzero exit
status. Invalid bytes/trust produce no partial record. Output excludes original
bodies, module/repository attribution and configured key text. Neither result
approves packages or changes any server state.

Inspection of retained evidence remains authorized after repository suspension or
removal. Current administrator credentials and repository authorization are still
checked on every read; suspension does not turn evidence inspection into serving.

Prototype source-12 failure labels lack original proof observations and may lack
historical key attribution. They remain unresolved legacy incidents. Neither an
empty new history page nor an upgrade manufactures proof, clears such an incident
or establishes safe recovery. Legacy incident discovery, conservative quarantine
and a separately reviewed recovery path remain required before public Go proxy
mode is enabled.


## Recover an unattributed historical incident

Schema 14 adds a recovery path for old journal entries labelled
`upstream_checksum_fork` without matching original signed observations and a
retained key-block witness. Their original key may be unknown because settings,
source epochs and repository state can have changed. cratectl preserves each
original event and its hash. It does **not** call the old label a proved fork.
Until reviewed, each such incident blocks every checksum key in that tenant.
Another tenant remains independent.

Use a current tenant administrator credential. In **Checksum inspection**, open
**Inspect retained legacy incidents**. Inspect the original journal context.
Obtain a separate external trust assessment of the exact selected public key;
enter the SHA-256 of that review document and an explanation. **Preview external
trust review** binds the decision to the original event/hash and the exact current
repository source revision, key, signed checkpoint revision and checkpoint hash.
Check the explicit acknowledgment before **Record external trust review**. This
is your decision to trust an external key despite unknown old attribution. It is
not a claim that missing historical proof has been recovered.

The response retains the disposition and its synchronous journal sequence. The
console keeps the original bytes/idempotency key if a response is not confirmed;
**Retry same request** confirms the original result. Read the historical outcome
with **Read retained review**. Refresh current state separately: a receipt never
proves that the key is still usable. Every other unresolved incident still needs
review. Packages require a new normal proof/publication and current policy.
An authenticated fork always blocks its key and cannot be cleared by review.

The same bounded workflow is available through the CLI:

```sh
cratectl --config "$CRATECTL_CLIENT_CONFIG" \
  --path '/api/v1/go/checksum/legacy-incidents?limit=25&after=0'
cratectl --config "$CRATECTL_CLIENT_CONFIG" \
  --path '/api/v1/go/checksum/legacy-incidents/SEQUENCE'
```

Replace `SEQUENCE` with the exact original journal position, preserving all 64-bit
precision. Query the repository checksum state with its current source revision.
Prepare an owner-private JSON file containing these exact fields:

```json
{
  "repository": "REPOSITORY",
  "dry_run": true,
  "accept_unattributed_history": false,
  "incident_hash": "ORIGINAL_EVENT_SHA256",
  "expected_source_revision": 0,
  "key_digest": "SELECTED_VERIFIER_KEY_SHA256",
  "expected_checkpoint_revision": 0,
  "checkpoint_sha256": "CURRENT_SIGNED_CHECKPOINT_SHA256",
  "review_reference_sha256": "SEPARATE_EXTERNAL_REVIEW_DOCUMENT_SHA256",
  "reason": "Explain the external key trust decision and unknown old attribution"
}
```

Replace every placeholder and both revisions with the actual inspected values.
Hashes must be 64 lowercase hexadecimal characters. Submit the preview:

```sh
cratectl --config "$CRATECTL_CLIENT_CONFIG" --method POST \
  --path '/api/v1/go/checksum/legacy-incidents/SEQUENCE/reviews' \
  --body-file ./legacy-review-preview.json
```

After assessing that exact preview, save a separate apply file with the same
bindings, `dry_run: false` and `accept_unattributed_history: true`. Supply a new
8–128-character idempotency key. Preserve the exact file/key until confirmed:

```sh
cratectl --config "$CRATECTL_CLIENT_CONFIG" --method POST \
  --path '/api/v1/go/checksum/legacy-incidents/SEQUENCE/reviews' \
  --body-file ./legacy-review-apply.json \
  --idempotency-key "$CRATECTL_LEGACY_REVIEW_REQUEST_ID"
cratectl --config "$CRATECTL_CLIENT_CONFIG" \
  --path '/api/v1/go/checksum/legacy-incidents/SEQUENCE/reviews?key_digest=EXACT_KEY_DIGEST'
```

A new review with stale source/key/checkpoint or incident bindings returns 409;
inspect and preview again. A different body cannot reuse a committed key.
Authenticated fork blocks also return 409. Readers and expired administrators
cannot inspect original context or apply/replay decisions. All responses are
private/no-store. Pages contain at most 100 incidents; original journal payloads
are at most 64 KiB. The local event hash link alone is not an independently
trusted journal/export anchor.

For a retained Go proxy, **Sources** can replace the explicitly
supplied checksum verifier/bootstrap through the existing complete settings
replacement and source-revision preview. It requires valid checksum authority and
mandatory checksum enforcement, and checks any endpoint credential against its
exact approved URL. This does not enable new Go proxy creation or public routing,
reset a previously accepted key timeline, transfer an old review to a new key,
or bypass missing incident review. A key with a genuine authenticated fork stays
blocked even if configured again later.

Schema-14 maintenance preserves all thirteen earlier receipts and original
journal bytes under the exclusive schema gate. Forced tenant RLS stays on;
temporary owner-only source/insert policies are removed before runtime admission.
Original label links are checked in 64-row pages, with at most 100,000 labels and
64 KiB per event. Damaged links or exceeded bounds roll back the whole migration;
large-history qualification and a broader maintenance path remain open. Do not
apply this source migration to the retained primary without separate maintenance
authority. The named recovery/migration behavior is qualified by exact source5816 on both
native Linux hosts normally/under race. Console behavior uses two explicit
response-stand-in Chromium workflows, with real database enforcement separately
qualified. This does not qualify full Go proxy or checksum-on stock clients.
