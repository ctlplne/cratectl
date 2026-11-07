# Export and verify a bounded journal range

The bounded range/signature foundation is qualified at a3d8df2 within the named
native profile: all257PostgreSQL functions normally/race on both actual Linux
hosts,683baseline checks including11actual OpenSSL3.0.13 checkpoint controls per
host,50fuzz/source gates on three hosts and18main x86 browser workflows/141checks
with three declared UI response stand-ins. See the
[exact-source checkpoint](../evidence/2026-11-07/github-a3d8df2-checkpoint.json).
This does not declare complete export, signing-provider or release readiness.
The later signed one-version Go collection/publication journey has separate
[badb85b native Go evidence](../evidence/2026-11-07/go-module-badb85b-native-checkpoint.json).
The multiple-event selection extension below still requires native qualification.

The tenant journal retains original event payloads. Each event hash covers the
previous hash, one newline and the exact original payload bytes. The new export
path verifies every consecutive sequence, tenant binding and hash link through
an exact terminal checkpoint. It does not reconstruct old payloads from current
database state.

A hash returned beside its data cannot authenticate itself. Before attributing
an export to cratectl, obtain the exact tenant, terminal sequence and terminal
SHA-256 through a separate trusted record or your existing external signing
tool. Verify that external record using independently configured trust. The
server checkpoint endpoint is explicitly unsigned. External signing/provider
adapters remain required work; cratectl does not run a signing or key-custody
service.

## Observe and authenticate a checkpoint

Use a current tenant administrator credential and the private client JSON from
installation. This read returns an observation, not independent trust:

```sh
umask 077
cratectl --config "$CRATECTL_CLIENT_CONFIG" \
  --path /api/v1/audit/checkpoint --raw-response > unsigned-checkpoint.json
```

The response contains `checkpoint: {tenant, sequence, hash}`, `signed: false`
and trust instructions. Genesis is sequence zero with an empty hash. Preserve
the exact observation and authenticate it outside the downloaded evidence.
Do not silently replace a previously authenticated checkpoint when a different
server hash appears.

After checking that separate trust path, set these environment variables from
the authenticated record. They are ordinary checkpoint values, not credentials:

```sh
export CRATECTL_TRUSTED_TENANT=your-tenant
export CRATECTL_TRUSTED_JOURNAL_SEQUENCE=123
export CRATECTL_TRUSTED_JOURNAL_HASH=the-exact-64-character-lowercase-sha256
```

The example values are placeholders. Sequence and hash must come from the
same record and tenant. Empty hash is accepted only for sequence zero.

## Collect a fixed range

```sh
umask 077
cratectl journal-export --config "$CRATECTL_CLIENT_CONFIG" \
  --tenant "$CRATECTL_TRUSTED_TENANT" \
  --through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \
  --through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" \
  --output ./cratectl-journal.jsonl
```

Collection starts at genesis by default. It uses the configured CA, verifies TLS,
refuses redirects and allows cleartext HTTP only to a literal loopback address.
Every request requires current administrator authority. A revoked or expired
credential cannot reread an old export page. The client follows only verified
advancing cursors while retaining the same terminal sequence/hash. Later journal
appends cannot move that range boundary.

The output file must be new; an existing file or symlink is never replaced. It is
created with mode 0600. Each page is verified before retention. The client syncs
the file and streams the complete saved bytes through the offline verifier,
including EOF, before emitting a success receipt. A failed collection leaves an
incomplete private file and returns nonzero without a success receipt. Preserve
that file and investigate. To retry, choose a new output path and retain the
same independently authenticated bindings.

For an incremental range, also supply `--after` and `--after-hash` from a
separately trusted prior checkpoint. The selected events are strictly after
that sequence and through the terminal sequence, inclusive. An identical
start/head produces one empty range page. Genesis exports use explicit
`--through 0 --through-hash ''`.

## Verify independently while offline

Copy the private file and independently authenticated checkpoint to the
verification machine. No server, database, credential, signer or network is
needed:

```sh
cratectl journal-verify --export-file ./cratectl-journal.jsonl \
  --tenant "$CRATECTL_TRUSTED_TENANT" \
  --through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \
  --through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH"
```

Use matching `--after`/`--after-hash` for an incremental export. The receipt names
the tenant, start/head bindings, page/event counts, exact input-file SHA-256 and
`matches_supplied_checkpoint`. This means the entire supplied range matches
the provided checkpoint. Attribution depends on the checkpoint's separate trust
path. Event integrity does not prove arbitrary event claims, external delivery,
security cleanliness or package admission.

Empty input, a missing terminal page/newline, repeated/reordered/trailing pages,
wrong tenant/anchors, changed payloads, sequence gaps, unknown/duplicate wire
fields and exhausted budgets fail without a success receipt. No valid prefix
is treated as a complete export. Journal page records are canonical version-1
JSON followed by LF. Preserve exact response bytes. One optional blank line
between records is accepted for the generic management CLI's terminal newline;
pretty-printing or normalizing JSON is not accepted.

## Verify a checkpoint signed with an external tool

This additional profile passes11actual OpenSSL3.0.13/native registry and CLI
controls per Linux architecture at a3d8df2. Keep its result separate from a manual
supplied-hash match. It adds offline Ed25519 signature verification; external
provider requests/adapters and other signing formats remain required.

Prepare the exact selected tenant/head for your external signer. Preparation is
unsigned and does not read a signing key:

```sh
umask 077
cratectl journal-checkpoint --tenant "$CRATECTL_TRUSTED_TENANT" \
  --through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \
  --through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" > checkpoint.json
```

The small version-1 statement binds its profile, journal-integrity purpose,
tenant, sequence and hash. Its canonical JSON includes a final LF. Preserve
those exact bytes. Have your own signer sign them, using its existing key or
provider reference. For example, an independently configured OpenSSL 3 Ed25519
signer uses raw input with no separate digest option. Its signing key stays
outside cratectl. [OpenSSL command specification](https://docs.openssl.org/3.0/man1/openssl-pkeyutl/).

```sh
openssl pkeyutl -sign -rawin \
  -inkey "$CRATECTL_EXTERNAL_SIGNER_KEY_REFERENCE" \
  -in checkpoint.json -out checkpoint.sig
```

Obtain the Ed25519 `PUBLIC KEY` SPKI PEM through an independent trusted channel
and set `CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE` to its path. A key bundled
with an untrusted export does not establish issuer trust. Optionally verify the
raw signature with the independent external tool:

```sh
openssl pkeyutl -verify -rawin -pubin \
  -inkey "$CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE" \
  -in checkpoint.json -sigfile checkpoint.sig
```

Both `journal-export` and `journal-verify` accept these three additional flags
together:

```sh
--checkpoint-file ./checkpoint.json \
--checkpoint-signature-file ./checkpoint.sig \
--checkpoint-key-file "$CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE"
```

Retain the original tenant/through/through-hash arguments. They must match the
verified signed statement exactly. Signature verification occurs before new
output creation or journal processing. A complete verified range receipt also
contains `checkpoint_signature.signature_verified`, the statement SHA-256 and
the trusted public key's SPKI DER SHA-256. Manual mode omits this field and does
not claim an external signature. A signature failure, wrong purpose/key/head,
partial flag set, private-key input or incomplete range emits no success receipt.

Statements are at most 2 KiB, signatures are exactly 64 raw bytes and the single
public-key PEM is at most 4 KiB. The statement file must be owner-private. Only
the external signer handles its private signing key. No signer/key generation,
signing command, CA or timestamp service is added to cratectl. A historic signed
checkpoint remains historic; this profile does not prove latest history,
signature time, external delivery, event truth, key revocation or package safety.

## Select several original events in one offline pass

For an export containing several original events, repeat `--select-event` on
`journal-verify`. Use exact sequence values from the artifact's source records
and the same independently authenticated signed terminal checkpoint:

```sh
cratectl journal-verify --export-file ./cratectl-journal.jsonl \
  --tenant "$CRATECTL_TRUSTED_TENANT" \
  --through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \
  --through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" \
  --checkpoint-file ./checkpoint.json \
  --checkpoint-signature-file ./checkpoint.sig \
  --checkpoint-key-file "$CRATECTL_JOURNAL_TRUSTED_PUBLIC_KEY_FILE" \
  --select-event "$CRATECTL_FIRST_EVENT_SEQUENCE" \
  --select-event "$CRATECTL_SECOND_EVENT_SEQUENCE"
```

Each requested sequence must be distinct, after the range start and at or before
the signed terminal sequence. Selection requires all three signature flags;
ordinary unsigned verification continues to accept a separately trusted hash.
A successful `selected_events` array preserves request order and contains only
`sequence`, `hash`, `previous_hash`, `payload_bytes` and `payload_sha256`.
Original payload text is never printed. The input journal itself contains
private tenant payloads and must remain protected.

The verifier reads the entire range once, including every later page and EOF.
Truncation, corruption, trailing records or exhausted budgets return no selected
events or success receipt, even when every requested event appeared earlier.
At most256events may be selected. `--selection-bytes` bounds retained original
payload bytes, defaults to4MiB and accepts1–64MiB; parser/page/input/time budgets
still apply separately. This identifies historic original bytes. It does not
establish package approval, current permission or complete dependency/provenance
closure, and does not itself create a multi-artifact export bundle.

## Bounds and failure handling

- API pages contain at most 1,000 events and 2 MiB including framing. Original
  event payloads may contain at most 256 KiB. PostgreSQL first returns bounded
  size/hash metadata; only selected payloads cross the database connection.
- The API may shorten a page before reaching its event-count limit. Follow
  `more`, `next_after` and `next_hash`, rather than inferring completion from a
  short page. The older `/api/v1/audit` list now also returns `more/next_after`
  with equivalent byte bounds. Its moving observation remains a live list.
- Both commands default to a 1 GiB file budget and five-minute total timeout.
  `--max-bytes` may be 1–64 GiB; `--timeout` may be positive through one hour.
  Collection uses one request at a time, a one-minute per-request timeout and
  at most 65,536 page records. The offline verifier separately bounds frames,
  individual events, parser allocation and total input bytes.
- `journal_checkpoint_changed` (409) means a supplied anchor is absent or
  differs from retained history. Preserve the trusted checkpoint and original
  evidence; a newly fetched hash cannot authorize replacement trust.
- `journal_evidence_limit` or `journal_evidence_unavailable` (503) means this
  retained range exceeds the supported profile or fails original integrity
  checks. Unsupported large events are not skipped or called clean. A
  separately qualified large-event recovery path remains required.

In the console, **Audit → Complete journal export** explains unsigned trust and
provides commands that require separate checkpoint variables. Values outside
exact browser integer precision disable copy actions; use exact API/CLI values.
**Export this page · JSON** remains a scoped view download, not a full verified
journal. Protect downloaded audit data as private tenant evidence.

This foundation does not finish signed export manifests/adapters, Go package and
proof bundles, backup/restore, export/GC protection leases, offline cache/install,
large-history performance, all browsers/platforms or the remaining GOAL scope.
The independently reproduced Go client trust-state failure (DEFECT.0126) remains
open and separate from journal verification.
