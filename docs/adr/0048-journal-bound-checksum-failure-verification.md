# Bind checksum failure verification to a signed journal range

Status: verified in the named809e826 native Go profile on both actual GitHub
Linux architectures:80Go PostgreSQL functions normally/race and the original
312stock hosted/group checks. The added function uses real original database
failure/journal bytes, actual external OpenSSL and the exact candidate offline
CLI; prefix/digest/context controls pass. Whole-candidate acceptance is separate.
See `evidence/2026-11-07/go-module-809e826-native-checkpoint.json`. Full Go/export
and the independent DEFECT0126 client failure remain open.

## Missing customer step

The existing offline Go checksum verifier requires an expected evidence SHA-256
from an independently trusted journal or manifest. Journal collection and an
external checkpoint signature now provide the ingredients, but operators still
have to select the correct original event and copy that digest themselves.
Complete this path without trusting a download's adjacent hash or current
repository settings. This remains evidence verification under GOAL4.1; no signer,
CA, key custody or external credential lifecycle belongs in this change.

## Verify the complete range before selecting a result

Add bounded selection of one exact event sequence during streaming journal
verification. Retain only that original event, at most256KiB, while verifying
every page and the terminal checkpoint. Return neither the selected event nor
a success receipt until the full range and EOF pass. Later truncation, tampering,
reordered/duplicate pages, wrong anchors, cancellation, reader errors or resource
limits must discard the selection. Require the target strictly after the start
and no later than the terminal sequence. Never expose a callback that acts on an
unverified prefix. Original range verification behavior must remain unchanged.

## Bind the actual Go failure record

Only an original `proxy.retrieval.failed` event with an exact lowercase
`go_checksum_failure_digest` can supply automatic attribution. Its tenant,
repository, path, source revision and generation must match the exact canonical
failure record. Parse required envelope/data keys case-sensitively and reject
duplicate, null or inconsistent bindings. Retain legitimate extra event metadata
without treating it as additional proof. Old bare fork labels have no such
digest and remain unattributed; never reconstruct them from current settings.

The CLI's automatic journal mode requires a separately trusted external
checkpoint public key and matching statement/signature, exact tenant/start/head,
the private complete journal file and explicit event sequence. Verify the
external statement, complete journal range, selected original event bindings,
exact failure-record bytes and checksum authority signatures. Keep manual
`expected-sha256` mode available. If both bindings are supplied they must agree.

Only after every check may the result identify the selected journal event/hash,
file hash and checkpoint signature proof. Original upstream bodies, package
coordinates, configured keys and unrelated journal payloads remain private.
Unverified observations remain nonzero outcomes, never clean/fork/admission
success. An authenticated journal range proves attribution relative to the
trusted signer checkpoint; it does not prove event truth, current package policy,
latest history, external delivery or package admission.

## Qualification

Preserve earlier cases and first native failures. Use ARM crypto/parser/CLI unit
and bounded fuzz tests locally, compiling/vetting real-PG suites only. Exercise
actual retained failure/journal bytes, exact immutable event binding, current API
authorization and typed evidence in native GitHub PostgreSQL normal/race tests.
Run the operator's actual offline CLI path with an ordinary external signing tool
in the existing bounded native profile. Public generated unit fixtures and UI
response stand-ins are separate claims, not stock-tool or database proof.

Implementation adds one actual-PostgreSQL Go function which records a genuine
typed failure, exports its immutable range, selects the exact original event,
checks tenant/generation/digest binding, rejects a truncated suffix, and invokes
the owned native CLI with an actual disposable OpenSSL checkpoint signature.
It compiles/vets only on the ARM development host; GitHub has executed it normally/race.
No test signer process or private key is part of the product's HTTP runtime.

No migration or retained primary maintenance is required. Full Go package/proof/
policy export bundles, durable external signing adapters, offline cache/install,
backup/restore/export-GC protections, conditional refresh and all450capabilities/
41families/later GOAL stages remain committed and incomplete. DEFECT0126's strict
three-host Go client trust-state failure remains independent and open.
