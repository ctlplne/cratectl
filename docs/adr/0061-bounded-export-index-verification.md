# 0061: Bind selected export manifests through one signed journal pass

Date: 2026-11-07. State: implemented; named96Go normal/race/312stock passes onboth actual native
Linux hosts atca44b37. Full multi-artifact and whole-campaign qualification remain.

An operator preparing several artifacts needs to authenticate all selected
original export manifests before collecting their package bytes. Add
`go-export-index-verify`: one private canonical index selects1–256distinct
hosted module/version exports and absolute private manifest paths. Reject
ambiguous duplicate coordinates, export IDs or event sequences. Repositories
remain explicit; different repositories cannot silently supply competing bytes
for the same coordinate.

Verify the independently selected external checkpoint/key, then the complete
journal and EOF once, retaining selected original events in index order. Only
then read and bind each bounded canonical manifest to its exact original
creation event. Any later corrupt/absent manifest, wrong event, trailing journal,
context failure or exceeded byte budget returns no partial binding/receipt.
Original single-version collector/import/offline command behavior is unchanged.

Bound index bytes to256KiB, member count to256, each manifest to32KiB, retained
selected event payloads to4MiB, existing journal input to at most64GiB and its
existing page/frame limits. Sum declared representation sizes without reading
package files: default1GiB, operator-selected positive ceiling up to64GiB.
Verification uses a default5minute journal timeout, positive through1hour. Read
private regular files through the existing bounded/no-final-symlink path on
Linux/macOS; Windows needs its separately required ACL/durability implementation.

Emit only the index hash, complete journal/external-signature receipt and each
selected original export/event/manifest identity, sizes and total declared
representation bytes. Omit private paths, original event bodies and policy
metadata. Explicitly keep package-byte verification, dependency closure,
consistent snapshot, checksum authority and current admission false. A list of
separately created historical exports is not one atomic source snapshot.

This is the preflight foundation for multi-artifact collection and full
package/dependency/authority/permission/provenance closure. It does not create
that bundle, resolve dependencies, supply current authorization/scan evidence,
write a live destination or execute package code. All450capabilities/41families
and later GOAL4.1 scope remain required.

Require canonical/count/duplicate/path/byte/failure/privacy regressions, exact
256member acceptance and bounded parser fuzz locally. Extend the existing real
PostgreSQL/OpenSSL/candidate-CLI journey with two distinct original exports,
reverse-order binding and late-member/trailing/budget refusal. Keep all original
collector process-kill/renewal/metadata/TLS/destination/SDK assertions; actual
normal/race executions belong to both native GitHub Linux jobs. No local real
PostgreSQL/registry/signer/client/browser campaign or schema/primary change.

Actual two-export original PG journal/external OpenSSL/candidateCLI reverse-order
binding and late-member/trailing/byte-budget refusal pass normally/race onboth
Linux hosts. See `evidence/2026-11-07/go-module-ca44b37-native-checkpoint.json`.
This does not verify multi-artifact package bytes, closure, one common snapshot
or current destination admission; all five explicit trust flags remainfalse.
