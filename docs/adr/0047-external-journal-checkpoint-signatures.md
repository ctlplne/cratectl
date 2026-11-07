# Verify externally signed journal checkpoints

Status: implemented and qualified at a3d8df2 in the named bounded native profiles.
Eleven actual external OpenSSL3.0.13/registry/CLI controls pass per Linux host with
exact tool/public statement/signature/PEM/DER/export hashes; all257PG normal/race,
50fuzz three hosts and18main Chromium141checks pass. Original ca fixture failures
and strict client0126 failure remain preserved separately. Full provider requests,
artifact signing policy and complete export bundles remain required. First14source
migrations stay frozen; stopped primary11 is untouched.

## Trust path and product boundary

The unsigned journal observation and manually supplied terminal hash are useful
integrity inputs, but customers need a standard external tool path for signed
checkpoint attribution. Add verification of a small canonical statement signed
outside cratectl using an independently trusted Ed25519 public key. OpenSSL 3
`pkeyutl -sign -rawin` provides the first ordinary-tool interoperability profile;
this is additive to the required Sigstore/Cosign/Notation/provider work.
See [OpenSSL's command specification](https://docs.openssl.org/3.0/man1/openssl-pkeyutl/).

cratectl accepts no signing private key, generates no customer signer or signing
identity, runs no signing command in the HTTP process, and operates no CA,
signing/custody/timestamp service. Customers sign exact prepared bytes with their
own tool/provider. Preparing an unsigned statement is not a signature. Durable
authenticated external signing requests/provider adapters remain required later
work; this read-only verifier does not claim to implement them.

## Signed statement

The versioned canonical JSONL statement binds fixed profile and purpose strings,
tenant, terminal sequence and hash. Sign the exact statement bytes, including
its final LF. Bound the statement to 2 KiB, a single Ed25519 SPKI PUBLIC KEY PEM
to 4 KiB and the raw signature to exactly 64 bytes. Reject unknown, duplicate,
case-aliased, null, reordered or noncanonical fields and extra bytes/PEM blocks.
Verify in internal/crypto only and return the public key's SPKI SHA-256 and exact
statement SHA-256. A public key delivered inside an untrusted export is not
independently trusted.

Keep the existing separately specified tenant/through-sequence/hash arguments.
The verified signed statement must match them exactly before collecting or
verifying the journal file. This prevents silently substituting another tenant
or terminal boundary. A historic signed checkpoint is a historic statement;
neither this profile nor a self-reported time proves freshness, latest history
or external delivery. No trusted timestamp, key rotation/revocation service or
automatic rollback policy is invented.

The CLI prepares canonical unsigned checkpoint bytes from exact tenant and
terminal sequence/hash arguments chosen for the external signing operation. Optional statement/signature/
trusted-key flags on both export and offline verify are all-or-none. Read and
verify them before opening new output or processing journal data. A bad signature
or binding produces no success receipt. A complete success receipt distinguishes
matching a supplied hash from verifying an external checkpoint signature. The
old manual-checkpoint mode remains available and explicitly unsigned.

## Evidence

Use ARM parser/unit/race/fuzz and public generated test fixtures for development.
Run actual OpenSSL signing/verification and the native cratectl collector/offline
verifier in the existing GitHub real-registry profile on both Linux architectures.
Generate only disposable test keys in that runner's private directory; never
upload them or treat generated unit fixtures as stock-tool interoperability.
Preserve actual tool version/binary hash and fixed control outcomes in reviewed
safe summaries, with raw records staying private. Exercise changed statement,
wrong public key, wrong signature, wrong tenant/head, partial flag sets and
malformed/oversized/private-key input. Never weaken earlier journal or checksum
client assertions. No new schema or retained-primary maintenance is needed.

Full export bundles, external provider requests/adapters, signer authorization,
artifact signature policy, disconnected operation, backup/restore/GC leases,
large history and every other GOAL requirement remain committed and incomplete.
