# 0055: Collect a signed hosted Go snapshot with resumable private files

Date: 2026-11-07. State: implemented; new native qualification pending.

The durable export API can serve authenticated, generation-fenced ranges, but
operators currently assemble its files manually. Add `go-export-collect` to
collect one exact hosted export and the original complete signed journal proof.
This advances the existing export/session workflow; full dependency, authority,
permission and provenance closure and destination import remain required.

Verify the complete supplied journal/checkpoint and independently selected public
key before contacting the server. Download the bounded canonical manifest and
bind it to that original creation event before selecting any package bytes.
Use an owner-private client config, TLS verification, no redirects/compression,
explicit export ID/generation and bounded range requests to the same authority.
Persist eight fixed members: ZIP/mod/info, manifest, complete journal, checkpoint,
signature and public key. Hash every copied file against the authenticated bytes.
No token/config/private key, package execution, server acknowledgment or new
signing service is introduced. A copied adjacent public key never supplies trust
for a later consumer: independently select the original signer again.

A new directory needs an owner-private parent. Explicit `--resume` alone permits
continuation in an existing directory; immutable binding metadata must match the
original authority/export/manifest/proof/file identities. Hold a nonblocking OS
directory lock, refuse links, shared files, unexpected entries and public modes,
and sync bounded checkpoints. Partial files have no completion claim. Rehash the
whole file after resumption, require exact range/content-length/digest/generation
headers, and recheck current authenticated serving before writing a synced local
receipt. A later explicitly supplied renewed generation may resume the same
immutable snapshot; a changed manifest or proof cannot. Completed receipt replay
preserves original bytes and requires revalidation. Failures preserve owned
partial files and give a concrete resume action, without a success receipt.

The receipt proves collection of the signed historical snapshot only. Current
registry/destination admission, checksum authority, dependency closure and remote
delivery acknowledgment remain false. Revocation cannot recall already received
bytes. Linux/macOS file semantics must be exercised on actual hosts; Windows ACL
and directory durability remain required and explicitly unsupported by this path.

Owned HTTP/stream/filesystem stand-ins support local unit/race checks. Require
actual native PostgreSQL/CAS/server socket, candidate CLI, external OpenSSL and
stock Go tests on GitHub for integration claims, including interruption/resume,
renewal, changed input, current policy/credentials, completed replay and an offline
consumer using the collected proof. Existing source16 definitions and primary11
remain untouched. Full GOAL scope and readiness gates stay open.

The console exposes both initial and explicit-resume commands and still withholds
unsafe/stale generations. Its existing UI response-stand-in assertions now check
the collector and resume action; no additional real database claim follows from
that browser test. A single integration-only server test launches the candidate
collector, external OpenSSL and pinned native Go. The architecture checker permits
execution only in that exact `_integration_test.go` file with the exact integration
build tag; three source-fixture tests preserve the production exec/crypto/EE/RLS
boundaries. This exception does not affect the registry binary.

The new first CLI fuzz target is included by enumerating both `cmd` and `internal`
product sources. All 55 old targets remain; the expected new total is 56. Expected
native inventory is 274 full PostgreSQL functions and 96 named Go functions
normally/under race on both Linux hosts, with original 312 Go/683 baseline checks,
15 historical binaries/20 upgrade reports per host, 19 main Chromium workflows/
151 checks and the separate 16-stage producer/consumer lane. Every selected job
must identify its exact source and limits before acceptance. The new native test
uses an explicit second-range HTTP barrier, kills the real collector process,
renews its server generation, resumes, verifies replay and corrupt-receipt/tenant/
policy/revocation failures, then independently verifies and downloads inert files
with the stock SDK. It does not qualify registry/server death, broad socket faults,
actual clock shifts, full closure or broad scale.
