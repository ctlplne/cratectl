# Hosted Go bytes from an authenticated historical publication

Status: implemented but native unverified. The new command and binding/file tests
pass on the ARM development host. The real PostgreSQL/CAS, external OpenSSL,
candidate CLI and stock Go SDK journey is assigned to GitHub, normally and under
race. First d179222 both-Linux runs fail only TempDir cleanup of default read-only
Go cache directories (DEFECT0128). Keep those failures and skipped stages; the
fixture repair uses pinned `go clean -modcache` only on its isolated cache, with
all original assertions/default permissions unchanged. Native replay remains
required. No migration, server export session or current policy transfer is added.

## Complete one historical package before preparing its file proxy

An original `go.module.published` journal event already binds a hosted repository,
canonical module/version and the SHA-256 of all three original representations.
Use that original record to prepare bytes for a disconnected customer who trusts
the journal signer. Require an independently chosen tenant, repository, module,
version and original event sequence. Verify the complete journal through its
externally signed terminal checkpoint before exposing the selected event.

Reject duplicate, aliased, null, missing or inconsistent required event fields,
additional representation identities, wrong event kinds and malformed digests.
This validates the recorded publication; it does not turn a retrieval-ready event,
current label or adjacent hash into a hosted publication. No signer or private
key is accepted by the product.

Copy the three private regular input files into a newly created private output
directory. Bound compressed ZIP to512MiB, go.mod to1MiB and info to64KiB. Hash
the copied bytes against the authenticated event, then inspect those same staged
files with the shared native Go archive validator:512MiB total expansion,
16MiB central directory and16384entries. Require root go.mod consistency and
canonical version/time metadata. Never execute or extract module code in the
product. Use bounded reads and a finite timeout.

Create no native `proxy` tree until all checks pass. Write/sync each file and a
private receipt, sync created directories, rename the complete staged tree into
place and sync the output/parent directories before reporting success. Preserve
any existing output. On failure discard only the new incomplete directory and
emit no success receipt. Linux/macOS semantics are explicit; Windows needs its
own private ACL and durability implementation/qualification.

The receipt records raw identities, computed native h1 values, journal/signature
proof and the exact file GOPROXY URL. `current_registry_admission` and
`checksum_authority_verified` remain false. Historical publication integrity
does not establish current authorization, scan approval, latest/revoked history,
dependency closure or consistent export policy. An operator approves exact
packages for the disconnected environment. This hosted/private profile uses no
public SumDB service. DEFECT0126 remains failed and independent.

## Required producer and broader offline outcome

This byte preparation is one consumer of the eventual export protocol. It does
not close the complete Go/offline/export capability. Implement a durable,
bounded export session in PostgreSQL with forced RLS and immutable item identity.
Create its journal, idempotency receipt and job intent in one transaction under
the existing tenant mutation fence. Stage and sync immutable manifest bytes before
committing their references. Recheck the exact snapshot after external storage
I/O instead of holding a long SQL transaction while copying bytes.

The future session must bind repository/source epoch, complete package/proof
objects, original public authority/checkpoint history, relevant policy decisions
and the journal range. Pin every object against physical GC for the explicit
session lifetime, including pending/resumed transfers and the manifest itself.
GC must recheck current protections under the same mutation fence as publication
and export transitions; a cached mark list is insufficient. An expired or lost
fence must prevent completion. Current authority/policy checks govern new online
requests; retained export policy describes historical context and does not grant
live serving rights.

Provide current-authorized preview/create/resume/download/cancel API/CLI/console,
finite retention/renewal and observable failure recovery. Verify proxy SumDB
evidence against separately trusted authority and retained checkpoint history,
never a bundle's own key. Build and verify complete bounded transitive dependency
closure, install using stock clients on actual isolated native hosts, and import
through ordinary current authorization/scanning/policy rather than copying old
approval into the destination. Test GC/delete/deny/source changes, interrupted
copy/restart/expiry, key changes, malformed archives and large directories.

Any new durable schema is append-only after the fourteen frozen definitions and
requires actual historical/native upgrade qualification. The stopped primary11
and selected qualified binaries remain unchanged. Backup/restore, provider
adapters, other formats and all450/41/later GOAL scope remain required.
