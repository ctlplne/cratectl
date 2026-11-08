# 0074: Verify Windows configuration protection through the open handle

Status: implemented locally; Windows runtime qualification remains required.
All owner-amended GOAL4.1 scope remains committed. This does not qualify Windows
server operation, offline collections, publication locks or installation.

The shared configuration reader previously treated Windows' synthesized mode bits
as POSIX permissions. Consequently a private configuration or token could not be
used by the native Windows CLI. Checking only those bits would also fail to prove
Windows access control. The Windows path now uses the OS security descriptor of
the actual opened file.

The reader rejects oversized paths, alternate data streams, nonregular files,
final reparse points and changed identities. It opens the disk handle without
following a final reparse point and denies shared writes/deletes for the lifetime
of that reader. Private files must have one hard link, the current effective user
as owner and a protected, present, non-NULL DACL. Every effective ordinary allow
entry must name that owner, Local SYSTEM or built-in Administrators. Those OS
administrators already have root-equivalent control. Other users/groups, callback
or object ACEs and unprotected/oversized ACLs refuse. Denies never create access;
the OS must also grant the requested actual read access.

The OS descriptor is bounded to128KiB,64 ACEs and184-byte SID strings. ACE and SID
ranges are checked within the copied descriptor before decoding. No data is read
or returned until handle identity and ACL validation succeed. Nonprivate public
inputs retain regular-file, identity, size, reparse and stream checks without
requiring a private DACL. Unix reader semantics remain unchanged.

Use the pinned BSD-3-Clause `golang.org/x/sys v0.49.0` Windows API bindings. No
credential is written, permission changed or privilege enabled by the product
reader. Provision credentials with protected ACLs at creation, or within an already
private folder before making the individual file's ACL protected. The unit fixtures
create only owned temporary files through explicit Windows security attributes;
they never repair a user's existing permissions or print credential values/SIDs.

Two platform-independent decision tests exercise bounded synthetic ACL records.
Six Windows-only native functions require real owner/protected ACLs and the
owner/SYSTEM/Administrators profile; broad, inherited and NULL DACL refusal; actual
NTFS hard links/streams; actual symlink refusal; handle write/rename exclusion; and
the clean native candidate CLI over a trusted TLS management-response stand-in.
The CLI must refuse a broad config/token and unknown fields before any HTTP request.
The management server is a declared stand-in, not a real PostgreSQL registry.
Missing native fixture capabilities fail; no skip becomes a pass.

The first Windows CI profile must run these functions plus the pure decision and
read-budget regression on actual x64 and ARM64 Windows hosts. Pinned Go/Python
architecture, embedded clean candidate identity, bounded execution/output and
closed safe evidence remain required before a native claim. Existing20-contract
12c6/78a campaigns must finish their original qualification before a new mandatory
Windows workflow/validator boundary is published. No existing job is restarted.

ARM build/unit/race/lint and Windows x64/ARM64 CLI/test compile/vet are local checks
only. Actual Windows ACL enforcement, symlink capability, sharing behavior and
native CLI execution are unverified until GitHub runs the exact source. GitHub's
documented standard public labels are `windows-2025` and `windows-11-arm`; label
availability is not test evidence.

A separate common-reader regression reproduced an integer overflow when adding
the one extra byte used to detect over-budget input: `ReadBytes(MaxInt64)` returned
empty successful bytes for a nonempty file. Reject that unsupported budget before
opening the file, while retaining exact bytes at MaxInt64-1. The original local
failure is retained and the new normal/race regression passes. Native source gates
must also run it; no external exploit or security release claim is inferred.

References: [Microsoft handle-based security information](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
[NULL versus empty DACLs](https://learn.microsoft.com/en-us/windows/win32/secauthz/null-dacls-and-empty-dacls),
[security for new objects](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptors-for-new-objects),
[pinned Go Windows API](https://pkg.go.dev/golang.org/x/sys@v0.49.0/windows),
and [GitHub native runner labels](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job).
