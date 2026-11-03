# Bounded NuGet archive identity

`InspectArchive` reads package identity and exact Nuspec bytes from one immutable
staged ZIP view. It never extracts files, loads assemblies, invokes MSBuild or
runs package scripts. The caller must retain that exact byte object and bind its
digest through the common publication transaction. This parser does not publish,
approve, scan or verify a signature, and it does not supply a NuGet feed.

The reader accepts a single ZIP32 archive with stored or deflated members.
Before the standard ZIP reader can allocate file records, it bounds and counts
physical central-directory records. EOCD's declared count alone is insufficient.
Local headers, names, flags, sizes and optional descriptors of 12 or 16 bytes must agree
with the central directory. Referenced spans cover the local region exactly;
overlap, hidden members, prefixes and unreferenced trailers fail closed.

Caller-provided compressed, expanded, directory and file budgets are positive
admission limits. This implementation additionally bounds directories to 16 MiB,
records to 16,384, raw ZIP32 bytes below 4 GiB, total declared expansion to 1 TiB,
paths to 2,048 UTF-8 bytes and 64 components and Nuspec bytes to 1 MiB. These are parser
safety bounds; they do not cap repository counts or impose edition limits.
ZIP64, split archives, alternative compression and other unsupported layouts
remain implementation and qualification work.

Paths reject traversal, absolute/drive/alternate-stream forms, separators that
other clients reinterpret, encoded aliases, control/invalid text and reserved
Windows names. Non-ASCII names require an explicit UTF8 flag. Conservative NFC
and Unicode simple-fold collision keys reject duplicate paths and file/ancestor
conflicts without rewriting the declared paths. Links, devices, alternate-path
extra records and ambiguous root Nuspec selection are rejected. These admission
rules do not establish native Windows/macOS extraction compatibility.

All member bytes stream through fixed 32 KiB buffers. Only the bounded root
Nuspec is retained. CRC32, including a declared zero, is checked through
`internal/crypto`; it is a ZIP compatibility checksum, never content authority.
The inflater exposes its consumed compressed-byte count, preventing read-ahead
from hiding trailing member bytes. Cancellation and every invalid observation
return no partial identity. The shared bounded Nuspec parser then derives the
version key while preserving declared text and original manifest bytes.

Regression tests cover actual stored/deflated ZIPs, signed/unsigned descriptors,
UTF8 paths, malformed headers/extras/counts, resource budgets, aliases/ancestors,
special files, corrupt/zero CRCs, trailing compressed data and cancellation.
The first scratch trailing-data failure and integrated architecture-check failure
are retained in [development evidence](../../evidence/2026-11-03/nuget-archive-development.json).
Local tests do not qualify a package client or the complete archive format.

The native SDK workflow adds four owned ZIPs to the existing version/Nuspec
contract. Actual `NuGet.Packaging.PackageArchiveReader` must agree on identity,
selected Nuspec path and exact manifest bytes for stored/deflated UTF8/UTF16
fixtures. Compilation and comparison remain unverified until GitHub runs them.
The fixture has no package references or remote package sources. Payloads remain
opaque; neither this fixture nor the server executes uploaded content.

Microsoft describes the [NuGet ZIP package format](https://learn.microsoft.com/en-us/dotnet/standard/library-guidance/nuget)
and the [package content/Nuspec API](https://learn.microsoft.com/en-us/nuget/api/package-base-address-resource).
The public [PackageArchiveReader API](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Packaging/PackageArchiveReader.cs)
is a behavioral reference; the Go implementation is original.

ID storage-key mapping, complete metadata/dependency/symbol/signature semantics,
immutable publication and policy binding, hosted/proxy/group feeds, stock-client
publish/consume and every tenant/lifecycle/platform journey remain required.
