# Bounded NuGet manifest identity

`ParseNuspecIdentity` reads an ID and version from immutable `.nuspec` bytes.
It preserves exact ID and raw-version text, including surrounding whitespace,
and derives only the version
key through the shared NuGet normalization contract. ID storage-key mapping,
full manifest validation and repository publication are separate work.

The parser accepts UTF-8 and UTF-16 little/big endian with a BOM or XML byte-order
signature. It rejects invalid UTF-8, odd UTF-16 lengths, unpaired surrogates and
contradictory encoding declarations. It does not replace invalid code units.
Raw input is limited to 1 MiB, XML depth to 32, tokens to 32,768 and attributes
per element to 128. ID text and version text are separately bounded. IDs retain
the legacy Unicode word-character form and a 100 UTF-16-unit limit on the trimmed
validation projection. Declared ID text remains bounded to400bytes; no Unicode
case fold is silently used as a repository key.

Identity must occur exactly once in `package/metadata/id` and
`package/metadata/version`. Duplicate attributes, duplicate identity fields,
case/namespace aliases, nested identity values, multiple roots and DTD/entity
declarations fail closed. No XML-specified external resource is opened. This
does not claim that every other manifest field or package is valid, approved
or clean. Unsupported encodings and the remaining format contracts stay open.

Local regression/fuzz checks cover these boundaries. The native Linux SDK
workflow now also compares 11 owned UTF-8/UTF-16, namespace, legacy-ID, entity,
CDATA and whitespace documents with the actual `NuGet.Packaging.NuspecReader`.
The owned fixture references installed SDK assemblies, has no package
references and clears remote package sources. Neither package contents nor
package scripts execute. On25115ae, both actual native SDK10.0.403 jobs compiled
the reference and compared NuGet.Packaging7.9.0.0. Ten documents matched; the
whitespace fixture exposed Go stripping ID text that the reader preserves.
The repair preserves declared text and has a failing-first local regression,
passing race/fuzz tests and actual native replay on e2208e7. All11documents agree
with the SDK reader on both Linux architectures. See
[the original comparison](../../evidence/2026-11-03/nuget-25115ae-nuspec-whitespace-failure.json).
The [accepted library checkpoint](../../evidence/2026-11-03/nuget-e2208e7-checkpoint.json)
retains exact source, fixture/helper/library hashes and versions.
Do not pass raw reader text directly to a repository key or claim complete
package validation from an identity-reader comparison.

The API follows the [NuGet manifest reference](https://learn.microsoft.com/en-us/nuget/reference/nuspec)
and the public [NuspecReader API](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Packaging/NuspecReader.cs).
The Go implementation is original. The earlier version-only native checkpoint
remains scoped to [f499369](../../evidence/2026-11-02/nuget-version-f499369-checkpoint.json).

Archive central-directory limits, entry/path/link validation, immutable package
byte binding, dependency/symbol semantics, feeds and every stock-client,
tenant/policy/lifecycle/platform journey remain required. This parser enables
that implementation; it does not advertise a working NuGet repository.
