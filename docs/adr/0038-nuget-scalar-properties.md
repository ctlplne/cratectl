# Bounded NuGet scalar manifest properties

Metadata endpoints need original package descriptions and labels without loading
package code or granting authority to its contents. `ParseNuspecProperties` reads
17 supported scalar properties after the existing bounded identity/XML admission.
It returns identity separately from declared values. Authors, owners, URLs,
license expressions and package-relative paths remain untrusted text: the parser
never fetches them, opens files, executes content or approves security evidence.

The compatibility target is the actual SDK's `NuspecReader.GetMetadataValue` for
the named scalar fields. This is distinct from typed dependency/framework/license
APIs. Its metadata dictionary uses the first nonempty leaf property with an
ASCII case-insensitive supported name, including a scalar in another namespace.
Elements with child elements are omitted. Original nonempty text is preserved;
it is never trimmed into a repository identity or interpreted as HTML.

The reader retains the 1 MiB source, 32-level depth, 32,768-token and 128-attribute
boundaries from identity admission. Supported field values have a 64 KiB ceiling.
UTF8/UTF16 decoding and declaration handling share one internal helper. The
second streaming pass keeps only the active scalar and its bounded result map.
Invalid or cancelled input never yields partial metadata. DTDs, entity resolution
and unbounded XML-to-object loading remain unavailable.

Whitespace is a reader behavior, not a blanket trim policy. Ordinary insignificant
XML whitespace, CDATA, character references, comments and inherited `xml:space`
need separate characterization. Local fixtures cover these, first/empty/duplicate
fields, ASCII case aliases, foreign scalar namespaces, ignored child elements,
exact text across native encodings, cancellation and byte limits. Malformed
`xml:space` is rejected. The source-guided behavior is not called SDK-compatible
until its actual native comparison passes.

The owned SDK oracle adds 23 source documents and compares every supported value
against actual `GetMetadataValue`, with source/library/helper/fixture identities
and bounded mismatch evidence. Earlier ID/version/order/Nuspec/archive contracts
remain mandatory. Local Go helper results and 456,139 fuzz executions do not
qualify the managed/native comparison.

This scalar reader is a prerequisite for complete metadata feeds. Dependency and
framework groups, version ranges, license validation, registration, search,
unlist/relist, signatures, symbols, proxy/group and all other format/platform and
product outcomes remain required. No incomplete resource is advertised by this
change, and the current immutable publication path is preserved.

References:

- [.nuspec reference](https://learn.microsoft.com/en-us/nuget/reference/nuspec)
- [Public SDK scalar reader](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Packaging/Core/NuspecCoreReaderBase.cs)
