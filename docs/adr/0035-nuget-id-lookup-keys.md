# NuGet ID lookup keys

Manifest readers return declared text. Repository lookup needs a separate,
bounded coordinate contract. `IDKey` rejects malformed/unsafe IDs, preserves
legacy Unicode word characters and derives the flat-container lowercase key.
It never trims whitespace or performs Unicode normalization. For example,
composed and decomposed accents retain separate keys.

Input is limited to 400 UTF8 bytes and the legacy 100 UTF16-unit identity
boundary. The legacy SDK validator uses a UTF16 character regex; supplementary
surrogate pairs are outside its word categories. Raw Nuspec reading remains a
different operation. The optional newer ASCII-restricted SDK validator is not
used to silently discard legacy Unicode support.

Invariant casing needs an explicit dotted-I exception: `ID` maps to `id`,
while `İD` maps to `İd`. Dotless `ı` also stays distinct. Ordinary Go lowercase
alone merges identities that .NET keeps separate. The implementation is
original; the public [runtime invariant-casing implementation](https://github.com/dotnet/runtime/blob/main/src/native/libs/System.Globalization.Native/pal_casing.c)
and [UTF16 regex word classification](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Text.RegularExpressions/src/System/Text/RegularExpressions/RegexCharClass.cs)
are behavioral references, not copied code.

This follows the [flat-container ID key contract](https://learn.microsoft.com/en-us/nuget/api/package-base-address-resource)
and [PackageIdValidator API](https://source.dot.net/NuGet.Packaging/PackageCreation/Utility/PackageIdValidator.cs.html).
The actual installed SDK remains the execution reference. No native matching
claim is made until the new differential campaign passes.

The owned fixture enumerates all 63,488 non-surrogate BMP values inside a package
name and adds 28 whole-ID casing, size, grammar, transport and supplementary
cases. All 63,516 cases execute; the encoded input stays below 2 MiB. Only the ID
mode increases the fixture's case budget to 65,536. Other modes retain 4,096.
The SDK calls its actual validator and `ToLowerInvariant`. The report records
native source/architecture, SDK/library/helper/fixture hashes, Go Unicode and
.NET runtime identities, mismatch indexes and bounded owned examples.

The repository transport profile rejects control characters even if an SDK
validator accepts a particular edge case. Reference acceptance and these
explicit profile exclusions are reported separately; they are never described
as SDK rejection or skipped tests. No generated package, project script or
model executes.

Local tests cover stable keys, invalid/no-partial results, boundaries and distinct
invariant/normalization cases. Native SDK compilation and the new ID comparison
remain unverified. See [development evidence](../../evidence/2026-11-03/nuget-id-development.json).

This is a wire-key foundation, not a durable package publication or identity-alias
implementation. Common-store byte/policy/idempotency/journal binding, complete
metadata/dependency/signature/symbol handling, hosted/proxy/group feeds and
stock-client/tenant/lifecycle/platform outcomes remain required.
