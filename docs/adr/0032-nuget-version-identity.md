# NuGet version identity foundation

NuGet version matching differs from a generic semantic-version parser. A
repository must give equivalent forms one coordinate to prevent duplicate
publication under a different spelling. The core `internal/nuget.VersionKey`
contract accepts one to four nonnegative 32-bit components, pads missing
components to three, omits a zero fourth component and removes build metadata
from identity. Its package-base-address key also folds prerelease ASCII case.
Numeric prerelease labels cannot have leading zeros. Build labels can.

This follows Microsoft's [version normalization reference](https://learn.microsoft.com/en-us/nuget/concepts/package-versioning)
and [package-base-address resource](https://learn.microsoft.com/en-us/nuget/api/package-base-address-resource).
The [current NuGet version parser](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Versioning/NuGetVersionFactory.cs)
was reviewed as a behavioral reference. The implementation is original Go code;
no vendor source was copied.

Input and normalized output each have a 1,024-byte safety budget. Rejection
returns a fixed error and no partial key. Padding cannot produce a key that
the same parser refuses to read back. Range expressions and floating versions
are separate dependency-resolution work; they cannot become package keys.

Regression examples cover equivalent spellings, nonzero revisions, case and
metadata, distinct identities, invalid separators, overflow, Unicode/path
substitution and exact byte-budget boundaries. A fuzz target checks stable
keys, rejection without partial output and metadata-insensitive identity.
The standard native GitHub fuzz inventory discovers the target automatically.

`nuget-contract.yml` adds actual Linux x86-64/ARM64 differential qualification.
An owned C# fixture calls the runner SDK's real `NuGet.Versioning` library;
the Go fixture calls the production contract. A deterministic synthetic corpus
compares both acceptance and exact normalized identities. The run records
the SDK/library version, library/helper/fixture hashes, native process
architecture, clean embedded Go source identity, case count and mismatch
indexes. Package sources are cleared and the fixture has no package
references. No uploaded package or project is built or executed. On f499369,
all1,129synthetic cases agree with actual SDK10.0.403 / NuGet.Versioning7.9.0.0
on each native Linux architecture. See [the exact checkpoint](../../evidence/2026-11-02/nuget-version-f499369-checkpoint.json).
This verifies the named library contract only.

This foundation adds no repository route or durable state. NuGet hosted/proxy/
group adapters, archive/nuspec identity binding, symbols, dependency/search
semantics, all stock-client journeys, legacy-client/platform behavior,
authorization/policy/lifecycle and every other format requirement remain
unfinished. No NuGet repository support or release readiness is claimed.
