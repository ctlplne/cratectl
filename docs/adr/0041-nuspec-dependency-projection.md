# Bounded dependency declarations for native metadata

Complete registration and search need dependency metadata derived from the exact
package manifest. `ParseNuspecDependencies` reads selected dependency declarations
after the existing full bounded identity/XML admission. It preserves raw target
frameworks, IDs, version ranges and include/exclude asset flags. Parsed lookup
keys and range observations are separate fields. A formatter result must not
replace the original declaration or its parsed floor.

Selection follows the public SDK reader: element names and unqualified attribute
names are case-sensitive; dependency elements use the metadata element's effective
default namespace. Any selected group, including an empty one, overrides all
legacy flat dependencies across dependency containers. If there are no groups,
legacy dependencies form one unrestricted-framework group. Nested wrappers,
foreign namespaces and unrelated package sections cannot supply dependencies.

The reader preserves framework declarations for the native client interpreter;
it does not turn an unsupported framework into an unrestricted one or invent a
partial framework alias table. Duplicate declarations and original asset-flag
strings remain available. Missing/empty ranges mean All. Invalid nonempty active
ranges and invalid transport-profile dependency IDs fail without partial results.
This admission rule is deliberately stricter than the SDK's default reader,
which can interpret malformed ranges as All. A Go rejection must never be
attributed to that lenient SDK. Ignored legacy declarations are not validated as
active dependencies.

The source remains limited to 1 MiB, 32 levels, 32,768 XML tokens and 128
attributes per element. Additional work ceilings are 2,048 groups, 8,192 declared
dependency items, 4 KiB per selected attribute and 1 MiB of selected declaration
text. The reader checks context cancellation during scanning and validation.
These are parser safety boundaries; no entitlement or user/package count is
license-gated. No URL is fetched and no package code or model is loaded.

Shared XML decoding now normalizes literal attribute tabs/newlines to spaces,
including CRLF as one line break. Explicit character references retain their
characters. Text, comments, CDATA and processing instructions keep their own
semantics. A bounded lexical pass performs this before namespace resolution,
without mutating the original manifest bytes. Both old identity/scalar/archive
contracts and the new dependency round-trip remain mandatory native SDK checks.

The owned Go oracle re-encodes only its selected declarations as a fresh test
Nuspec. Actual SDK readers compare the original and projected dependency groups,
framework interpretation, range boundaries/build metadata, inclusivity, floating
state and asset flags. This tests semantic preservation without pretending the
Go reader implements SDK framework canonicalization or duplicate-set rules.
The 49 owned valid documents include UTF8/UTF16, namespace/case/scope changes,
legacy/group precedence, empty/duplicate groups and dependencies, raw floating
floors, build metadata, framework forms and literal/reference attribute whitespace.
Managed compilation and native comparison remain unverified for this source.

Local build/unit/race/lint checks pass, along with bounded fuzz campaigns for
dependencies, attribute normalization and the existing identity/scalar/archive
readers. This is a library prerequisite. Durable validated projections/backfill,
complete typed license and package metadata, registration retaining permitted
unlisted dependencies with `listed: false`, search exclusion, SemVer/gzip profiles,
full native client resolution and every other GOAL.md requirement remain required.
No new protocol resource is advertised and no primary schema/binary is changed.

References:

- [Public SDK dependency selection](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Packaging/NuspecReader.cs)
- [Public SDK dependency data](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Packaging/Core/PackageDependency.cs)
- [XML attribute-value normalization](https://www.w3.org/TR/xml/#AVNormalize)
