# Dependency intervals and floating preferences

Complete NuGet metadata needs to retain what each dependency allows. A minimum
version, an exact version, an interval and a floating preference have different
meanings. Treating every declaration as an exact package coordinate would drop
valid dependencies; treating malformed declarations as unrestricted would widen
what a consumer can install.

`ParseVersionRange` reads at most 4 KiB and retains private parsed bounds and
floating state. Each concrete version still uses the existing 1 KiB, Int32-core
and lowercase lookup profile. Invalid input returns a zero, unusable result.
Public observations are copies, and an unparsed zero value cannot satisfy a
candidate. No package code, network source or repository authority is involved.

The implementation covers minimum/exact/closed/open/half-open intervals and the
SDK's stable, prerelease, revision and combined floating forms. Interval
membership and floating preference are separate operations: `1.*` prefers the
1.x family, but its interval still has no upper bound. Choosing a version must
apply both the interval and the resolver's preference/prerelease rules. This
library does not claim complete dependency-graph resolution.

Range projections use lowercase version keys and ignore build metadata for
comparison, consistent with the existing feed identity profile. Original
declared text must be retained separately. An ordering tie does not merge
coordinate identities. SDK edge cases include empty open intervals, rejected
half-open equal bounds, whitespace-only missing bounds and noncanonical floating
inputs. In particular, the source-admitted `1.2*` minimum is 1.20.0 even though
its floating formatter produces `1.*`. A formatter result must never silently
replace that parsed minimum. Actual native comparison is required before this
source-guided behavior is called compatible.

The owned SDK oracle compares validity, normalized keys, both bounds and their
inclusivity, floating behavior/text, candidate validity, interval membership and
floating-subset membership. It preserves all earlier version/ID/order/scalar/
Nuspec/archive contracts. Its corpus stays within the existing 4,096-case and
2 MiB input ceilings, with bounded first-mismatch examples. Unit regressions,
race checks and 42,435 local fuzz executions pass; actual managed compilation
and native comparison remain unverified.

Typed Nuspec dependency/framework groups and license semantics, complete
registration/search with unlisted and SemVer filters, native lifecycle discovery,
signatures/symbols/proxy/group, client/platform/trust and every other original
GOAL.md requirement remain required. This change advertises no new resource.

References:

- [NuGet version ranges](https://learn.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges)
- [Public SDK range parsing](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Versioning/VersionRangeFactory.cs)
- [Public SDK floating behavior](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Versioning/FloatRange.cs)
- [Public SDK normalized formatting](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Versioning/VersionRangeFormatter.cs)
