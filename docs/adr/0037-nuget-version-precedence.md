# NuGet version precedence and bounded index sorting

Normalized version keys identify stored coordinates. Precedence answers a
different question: which version sorts before another. Registration bounds,
search and version selection need a comparator rather than text ordering;
`2.0.0` precedes `10.0.0` despite their lexical order.

`CompareVersions` validates through the existing version-key contract, compares
four numeric core components, then release labels, and ignores build metadata.
Stable versions follow prereleases. The implementation follows the public SDK
comparer's signed Int32 label classification and textual fallback on overflow,
rather than assuming arbitrary-precision SemVer numbers. This source-guided
behavior still requires the actual installed SDK comparison on a named source.
No SDK matching claim comes from local unit vectors.

An ordering tie never changes coordinate identity. In particular, signed zero
release labels can compare equally while their wire keys remain distinct.
Publication and duplicate detection continue to use exact normalized keys.
No persisted coordinate, original manifest or immutable package bytes changes.

`SortVersionKeys` accepts canonical keys, parses each once and returns a stable
ascending copy. It bounds the collection to 100,000 entries and 64 MiB of key
bytes, beneath any tighter caller budget. These are resource safety ceilings.
Release labels remain string slices instead of allocating an array per dotted
label. A bottom-up merge checks cancellation between work units; no invalid,
noncanonical or cancelled sort returns partial data or changes its input.

The hosted version query still projects only bounded keys under current tenant,
repository, policy and retirement authority. The final order now uses this
shared comparator. Complete-index limits fail; they never silently omit versions.
The PostgreSQL regression publishes versions 1, 10 and 2, checks their semantic
order, concurrent uniqueness, and that rejected pushes do not add journal events.

The owned SDK oracle adds 3,025 ordered pairs: normalized aliases, numeric core
boundaries, release prefixes, case/build metadata, signed/numeric overflow,
large labels and invalid inputs. All pairs stay within 2 MiB and the existing
4,096-case budget. Both native Linux architectures compare against actual
`NuGet.Versioning.VersionComparer.VersionRelease`. Reports retain exact
source/SDK/library/helper/fixture identity, every mismatch index and bounded owned
examples. Existing version, ID, Nuspec and archive comparisons remain required.

Local build, unit, race, cancellation/budget checks and 512,024 fuzz executions
pass. Integration compilation and local Go helper execution are not SDK or
PostgreSQL runtime proof. The initial unreachable cancellation test trigger is
retained separately; it was a fixture error, not observed product data exposure.
Native SDK/updated database replay remains required.

This is a shared prerequisite for complete metadata, registration, search,
dependency/version-range and lifecycle behavior. Those endpoints and all other
NuGet/platform/product requirements remain committed work.

References:

- [NuGet versioning](https://learn.microsoft.com/en-us/nuget/concepts/package-versioning)
- [Public SDK comparer source](https://github.com/NuGet/NuGet.Client/blob/dev/src/NuGet.Core/NuGet.Versioning/VersionComparer.cs)
- [Registration metadata](https://learn.microsoft.com/en-us/nuget/api/registration-base-url-resource)
