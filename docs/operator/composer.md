# Hosted Composer libraries

Create a hosted repository with format `composer`. Publish a library ZIP by
using a repository writer credential to PUT the original bytes to
`/composer/REPOSITORY/dist/VENDOR/PACKAGE/VERSION.zip`. Use a lowercase package
name and a three-part tag such as `1.2.3`, a numbered prerelease such as
`1.2.3-rc1`, or a lowercase development branch such as `dev-main`. Include one
`composer.json` at the ZIP root or inside its single top-level directory. Its
`name` must match the coordinate. If it declares a `version`, that version
must also match.

Cratectl retains the ZIP unchanged and derives Composer metadata from the
manifest. Versions, dependency constraints and conventional autoload mappings
appear in the Composer v2 index. The download URL stays on the configured
registry. The index publishes the original ZIP's SHA-256 as its dist reference
and the SHA-1 compatibility checksum that Composer can verify. A changed ZIP
at the same coordinate returns a conflict. Repository grants, digest decisions
and retained-reference deletion govern both discovery and downloads.

Add a Composer repository to the project's `composer.json` and point it at
`https://registry.example/composer/REPOSITORY/`. Configure TLS trust for the
operator CA, and use a private Composer HTTP Basic credential with username
`token` and a repository reader token as the password. Keep credentials out
of `composer.json` and `composer.lock`. Use `composer install --no-scripts
--no-plugins` when installing owned verification fixtures.

- [Composer repository format](https://getcomposer.org/doc/05-repositories.md)
- [Composer private repository authentication](https://getcomposer.org/doc/articles/authentication-for-private-packages.md)

## Ordered groups

Create a Composer group with hosted members in
`settings.members`, ordered by preference. The first member that retains
any archive for a package name supplies its complete version list. Consumers
need read grants on the group and each consulted member. An explicit
`settings.namespace_owners` entry such as `"acme/library/": "team-releases"`
selects that member for the package. Review and deletion still apply in the
selected repository.

Use the same Composer source configuration with the group repository name.
Composer records a SHA-256 pin in its download URL. If a new member comes to
own the package and has different bytes for a locked coordinate, the old URL
fails. Refresh the lockfile after reviewing the newly selected source.

Composer reads tagged releases and prereleases under the ordinary package
index. It requests a separate development index when the project allows
development packages. Both indexes apply current grants and review.

## Checksum-bound proxy

Create a Composer proxy with an explicit `settings.upstream.url` and allowed
network ranges. Cratectl reads the source's Composer v2 metadata at
`p2/VENDOR/PACKAGE.json` and `p2/VENDOR/PACKAGE~dev.json`. It accepts ordinary
JSON and the Composer 2.0 delta format.

This proxy profile requires the upstream metadata to include the original
ZIP's SHA-256 in the `dist.sha256` extension. Composer's optional
`dist.shasum` is checked for compatibility when present. Add any separate
archive base URL to `settings.download_sources` with its own allowed
networks and credential reference. Package metadata cannot add a new source
authority.

Cratectl checks the exact archive digest, inspects the ZIP, and compares its
install metadata with the source before retaining the package reference.
The download URL pins the SHA-256 and still requires current catalog and
policy approval. For a review-required repository, an operator can request
the exact pinned archive using the approved source metadata, review the
retained digest, then run Composer against the proxy. Cache expiry requires
revalidation of the configured source.

Public origins that do not supply this strong digest, mixed proxy/hosted
groups, additional version forms, other distribution formats and broader
package metadata remain open.

## Hosted discovery

Run `composer search TERMS` against a project that lists the hosted
repository. Search matches package names and the start of descriptions from
visible ZIP manifests. `composer search --only-name TERM` and the native
package list use names from current retained, policy-allowed versions.
Full-text search returns up to 100 matches. Proxy and group discovery through
the native search command require separate support.
