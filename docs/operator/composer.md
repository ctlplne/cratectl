# Hosted Composer libraries

Create a hosted repository with format `composer`. Publish a library ZIP by
using a repository writer credential to PUT the original bytes to
`/composer/REPOSITORY/dist/VENDOR/PACKAGE/VERSION.zip`. Use a lowercase package
name and a three-part stable version such as `1.2.3`. Include one
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

This profile handles hosted ZIP libraries and stable releases. Proxy and group
resolution, other distribution formats, development versions and broader
package metadata remain open.
