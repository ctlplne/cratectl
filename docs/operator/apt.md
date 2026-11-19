# Hosted Debian packages

Create a hosted repository with `format` set to `apt`. Use a writer credential
to PUT the original binary package at
`/apt/REPOSITORY/pool/PACKAGE/VERSION/ARCHITECTURE/PACKAGE.deb`. The path uses
the version in the control stanza, including an epoch when present. An existing
coordinate retains its original bytes. A matching retry succeeds.

The hosted intake reads Debian 2.0 archives with plain or gzip control members.
It preserves the control stanza and treats data members and maintainer scripts
as opaque bytes. Archive inspection leaves the package unassessed for review.
[Debian binary archive format](https://manpages.debian.org/trixie/dpkg-dev/deb.5.en.html)

Use an authorized reader to inspect `Packages` or `Packages.gz` under
`/apt/REPOSITORY/`. The derived flat index includes each permitted stanza with
its exact archive path, size and SHA-256. Review changes and retained reference
deletions affect the next read. Direct archive reads use repository policy and
the shared verified object transfer.
[Debian repository indexes](https://wiki.debian.org/DebianRepository/Format)

Signed Release publication, the `dists/` hierarchy, xz and zstd control
members, APT proxy and group routing, and stock package-manager qualification
remain open.
