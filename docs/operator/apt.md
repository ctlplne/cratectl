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

## Signed flat repository

Fetch the current `Packages` and `Packages.gz` with a repository credential.
Prepare a Release stanza with `Date`, `Valid-Until` and a `SHA256` continuation
entry giving the digest and byte count for each index. Clear-sign the file with
your external OpenPGP signer. An administrator can PUT the resulting original
`InRelease` bytes at `/apt/REPOSITORY/InRelease`. Cratectl accepts a currently
valid envelope only when both index entries match its current authorized
inventory. Repository review also applies to the exact `InRelease` digest.

Configure the stock client as a flat repository with suite `./`, the registry's
trusted TLS CA, a private source credential and the independent signer public
key in `Signed-By`. APT verifies the OpenPGP signature before using the index.
Current index hashes can also be retrieved at `by-hash/SHA256/DIGEST`. When a
policy or inventory change invalidates the signed view, publish a new envelope
with a later `Date`.
[APT archive authentication](https://manpages.debian.org/bookworm/apt/apt-secure.8.en.html)

## Signed named suite

Set `settings.debian_distribution` at repository creation to an object with
`suite`, `component` and `architectures`. For example, a repository named
`cratectl-apt` can serve suite `stable`, component `main` and architectures
`amd64` and `arm64`. Use those suite and component names in the APT source.
The base URI remains `/apt/cratectl-apt/` and package uploads use the same
`pool/` paths. Packages with `Architecture: all` appear in both indexes.

Publish the signed file at `dists/stable/InRelease`. Its `Suite` or `Codename`
must match `stable`. Set `Components` to `main` and `Architectures` to the
configured architectures. Include the plain and gzip SHA-256 entries for
each architecture relative to the Release file, such as
`main/binary-amd64/Packages.gz`. Each architecture also serves by-hash reads
under its own binary index directory. A policy change in any included
architecture invalidates the signed view.

xz and zstd control members, proxy and group routing, and further native
package-manager qualification remain open.
