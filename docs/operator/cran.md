# CRAN repositories

Create a repository with `format: cran` and `mode: hosted`. The repository
root is `/cran/REPOSITORY/`. Give publishers write access and consumers read
access. A repository that requires review serves only approved exact digests.

## Publish a source archive

Publish the original gzip-compressed R source tarball to its package and
version. Package names are case sensitive. The archive directory and
`DESCRIPTION` must match the name and version in the request.

```sh
cratectl --config /private/path/writer.json --method PUT \
  --path /cran/REPOSITORY/src/contrib/PACKAGE_VERSION.tar.gz \
  --upload-file PACKAGE_VERSION.tar.gz
```

The upload response identifies the original bytes in `X-Checksum-Sha256`.
The coordinate is immutable. Archives may contain regular files and
directories in one package directory. The maximum archive size is 64 MiB
compressed and 256 MiB expanded. `DESCRIPTION` uses UTF-8 and is limited to
128 KiB. cratectl reads package metadata without extracting or evaluating
package code.

## Read the index and download from stock R

Trust the registry CA and load the scoped reader token from a private file.
Use only the intended repository with these request headers.

```r
Sys.setenv(CURL_CA_BUNDLE = "/private/path/ca.crt")
repo <- "https://registry.example/cran/REPOSITORY/"
headers <- c(Authorization = paste("Bearer", readLines("/private/path/reader.token", n = 1)))
index <- available.packages(repos = repo, type = "source", method = "libcurl", headers = headers)
download.packages("PACKAGE", destdir = ".", available = index, repos = repo,
                  type = "source", method = "libcurl", headers = headers)
```

Both `src/contrib/PACKAGES` and `src/contrib/PACKAGES.gz` describe the
current approved source packages. They include inspected dependency and
license fields and an MD5 compatibility checksum derived from the original
archive. SHA-256 remains the identity for review and retained restoration.
Retirement removes a version from both indexes and prevents archive reads.

## Retrieve a retained version

Under `src/contrib/Archive/PACKAGE/`, the directory lists reviewed source
versions older than the newest currently visible version. The comparison
uses R's numeric version components. Use the linked filename to read the
original archive. The exact URL keeps the same bytes while that reference
remains eligible, including if review changes which version is newest.

## Read an ordered group

Create a `cran` group with an ordered list of hosted CRAN members. Consumers
need read access to the group and every member. The first member retaining
any version of a package owns all its versions in the group. A denied or
retired version still reserves its package name. You can assign an exact
case-sensitive package name to a specific member through `namespace_owners`.

Run the same stock R commands using the group root as `repo`. The group index
adds a digest-bound `Path` field that native R uses for the source URL. At
download time cratectl checks the current owner, both review policies and
the exact SHA-256. Publish and restore source archives in the hosted members.
Historical directories are available on the hosted members.

## Publish and consume hosted binaries

Use the `contrib.url(repo, type = .Platform$pkgType)` result from the target
R distribution to choose among these hosted directories.

- macOS Apple silicon on Sonoma `bin/macosx/sonoma-arm64/contrib/X.Y/NAME_VERSION.tgz`
- macOS Apple silicon on Big Sur `bin/macosx/big-sur-arm64/contrib/X.Y/NAME_VERSION.tgz`
- macOS Intel on Big Sur `bin/macosx/big-sur-x86_64/contrib/X.Y/NAME_VERSION.tgz`
- Windows x64 `bin/windows/contrib/X.Y/NAME_VERSION.zip`

Publish the original archive with `PUT`. cratectl checks the plain
`DESCRIPTION` against the package name, version and R series in the URL. It
checks the declared OS and target when present. Stock R omits the target for
packages built without native code. The inspection checks for the installed
metadata file and preserves it as opaque bytes. The metadata checks leave ABI
compatibility and execution testing to the target system.

Each directory has its own `PACKAGES` and `PACKAGES.gz` views. A source and
two binaries can share a package name and version, with separate reviews
for their original SHA-256 digests. On a supported R distribution, use
`.Platform$pkgType` in place of `"source"` in both commands above. Serialized
indexes and groups with binary channels remain open.

## Proxy a source mirror with SHA-256 metadata

Create a `cran` repository with `mode: proxy` and `settings.upstream.url`
pointing to the approved repository root. The same configured origin serves
`src/contrib/PACKAGES` and its packages at `src/contrib/NAME_VERSION.tar.gz`.
Give each record `SHA256sum` and `MD5sum` fields computed from the original
tarball. Put the source dependency fields in the record so cratectl can
check them against the exact downloaded archive. The `SHA256sum` field is a
mirror requirement for this mode. Plain CRAN indexes that only carry MD5
need a separately qualified trust path.

The proxy's regenerated `PACKAGES` and `PACKAGES.gz` advertise local
digest-bound paths. If the repository requires review, an authorized
operator can use the mirror's `SHA256sum` and filename to request
`src/contrib/sha256/DIGEST/NAME_VERSION.tar.gz` and populate the cache. The
first read is refused while the cached digest awaits review. Approve the
exact retained path and digest to make it eligible for discovery and reads.
Reads recheck the current catalog, source configuration and review, so a
replaced catalog entry or denied archive stops an old download URL.

Run the same stock R source commands with the proxy root as `repo`. Binaries,
historical archive listings and groups containing proxy members need
separate qualification.

[Writing R Extensions](https://cran.r-project.org/doc/manuals/R-exts.html)
[R Installation and Administration](https://cran.r-project.org/doc/manuals/r-release/R-admin.html)
[Native R index and downloader](https://stat.ethz.ch/R-manual/R-devel/library/utils/html/available.packages.html)
