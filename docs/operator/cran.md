# Hosted CRAN source repositories

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

The hosted profile covers source archives and the two DCF indexes.
Platform binaries, serialized indexes, proxy and group repositories need
separate implementation and qualification.

[Writing R Extensions](https://cran.r-project.org/doc/manuals/R-exts.html)
[Native R index and downloader](https://stat.ethz.ch/R-manual/R-devel/library/utils/html/available.packages.html)
