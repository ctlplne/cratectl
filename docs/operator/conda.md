# Conda channels

Create a repository with `format: conda` and `mode: hosted`. The channel
root is `/conda/REPOSITORY/`. Give publishers write access and consumers read
access. If the channel requires review, approve the exact SHA-256 before a
consumer can discover or download it.

## Publish an archive

Upload the original `.tar.bz2` or `.conda` to its exact coordinate with a
scoped writer configuration. The filename and subdirectory must agree with
`info/index.json`.

```sh
cratectl --config /private/path/writer.json --method PUT \
  --path /conda/REPOSITORY/linux-64/PACKAGE-VERSION-BUILD.tar.bz2 \
  --upload-file PACKAGE-VERSION-BUILD.tar.bz2
```

A successful upload returns the archive SHA-256 in `X-Checksum-Sha256`.
Publishing different bytes to an existing coordinate returns a conflict.
The archive limit is 64 MiB compressed and 256 MiB expanded across its
components. A `.conda` file uses the version 2 ZIP layout with two separate
Zstandard-compressed tarballs. The ZIP directory stays within the 32-bit
layout. The bounded 64-bit local sizes used by the standard Python writer
must match that directory. The reader accepts regular files and directories,
limits `info/index.json` to 128 KiB and leaves package scripts and serialized
contents opaque. Dependencies and constraints use the package-name, version
and optional build form within the configured channel.

## Consume with micromamba

Keep the reader credential in a private file. The scheme, host, port and
channel path below should match the operator’s TLS endpoint. The example
fetches and extracts archives into the package cache without linking them
into an environment.

```sh
CHANNEL=https://registry.example/conda/REPOSITORY/
micromamba auth login "$CHANNEL" --username token --password-stdin < /private/path/reader.token
micromamba create --download-only --name cratectl --override-channels \
  --channel "$CHANNEL" --ssl-verify /private/path/ca.crt PACKAGE
```

The channel serves `repodata.json` and `current_repodata.json` for each
recognized native subdirectory and `noarch`. Both use the same current
review and retained reference rules. Legacy and modern files appear in
`packages` and `packages.conda` respectively. Each record includes its original
size and SHA-256, with MD5 for older client compatibility. A denied or
retired archive disappears from the next index. Restoration requires the
retained exact bytes and the current lifecycle revision.

## Consume an ordered group

Create a repository with `format: conda`, `mode: group` and an ordered
`settings.members` list of hosted Conda channels. Readers need access to the
group and every member. Publish to the hosted members. The first member that
retains a package name owns its builds across platforms, including `noarch`.
An unapproved or retired build still reserves the package name. To choose a
specific source, use an exact package name followed by `/` in
`settings.namespace_owners`, with the member name as its value.

For micromamba 2.9.0 over Basic authentication, first resolve the group's
current channel URL. That client reconstructs package paths relative to the
configured channel when credentials are present. The snapshot is part of the
configured channel path, so its ordinary metadata and package requests both
carry the same binding.

```sh
CHANNEL=$(cratectl --config /private/path/reader.json \
  --path /conda/GROUP/snapshot.json | jq -er '.channel')
micromamba auth login "$CHANNEL" --username token --password-stdin < /private/path/reader.token
micromamba create --download-only --name cratectl --override-channels \
  --channel "$CHANNEL" --ssl-verify /private/path/ca.crt PACKAGE
```

Clients that honor authenticated Conda repodata version 2 download URLs can
use the group root directly. Its platform indexes include a `base_url` for
each platform snapshot. Both routes check source grants, snapshot identity
and current digest review before sending bytes. Refresh the channel snapshot
or repodata and resolve again when the registry returns `conda_snapshot_changed`.

The hosted and grouped channels serve both archive formats and plain JSON
indexes. Proxy members and compressed indexes remain open.

[Conda package specification](https://docs.conda.io/projects/conda/en/stable/user-guide/concepts/pkg-specs.html)
[Conda repodata version 2](https://conda.org/learn/ceps/cep-0015/)
[Conda package file formats](https://conda.org/learn/ceps/cep-0035/)
[Micromamba 2.9.0 authenticated download behavior](https://github.com/mamba-org/mamba/blob/2.9.0/libmamba/src/core/package_fetcher.cpp)
[Micromamba user guide](https://mamba.readthedocs.io/en/stable/user_guide/micromamba.html)
