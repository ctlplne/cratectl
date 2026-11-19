# Hosted Conda channels

Create a repository with `format: conda` and `mode: hosted`. The channel
root is `/conda/REPOSITORY/`. Give publishers write access and consumers read
access. If the channel requires review, approve the exact SHA-256 before a
consumer can discover or download it.

## Publish an archive

Upload the original `.tar.bz2` to its exact coordinate with a scoped writer
configuration. The filename and subdirectory must agree with `info/index.json`.

```sh
cratectl --config /private/path/writer.json --method PUT \
  --path /conda/REPOSITORY/linux-64/PACKAGE-VERSION-BUILD.tar.bz2 \
  --upload-file PACKAGE-VERSION-BUILD.tar.bz2
```

A successful upload returns the archive SHA-256 in `X-Checksum-Sha256`.
Publishing different bytes to an existing coordinate returns a conflict.
The archive limit is 64 MiB compressed and 256 MiB expanded. This profile
accepts regular files and directories and limits `info/index.json` to
128 KiB. The reader checks the archive and derives its index record without
extracting package files or invoking hooks. Dependencies and constraints use
the package-name, version and optional build form within the configured channel.

## Consume with micromamba

Keep the reader credential in a private file. The scheme, host, port and
channel path below should match the operator’s TLS endpoint. The example
fetches and extracts archives into the package cache without linking them
into an environment.

```sh
CHANNEL=https://registry.example/conda/REPOSITORY/
micromamba auth login "$CHANNEL" --bearer-stdin < /private/path/reader.token
micromamba create --download-only --name cratectl --override-channels \
  --channel "$CHANNEL" --ssl-verify /private/path/ca.crt PACKAGE
```

The channel serves `repodata.json` and `current_repodata.json` for each
recognized native subdirectory and `noarch`. Both use the same current
review and retained reference rules. The index includes the original archive
size and SHA-256, with MD5 for older client compatibility. A denied or
retired archive disappears from the next index. Restoration requires the
retained exact bytes and the current lifecycle revision.

This hosted profile covers legacy `.tar.bz2` packages with plain JSON indexes.
Modern `.conda` archives, proxy and group channels, and compressed indexes
remain open.

[Conda package specification](https://docs.conda.io/projects/conda/en/stable/user-guide/concepts/pkg-specs.html)
[Micromamba user guide](https://mamba.readthedocs.io/en/stable/user_guide/micromamba.html)
