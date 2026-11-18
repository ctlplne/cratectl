# Assemble Linux binary candidates for local qualification

Use a clean cratectl commit, the pinned Go SDK and a prepared local Go dependency
cache. From the repository root, run:

```sh
make package-linux
```

The command builds `cratectl` and `cratectld` for `linux/amd64` and `linux/arm64`.
The archives and printed SHA-256 digests are under
`.cache/cratectl-linux-candidates/<commit>/`. Each archive contains executable
files and a manifest with the Git revision, platform, toolchain, binary hashes
and source input hashes. Archive ownership, permission and time metadata are
fixed. If an archive already exists, another build verifies that it produced
identical bytes before reusing the filename.

The dual-architecture build also emits canonical `SHA256SUMS` bytes. An external
signer can sign that file with your own Ed25519 key. On the signing host, use
the approved key and write a detached signature:

```sh
openssl pkeyutl -sign -rawin -inkey "$SIGNING_KEY" -in SHA256SUMS -out SHA256SUMS.sig
```

On the verification host, authenticate the public key through your separate
trust channel. Verify the detached signature before using the archive digests:

```sh
openssl pkeyutl -verify -rawin -pubin -inkey "$TRUSTED_PUBLIC_KEY" -in SHA256SUMS -sigfile SHA256SUMS.sig
```

Use a version of OpenSSL with Ed25519 support in `pkeyutl`.
[OpenSSL signature options](https://docs.openssl.org/3.5/man1/openssl-pkeyutl/)

Check a local archive against a SHA-256 received through your trusted channel:

```sh
python3 scripts/verify_linux_candidate.py /path/to/cratectl-linux-arm64.tar.gz --sha256 "$EXPECTED_SHA256"
```

The verifier checks the compressed bytes first. It then confirms the manifest,
member names, normalized metadata, both ELF architectures and executable
digests without extracting or running either program.

To install on Linux x64 or ARM64, carry the archive and the trusted checkout's
`scripts/install_linux_candidate.py`, `scripts/verify_linux_candidate.py` and
`scripts/package_linux.py` to the target. The installer needs Python 3.10 or
newer and the normal Linux `/proc` filesystem. Create a private, existing
directory as the installing user and pass the independently authenticated
digest.

```sh
mkdir -m 0700 /path/to/installations
python3 scripts/install_linux_candidate.py /path/to/cratectl-linux-arm64.tar.gz \
  --directory /path/to/installations --sha256 "$EXPECTED_SHA256"
```

The installer checks the compressed bytes, platform and executable digests.
It stages and syncs both executables and their original manifest before
publishing a new directory named for the exact commit and architecture.
It refuses to replace an existing installation. The installation reads only
local inputs and makes no network calls.

To assemble a single architecture, pass `--architecture amd64` or
`--architecture arm64` to `scripts/package_linux.py` with Python 3.10 or newer.
The package build disables Go module proxy access and expects the modules already
in `.cache/go-mod`.

These bundles serve local engineering. Owner-approved license terms and complete
distribution notices are required before shipping. Release signing authority,
operating system and image inventories, and network-isolated installation of the
full stack remain separate qualification work.
[Licensing record](../licensing.md)

Run `make package-linux-sbom` to generate separate SPDX 2.3 and CycloneDX 1.6
documents beside each archive. The generator matches the compressed and
executable SHA-256 values, reads the exact linked Go module inventory from
each executable, and checks the embedded browser dependencies against the
lockfile and notices. Each document covers one archive and its contents.
Operating system packages, build-only dependencies, CVE verdicts and full
license review are outside this inventory.
[SPDX package information](https://spdx.github.io/spdx-spec/v2.3/package-information/)
[CycloneDX BOM guide](https://cyclonedx.org/guides/sbom/bom)

Two builds of `b910da7` produced byte-identical Linux x64 and ARM64 archives.
The extracted ARM64 binaries also ran their expected help commands with
container networking disabled. [Assembly evidence](../../evidence/2026-11-18/linux-candidates-b910da7-local.json)

The `5fd3edd` external signing test verified both exact archives and refused a
different public key, altered checksum bytes and a changed archive.
[External signature evidence](../../evidence/2026-11-18/linux-candidate-signed-checksums-5fd3edd.json)
