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

To assemble a single architecture, pass `--architecture amd64` or
`--architecture arm64` to `scripts/package_linux.py` with Python 3.10 or newer.
The package build disables Go module proxy access and expects the modules already
in `.cache/go-mod`.

These bundles serve local engineering. Owner-approved license terms and complete
distribution notices are required before shipping. Detached signatures, software
bills of materials, native installation from the packages and network-isolated
installation of the full stack remain separate qualification work.
[Licensing record](../licensing.md)

Two builds of `b910da7` produced byte-identical Linux x64 and ARM64 archives.
The extracted ARM64 binaries also ran their expected help commands with
container networking disabled. [Assembly evidence](../../evidence/2026-11-18/linux-candidates-b910da7-local.json)
