# Hosted Cargo registry

Create a hosted repository with format `cargo`. For restricted repositories,
grant the publisher read and write access and grant consumers read access. Use
the registry's HTTPS hostname and trust its certificate authority on each
client. In Cargo's `config.toml`, configure the registry alias and sparse index.

```toml
[registries.cratectl]
index = "sparse+https://packages.example.com/cargo/rust-releases/index/"
credential-provider = "cargo:token"

[http]
cainfo = "/private/path/ca.crt"
```

Supply `CARGO_REGISTRIES_CRATECTL_TOKEN` from your private credential provider
for the individual command or build job. Cargo uses the token for index reads,
archive downloads, and publishing. Use a writer token for
`cargo publish --registry cratectl`. Consumers can use a read-only token and a
dependency with the matching alias.

```toml
[dependencies]
example-lib = { version = "1.0", registry = "cratectl" }
```

The registry inspects each uploaded archive's normalized `Cargo.toml`, including
features and same-registry dependencies. It computes SHA-256 from the original
`.crate` bytes before recording the package. Cargo reads this checksum from the
sparse index and can verify identical bytes on download. Name and version are
immutable. Case, hyphen versus underscore, and SemVer build metadata cannot be
used to publish a second copy of a coordinate.

When review is required, the package is recorded immediately and stays absent
from discovery until its exact digest is approved. Cargo's publish command
waits for the version to appear. If its wait expires, inspect the repository's
artifact inventory and approve the original digest. The same authenticated
publication can be retried with identical bytes.

An authorized repository writer can run
`cargo yank example-lib --version 1.0.0 --registry cratectl` to exclude a
version from fresh dependency resolution. Existing lockfiles can still use
the version when policy allows the exact archive. Add `--undo` to make the
version available for new resolutions again. An active artifact hold blocks
these state changes. To remove even existing lockfile access, use the common
review policy or the artifact's lifecycle controls.

The current profile covers a single hosted sparse registry and same-registry
dependencies. Per-crate ownership, legacy Git indexes, upstream proxying,
groups, and native search remain open.
