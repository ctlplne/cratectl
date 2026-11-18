# Cargo registries

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

An authorized crate owner with a current repository write grant can run
`cargo yank example-lib --version 1.0.0 --registry cratectl` to exclude a
version from fresh dependency resolution. Existing lockfiles can still use
the version when policy allows the exact archive. Add `--undo` to make the
version available for new resolutions again. An active artifact hold blocks
these state changes. To remove even existing lockfile access, use the common
review policy or the artifact's lifecycle controls.

Use `cargo search --registry cratectl example` to search crate names in this
repository. Search uses current grants and availability decisions. It selects
the highest allowed version that is eligible for fresh resolution and returns
its packaged description when available.

The current profile covers a single hosted sparse registry and same-registry
dependencies. The writer who publishes a new crate becomes its first owner.
Use `cargo owner --registry cratectl --list example-lib` to read the owner
list. Add or remove a tenant actor with `--add ACTOR` or `--remove ACTOR`.
The last owner remains protected. Each co-owner also needs a current
repository write grant. A tenant administrator can manage ownership to
recover access or add the first owner to a crate that predates ownership.
For a read-only group, add hosted Cargo repositories as ordered members.
Point the same sparse client configuration at the group. The first member
that retains a crate name controls its index and downloads, including
unassessed or retired versions. Group policy can require review even when
the selected member permits unassessed bytes. An explicit namespace owner
can select a member for a crate using the crate name followed by `/`.
Grant readers access to the group and its configured members. When a crate
has an explicit owner mapping, the group reads only that member for the
crate. Publish and run native search against hosted repositories.

## Sparse proxy

Create a `cargo` repository in `proxy` mode. Set `settings.upstream.url` to
the upstream sparse index's HTTPS base and `settings.upstream.networks` to
its permitted network ranges. Point clients at the proxy using the same
authenticated sparse configuration. The proxy reads the source's root
`config.json` and uses its `dl` template. Add an explicit
`settings.download_sources` entry when the expanded crate URL uses a separate
host or base path. Each entry has its own permitted networks and optional
credential reference. For an upstream that expects an opaque Cargo token, set
`authentication` to `cargo-token` on both the repository authority and the
operator's private credential binding. The client still uses its cratectl token.

The proxy pins each version's URL, index dependency graph and SHA-256 under
the configured source revision. It checks the downloaded archive and its
`Cargo.toml` before recording a byte reference. It rejects a changed pin
within that source revision and records `upstream_cargo_coordinate_changed`
in the cache status. Inspect the upstream and its retained pin before using
the source settings API to approve a new source revision. Downstream Cargo
keeps its usual archive checksum in `Cargo.lock`.

When local approval is required, a repository reader can request the exact
`/cargo/REPOSITORY/download/CRATE/VERSION` endpoint to stage a known version.
The download is denied while review is pending. An administrator can inspect
the `crates/` reference in the artifact inventory and approve its exact digest.
After approval, the version can appear in the sparse index. An upstream yank
changes resolution while existing lockfiles may still fetch approved bytes.
Use artifact lifecycle controls to retire or explicitly restore a cached reference.

The current proxy handles sparse indexes with same-registry dependencies and
explicit download authorities. Legacy Git indexes, groups with proxy members,
and cross-repository search remain open.
