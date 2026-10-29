# Change a proxy or group source

Use **Repositories → Sources** as a tenant administrator. Read the current source
revision, edit the complete proposed settings, give a reason and preview. Preview
checks configuration, member states and private credential destinations locally;
it does not contact the upstream or prove connectivity. Apply sends the exact
previewed replacement. A concurrent configuration change requires a new preview.

The management API has the same workflow:

- `GET /api/v1/repositories/{name}/configuration` reads retained settings and
  `source_revision`, including when the repository is suspended or removed.
- `PUT` on that path accepts `expected_revision`, complete `settings`, a nonempty
  `reason` of at most 1024 UTF-8 bytes, and optional `dry_run`. Apply requires an
  8–128 character `Idempotency-Key`; retry identical bytes with the same key.
- `GET .../configuration/history?after=0&limit=10` returns ascending immutable
  receipts. Continue from the returned `after`; the maximum limit is 1000 and a
  separate response-byte budget applies. Receipts retain before/after settings,
  revision, actor, reason, timestamp and journal sequence.

Change settings only for proxy/group repositories. Names, formats, modes, access
policies and review policies use their existing workflows. Provide every desired
source field, including download authorities, OCI token authority, Python index
format and group namespace ownership. Values omitted from the replacement are
not implicitly copied. Credential references contain no credential values.

Every applied replacement advances the revision, even identical settings. Active
fills from an older revision cannot publish. The next package request must
validate the new source; old cache freshness, stale windows, conditional validators
and npm/PyPI download locators do not carry across. A client holding an old native
download URL should refresh the package index and retry. A source change racing a
read returns `503 source_configuration_changed`; retry against the current
configuration. A stale administrator edit returns `409 configuration_changed`.
An unbound credential destination returns `400 upstream_credential_authority`.

To roll back, choose a historical snapshot, preview it against the current
revision and apply. Rollback creates another revision. It retains the intervening
history and requires source validation again. Replaying the original change's
idempotency key only confirms that old result; it does not perform rollback.

The private credential provider is currently loaded at startup. To rotate a value
under the same reference, suspend the proxy, stop/restart the registry with the
updated private provider, apply the same complete settings, then resume. Confirm
the new credential through an ordinary client with an independent client cache.
Use preconfigured, destination-bound references when switching credentials by
reference. Never place passwords or bearer values in source URLs or API settings.

Configuration changes retain old objects and source receipts. They do not reclaim
disk space or undo a local digest denial, quarantine, hold or OCI tombstone. Native
catalog refresh can retain observations about retired peers while hiding those
peers from consumers; it cannot restore them. Physical reclamation, managed secret
providers, rolling upgrade and broader client/platform qualification remain open.
