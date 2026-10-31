# Retain, hold and restore native package references

Development status: implemented; PostgreSQL/HTTP regression coverage is being
retained. Stock-client and clean candidate qualification remain required. This
does not qualify complete format lifecycle, legal compliance or release readiness.

Generic files, Maven package files, npm tarballs and Python distributions use the
same lifecycle API as canonical OCI references. In a source repository's package
inventory, choose **Lifecycle**, select an action and reason, then preview and
apply the exact digest and revision. Writers can delete or restore; only tenant
administrators can place or release a hold. A group has no independent copy to
retire: change its selected source repository.

Each action changes one materialized path. Maven POMs, JARs and classifiers remain
separate references. This does not retire every file in a package version or
prevent publication at a different coordinate. Mutable npm/Python catalogs and
Maven `maven-metadata.xml` remain discovery projections and are excluded.

Deletion retains bytes, decisions, native tags/yanks and journal history. The
download stops serving that reference. Native version/file metadata omits retired
candidates while retaining their blocked source identity internally, so a group
cannot silently substitute a lower-priority copy. Source-pinned npm/Python group
URLs also recheck known earlier-source tombstones immediately before serving.
Deleting one source does not deny the same digest in another directly addressed
repository. No physical storage is reclaimed.

Restore opens the retained objects, checks actual lengths and hashes, and
rechecks the digest and lifecycle revision in the publication transaction. A
missing or corrupt object leaves the tombstone intact. Existing security policy
still applies. A removed npm tag stays removed; a Python yank stays in force.

A hold preserves the exact current bytes. If a proxy refresh returns different
bytes, publication rejects the replacement under the current hold. It releases
that attempt's lease and keeps the previous freshness deadline and validators;
it does not invent a successful upstream check or authorize expired cache bytes.
After release or expiry, a permitted replacement advances the lifecycle revision
and includes old/new identities in the publication event. Earlier hold/release
receipts keep their original digest. The new digest has no historical hold until
an administrator actually places one. An old preview cannot delete the new bytes.

Use `GET /api/v1/repositories/{repository}/artifacts/lifecycle?path=...` for the
current state. `PUT` accepts `path`, `digest`, `action`, `expected_revision`,
`reason`, optional `hold_until` and `dry_run`. The action is `delete`, `restore`,
`hold` or `release_hold`. Read/preview requires current write authority; applied
changes also require an `Idempotency-Key` of 8–128 characters. Replay rechecks
current authority and returns its original receipt. The `cratectl` management CLI
supports the same path with `-method`, `-body-file` and `-idempotency-key`.

Administrators can inspect original hold receipts through **Storage → Reference
holds** or the lifecycle `/history?path=...` endpoint. Current inventory attaches
old receipts only to their original digest. Cases/matters for these non-OCI
subjects, package-wide bulk retirement, retention selection, release/replica/
restore-point protection and safe physical garbage collection remain open work.
