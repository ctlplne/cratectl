# Digest decisions and npm tag state

Manual decisions identify bytes by tenant, repository and SHA-256 digest. A path
selects an existing reference and must match the supplied digest, but does not
limit the decision to that path. Otherwise, publishing or caching the same bytes
under another path bypasses a denial. The canonical decision table covers present
and future aliases. Read, inventory and native metadata queries join it in their
authorization snapshot. Repositories and tenants remain independent authorities.

Decisions have monotonically increasing versions. The decision, path projection,
management replay response, audit event and outbox intent commit together under
the tenant mutation lock. An admitted read uses one repeatable-read snapshot;
changes govern subsequent requests, without revoking bytes already in flight.
Legacy path decisions backfill conservatively: a conflicting denial wins, and a
repeated migration never overwrites a canonical decision. This is manual review,
not scan evidence or the complete versioned policy/intelligence model.

npm distribution tags are mutable named pointers to published versions. They
live in a separate RLS-protected table, with revisions and deletion tombstones.
Publication and its tag changes commit atomically; a tag-budget failure rolls
back the version reference too. A deleted tag's tombstone prevents old embedded
publication metadata from resurrecting it during migration. A later authorized
tag update can restore that name. Tag addition checks current digest policy;
metadata omits tags targeting versions that are currently denied or quarantined.

Complete package metadata and tags are read from one database snapshot. Version,
tag and encoded-metadata budgets return an explicit 503 instead of a partial
index that silently changes dependency resolution. These are operator safety
budgets, configurable with `--native-version-budget` (10000),
`--native-tag-budget` (128) and `--native-metadata-bytes` (8 MiB).

The hosted npm adapter accepts canonical semantic versions through the maintained
Masterminds SemVer parser, including prereleases and build metadata. Named tags
cannot be semantic-version ranges. Stock npm may normalize build metadata out of
the published coordinate; retained native evidence records that client behavior.
Version/tag resolution, metadata conditional requests and npm dist-tag add/remove
are supported. npm proxy/group, unpublish, ownership, signatures and comprehensive
client/version qualification remain open.

npm intake now streams over the expanded gzip/tar representation without writing
archive entries to the filesystem. It bounds encoded publication bytes, expanded
bytes (including padding), logical file bytes, entry count and package.json size.
It validates the gzip trailer, rejects trailing payloads, and accepts one root
`package/package.json` matching the coordinate. It rejects traversal, ambiguous
duplicate paths, special devices, linked parents, dangling/cyclic/escaping links
and Windows path/stream interpretations. Safe internal links must resolve to a
member of the same archive; hard links must resolve to regular files.

Published package fields, including dependencies, come from that package.json.
Computed SHA-1 (native compatibility) and SHA-512 integrity describe the exact
compressed bytes. The registry generates its own tarball URL. No package script
or model is executed, and archive validation is not a malware or vulnerability
verdict. The full archive parser/security campaign remains required.
