# OCI structured intake, weak subjects and referrers

Accepted 2026-10-28 after the retained native regression accepted an image
manifest with no configuration descriptor. This extends ADR 0002 and establishes
the intake contract that OCI proxy graph retrieval must also use.

Parse the exact manifest bytes before publication. Bound the document to 4 MiB,
JSON nesting to 64 and descriptors to 4096. Reject duplicate JSON members,
contradictory content types, mixed image/index structures, missing required
arrays/configuration and invalid descriptor identities. Verify optional embedded
descriptor data against its declared size and SHA-256. Unknown extension fields
and binary config/layer media types remain opaque. Descriptor URLs are retained
in the original bytes; intake never follows them or executes payloads.

The derived metadata records each strong dependency's path, digest, size and
media type. Recheck durable children and current digest decisions inside the
same tenant-serialized publication transaction that writes the root, tag and
journal/outbox intent. Match manifest child media types; blobs are uploaded as
opaque bytes. Validate the complete bounded graph before acknowledging its
publication. A successful intake can remain quarantined.

An OCI subject is a weak association to another manifest, rather than a required
payload dependency. Accept an attachment before its subject arrives. If the
subject is present, verify its descriptor and current graph policy. Recheck that
association on reads, including after a late subject arrival. A known denied or
quarantined subject blocks attachment reads under the applicable policy. Subject
association does not establish signature validity, provenance or scan approval.

Discover referrers from validated immutable manifest metadata in one PostgreSQL
authorization/policy snapshot. The derived index includes media type, size,
digest, artifact type and annotations; filtering preserves those bindings.
Oversized results fail explicitly instead of returning a partial index. The
index uses the existing tenant/RLS boundary and an indexed subject lookup. A
denied subject fails the discovery request; blocked referrers are omitted.

Resolve tags and their complete graphs in one read snapshot, then resolve the
tag again after stored-byte verification and before response headers. A retarget
returns a conflict instead of admitting the old selection. Digest requests retain
their immutable identity. Never convert a stored manifest to another media type;
reject an incompatible Accept header. Parse protocol suffixes from the end so
valid image names containing words such as `manifests` still work.

Pre-parser development manifests fail closed until an authorized same-byte
re-import, with children before parents, enriches their metadata. Preserve their
canonical digest decisions and first-published media identity. This is a local
development migration mechanism, not a production upgrade/recovery qualification.

OCI proxy/group graph transactions, challenge-token authentication, approved CDN
redirects, complete multi-architecture/platform and Docker/Podman/Helm workflows,
additional digest/manifest types, lifecycle/deletion, signatures and full parser,
fault and production campaigns remain required. Graph limits still need operator
configuration and scale qualification. All broad OCI rows remain open.

Primary references observed 2026-10-28:

- [OCI image manifest 1.1.1](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md)
- [OCI image index 1.1.1](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-index.md)
- [OCI descriptor 1.1.1](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md)
- [OCI Distribution 1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
