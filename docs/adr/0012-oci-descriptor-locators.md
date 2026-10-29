# OCI descriptor locators and retained member refresh

After a canonical digest request returns 404, OCI proxy intake can retrieve the
object through its descriptor's alternate URLs. This applies to index children,
image config/layers and weak subjects. A canonical authorization error, transport
failure or other status does not start fallback. Missing or temporary alternate
responses can advance to another candidate. Authorization, transport, integrity,
encoding and resource failures stop the affected retrieval; corrupt bytes never
become an eligible stale success.

Locators convey no network or credential permission. Use the existing most
specific approved origin/download source, explicit signed-query permission,
separate source credentials and manual redirect handling. Reject unapproved
candidates before HTTP; retained authority/CIDR/private-network ceilings apply
to every connection. An HTTPS canonical request cannot fall back to HTTP.
Preserve opaque query bytes. Verify the requested digest and descriptor size;
manifest dependencies additionally verify media type, structure and their graph.
Only the complete validated graph can enter the existing publication transaction.

Keep locators transient in parsed structures. Normalized manifest metadata stores
only descriptor identity, not URLs. Cache rows identify the canonical repository
path; journals/jobs do not record alternate URLs or source credentials. Original
immutable manifest bytes retain their exact descriptor fields, including any
URLs supplied by the publisher. Those bytes are tenant artifact data subject to
ordinary policy and cannot be rewritten without changing the manifest digest.
A signed URL embedded in immutable bytes may expire; source operators must
provide usable locators or publish a new manifest. No credential renewal is
inferred from an expired embedded URL.

Direct blob/manifest refresh must work after the process restarts. Query bounded
canonical parent records in the same tenant, repository and image, under current
repository grants. Exclude denied parents and reject a denied target digest.
Verify the retained parent bytes in CAS, reparse them, and match the raw
descriptor identity against normalized metadata before recovering locators.
This intake lookup is not graph-serving authorization and does not require an
expired dependency to become fresh first. Current graph policy and retrieval
generation/journal fences still apply at publication and serving. A direct
digest denial is checked before cache/source selection and remains an explicit
403, including forced refresh and a previously failed cache entry.

For a referent whose locator appeared only in a mutable referrers index, recover
its subject from verified cached referent bytes and walk that source catalog
again. Complete every bounded page, including legacy fallback only after API
404, before using the matching descriptor. This permits newly issued signed
advertisements after restart without persisting their old URLs. Combine unique
locators from repeated descriptors with the same primary identity.

Default URI attempt budget is 32 per retrieval (`--oci-descriptor-urls`); zero
disables fallback, maximum 4096. Retained parent lookup defaults to 64 candidates
(`--oci-descriptor-parents`, range 1–4096). Parent query results and raw manifest
reads share the native metadata byte ceiling. Duplicate retained locators are
deduplicated. Parent result exhaustion fails explicitly. Parser ceilings are 64
locators per descriptor and 32 KiB per URI; configured delivery URL/query limits
also apply before HTTP. Existing graph/transfer/deadline limits remain in force.

Owned-source tests cover approved, missing, temporary, corrupt, mis-sized,
unapproved, private-network, query, downgrade and budget cases. Real PostgreSQL
tests cover parent isolation, grants, decisions and bounds. A stock ORAS journey
launches the actual native server, copies an index/manifest/config/layer graph,
restarts the process and refreshes direct invalidated layer/manifest pins. It
checks no partial publication, no stale delivery after corruption, explicit
denial, newly issued referent query use after restart and locator absence from
normalized durable data. Exact source/binary
qualification is retained separately.

All provider/client/platform, private PKI, expired locator renewal, mutable-source
fault/scale and lifecycle/recovery campaigns remain required. No broad format or
readiness verdict is closed.

Primary reference observed 2026-10-28:

- [OCI Image 1.1.1: descriptor identity, alternate URLs and verification](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md)
