# OCI hosted artifacts and attachments

Create a hosted repository with format `oci`. Its native image reference is
`REGISTRY/REPOSITORY/IMAGE:TAG`, where REGISTRY is the public host and port.
Configure an ordinary OCI client with an expiring tenant token. For ORAS, keep
the token and client registry configuration private:

```sh
oras login --registry-config /private/cratectl-registry.json \
  --username token --password-stdin REGISTRY < /private/cratectl-token
oras push --registry-config /private/cratectl-registry.json \
  REGISTRY/REPOSITORY/IMAGE:v1 artifact.tar:application/octet-stream
oras pull --registry-config /private/cratectl-registry.json \
  REGISTRY/REPOSITORY/IMAGE:v1
```

A writer publishes; a reader consumes permitted bytes. Review-required
repositories accept durable intake while keeping its manifest and payload graph
quarantined. Inspect administrator inventory and manually decide the exact root
and required child digests. An intake response is not a security assessment.
Registry processes never execute or unpack these artifacts.

OCI image manifests require a complete config descriptor and layers array.
Indexes require a manifests array. Declared lengths must match durable bytes,
and a manifest child's media type must match its stored identity. The current
digest support is SHA-256. Input is limited to 4 MiB, 64 JSON levels and 4096
descriptors; serving and publication graphs have depth 32 and 4096 unique-object
budgets. Those graph limits need operator configuration before production use.
Duplicate JSON members and contradictory content types are rejected. Recreate an
invalid manifest from its original build outputs before retrying.

Use `oras attach --artifact-type MEDIA_TYPE REFERENCE FILE` to attach an SBOM or
other evidence, and `oras discover REFERENCE` to discover permitted attachments.
The native referrers API supports artifact-type filtering, HEAD, conditional
reads and preserved annotations. Attachment bytes remain unassessed until a
policy decision says otherwise; storing a signature does not verify it.

An attachment may arrive before its subject. Once the subject exists, its exact
descriptor and current policy also govern attachment reads. A denied subject or
payload blocks its dependent manifests, tags and referrer discovery. Denied
attachments are omitted from discovery. A digest pin does not bypass policy.

Tags can change while clients operate. A tag retarget during stored-byte
verification returns a conflict; retry to resolve its new permitted value, or use
an intentional digest pin. A 406 response means the requested representation
does not accept the stored OCI/Docker media type. The registry serves exact bytes
and never converts a digest-addressed manifest.

Development manifests without structural validation return
`oci_manifest_unvalidated`. Re-publish the same bytes through an authorized
writer, children before parents. Existing digest decisions remain in force.
This does not qualify production upgrades or restore.

Create a proxy repository with its upstream native base, such as
`https://registry.example/v2/`, explicit network CIDRs and an optional
tenant-scoped credential reference. Clients use its ordinary
`REGISTRY/REPOSITORY/IMAGE:TAG` endpoint. A miss stages and validates the complete
manifest graph before publishing its references. Review-required proxies keep
that graph quarantined until exact digest decisions permit consumption.

For a challenge-token upstream, explicitly configure `oci_token_endpoint` with
its exact realm URL, CIDRs and separate credential reference, plus
`oci_token_service` with its exact audience. Origin and token credentials are
independently bound in the server's private credential file. Anonymous realms
can omit a credential. The challenged URL/audience must match, and the requested
scope is limited to pull access for the configured source repository path.
Private addresses still require the operator's private-network ceiling.

Cached reads enforce current policy. Freshness, negative caching and explicit
stale windows use the shared proxy cache settings. Inspect the cache API for the
requested `IMAGE/manifests/TAG` or `oci-catalog/IMAGE/tags` path to explain a
failure or expire a binding after repairing its origin. A complete tag refresh
can add or remove mutable tags while retained digest pins keep their exact bytes.
Full per-object freshness and invalidation for implicitly staged graph members
remains open. Explicit `Cache-Control: no-cache` requests force retrieval; the
current native freshness proof covers the listed tag/catalog paths.

Groups take an ordered hosted/proxy `members` list. Reserve private image prefixes
through namespace ownership. The first source owns a tag/digest collision,
including blocked content; a denial never authorizes fallback. Readers need
grants to all selected sources. Group review covers the whole graph. Publish to
a hosted member, then pull or discover through the group endpoint.

The default aggregate OCI retrieval budget is 4 GiB (`--oci-graph-bytes`), with
shared native metadata/tag budgets and a 32 MiB graph-read metadata budget.
Layer bytes remain opaque. There is no partial graph or truncated native index.
Node/depth/read-metadata limits still need operator configuration and scale proof.

Native ORAS proof covers hosted/proxy/group multi-layer workflows, tag refresh,
retained pins, referrers, concurrent misses, interrupted hosted upload, restart
and current policy. Approved token-realm authority has transport fixture tests.
CDN/cross-authority redirects and signed URLs remain rejected, so upstreams that
require those delivery paths are not yet compatible. Full multi-platform and
Docker/Podman/Helm cases, token-service/registry combinations, referrer fallback/
pagination, deletion, signatures, lifecycle and full security/fault qualification
remain open.
