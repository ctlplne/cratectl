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
The native referrers API supports artifact-type filtering, pagination, HEAD,
conditional reads and preserved annotations. Attachment bytes remain unassessed until a
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
Every implicitly staged canonical manifest and blob has its own cache record:
inspect `IMAGE/manifests/sha256:DIGEST` or `IMAGE/blobs/sha256:DIGEST`. Expiring a
member also forces its dependent graph to revalidate before serving. Explicit
`Cache-Control: no-cache` forces retrieval. A successful zero-freshness response
admits its current request; the next request revalidates again. A root 304 still
renews its dependencies. Mutable manifests require strong ETags for exact-byte
reuse; weak/time-only validators cause a full root fetch.

A `graph_cache_superseded` conflict means newer member/tag state won while the
request was fetching. Retry to resolve current state; no partial graph was
published. `graph_cache_expired` means the bounded retry did not establish a
complete current graph; inspect the source/member cache records and origin.
An outage can serve stale bytes only inside every required member's own allowed
window. Operator invalidation, missing members and policy denial block stale use.
Complete source removal/lifecycle and the full fault campaign remain open.

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
Explicitly approved CDN delivery and opaque query credentials have owned
transport and stock-client/PostgreSQL proof. One pinned Linux arm64 image also has real Docker Hub/token/CloudFront proof.
Other providers and registry/token-service/client/platform combinations still
need qualification.
Full Docker/Podman/Helm, descriptor URL fallback, deletion, signatures,
lifecycle and security/fault/production campaigns remain open.

For native tags and referrers, send `n=100` and follow the returned relative
`Link` with `rel="next"`. The link retains the artifact-type filter and includes
an exclusive `last` marker. Use one nonnegative `n` and one valid tag or digest
marker; malformed or duplicate values return 400. `n=0` and exhausted pages return
empty arrays without a next link. GET and HEAD support representation ETags.
Each page rechecks current grants and policy, so concurrent mutations can change
later pages. A cursor does not retain an old policy snapshot.

Proxy discovery walks every source page before committing a complete catalog.
Opaque origin cursors are permitted only at the exact requested catalog resource;
another path or authority requires the approved delivery configuration described
below. Raw query bytes are preserved. A later-page error cannot publish a partial
graph or catalog. Catalog metadata is fetched unconditionally because a first-page
ETag cannot validate every page. Manifest/blob validators remain supported.

When the source referrers API returns 404, cratectl reads the legacy
`sha256-HEX` referrers tag. A missing fallback index is an empty catalog; other
errors and malformed indexes fail. Every discovered manifest must identify the
requested subject and pass current graph policy. Legacy discovery does not
verify signatures or scan payloads.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--oci-catalog-pages` | 32 | Maximum source pages per complete catalog walk; maximum 4096 |
| `--oci-page-size` | 1000 | Default and maximum entries per native page; maximum 100000 |

Entry, metadata and graph budgets also apply to the complete view. A limit error
requires reducing the catalog or deliberately adjusting the relevant configured
budget; pages never silently truncate it. See [ADR 0011](../adr/0011-oci-complete-discovery.md)
for the publication and cursor contract and its primary protocol references.


To consume a registry that redirects blobs to another service, add that service's
exact approved base under the OCI proxy's `download_sources`. For example, this
source entry permits opaque query credentials only below the stated path:

```json
{
  "url": "https://cdn.example/objects/",
  "networks": ["203.0.113.0/24"],
  "allow_signed_query": true
}
```

Replace the documentation address/CIDR with the source's actual authority and
approved networks. This is a source entry inside `settings.download_sources`,
not a credential value or a complete repository document. For an authenticated
CDN, add its own `credential_ref` and authentication scheme, with an independently
bound entry in the private server credential file. Anonymous signed delivery
usually omits a separate credential. Never paste a temporary signed URL into
repository settings. The registry issues a new URL on later refresh.

Each redirect uses the longest matching approved path and that source's own
credentials. The registry's bearer and token-realm credentials stay at their
respective sources. A CDN cannot request a registry token exchange. No Referer or
Cookie is forwarded. Unapproved hosts/paths, HTTPS downgrade, invalid query
syntax and network-ceiling violations fail before content publication. A rejected
more specific source cannot fall through to a broader credential.

`allow_signed_query` is false by default and is accepted only for OCI proxy
origin/download configurations. Query order, escaping and repeated parameters
remain exact; the upstream service validates its signature. Locations/query URLs
are not retained in durable cache metadata. An operator can inspect the canonical
member's cache state without exposing its temporary delivery credential.

Defaults and operator controls are:

| Control | Default | Meaning |
| --- | --- | --- |
| `--oci-delivery-redirects` | 5 | Hops per upstream request; 0 disables redirects; maximum 64 |
| `--oci-delivery-url-bytes` | 16384 | Complete ephemeral URL, within the 32 KiB response-header ceiling |
| `--oci-delivery-query-bytes` | 8192 | Query bytes, no greater than the URL budget |
| `--oci-delivery-query-pairs` | 64 | Total parameter pairs, including repeated keys; maximum 4096 |

If the cache reports `upstream_delivery_transport_failure`, inspect source DNS,
connectivity and TLS trust as well as the configured authority and network
ceilings. Signed URLs are deliberately absent from the error. This failure does
not grant stale delivery. Expired query credentials or rejected CDN responses
require repairing the source and revalidating the canonical repository path.

`make integration` now also runs the separate native-client conformance package.
It requires real PostgreSQL runtime/owner configuration and stock ORAS at
`.cache/bin/oras`; missing inputs fail explicitly. The server itself never
launches package clients or build tools. Owned upstream HTTP fixtures use temporary
loopback listeners; the native downstream registry uses the reserved port 38443.


For a real public provider qualification, use the separate explicit-source script.
This observed Docker Hub image is a Linux arm64 BusyBox 1.37 manifest; the digest
pins exact bytes even if the tag changes. The provider documents its token,
registry and CloudFront domains in its [official allowlist](https://docs.docker.com/desktop/enterprise/allow-list/).

```sh
CRATECTL_DEV_DATABASE=native python3 scripts/dev.py python3 scripts/conformance_public_oci.py \
  --registry https://registry-1.docker.io/v2/ \
  --image library/busybox \
  --digest sha256:d82c2ab94640ded77cf76514ce6a84870761105058a4a9e51b05a8a79be97a6c \
  --token-realm https://auth.docker.io/token \
  --service registry.docker.io \
  --delivery-base https://production.cloudfront.docker.com/ \
  --source-document https://docs.docker.com/desktop/enterprise/allow-list/ \
  --require-clean-build
```

Build the clean committed source first and start the owned development database.
The script uses fresh private tenant/client configuration and the owned loopback
registry port. Public-source CIDRs permit public addresses; no private-network
ceiling is enabled. It limits graph intake to 16 MiB and retains image bytes in
private OCI layouts. It verifies native proxy/group copies, cache generations,
process restart, member revalidation, current digest denial and the negative
control for missing signed-query permission. Credentials and signed delivery URLs
stay out of the report. Provider availability/rate limits can fail this explicit
qualification; deterministic owned fixture tests remain separate. Other providers,
architectures and clients still require their own evidence.
