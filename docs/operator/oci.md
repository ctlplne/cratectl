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

Native proof covers ORAS hosted multi-layer artifacts, indexes, referrers,
interrupted upload, restart and current policy. Proxy/group modes, challenge-token
upstreams, full multi-platform and Docker/Podman/Helm cases, deletion, signatures,
lifecycle and the complete security/fault campaign remain open.
