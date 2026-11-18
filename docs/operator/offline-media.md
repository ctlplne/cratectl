# Prepare and check Linux offline media

This candidate workflow is for authorized local qualification. It requires a
clean source checkout, its pinned Go toolchain and prepared Go module cache.
The assembly host also needs Helm and a local Docker engine that supports
platform-specific image inspection and export through API 1.49 or newer.
The PostgreSQL image must already be available by the pinned reference in
`scripts/compose_evaluation.py` for the intended platform.
[Docker image inspection](https://docs.docker.com/reference/cli/docker/image/inspect/)
[Docker platform-specific export](https://docs.docker.com/reference/cli/docker/image/save/)

```sh
make package-linux-sbom
python3 scripts/linux_offline_media.py prepare --architecture arm64
```

The resulting directory in `.cache/cratectl-offline-media/` contains the native
archive, two inventory documents, two platform-specific OCI image archives,
the Helm chart, local operating instructions, installer scripts and a manifest
binding every file by length and SHA-256. The image archive for the registry
comes from the two executables in the verified native archive. The manifest
records the exact cratectl-owned tags and image configuration digests.

Have the authorized external signer sign the exact `release-manifest.json`
bytes using its approved Ed25519 key. Write the detached signature to
`release-manifest.sig` in the prepared media directory.

```sh
openssl pkeyutl -sign -rawin -inkey "$SIGNING_KEY" \
  -in "$MEDIA/release-manifest.json" -out "$MEDIA/release-manifest.sig"
```

Bring the trusted verifier and its source dependencies from the approved
checkout. Receive the Ed25519 public key and its PEM file SHA-256 through an
independent trust channel. Verify the staged copy before using its images,
installer or documentation.

```sh
python3 scripts/linux_offline_media.py verify "$MEDIA" --architecture arm64 \
  --trusted-key "$APPROVED_PUBLIC_KEY" --trusted-key-sha256 "$APPROVED_PEM_SHA256"
```

Copy the authenticated directory into storage controlled by the installing
operator. Import the named image archives on the disconnected Docker engine
and compare each platform's image configuration digest with `images` in the
verified manifest. The saved tags are specific to the candidate and
architecture.
[Docker platform-specific import](https://docs.docker.com/reference/cli/docker/image/load/)

```sh
docker image load --platform linux/arm64 -i "$MEDIA/postgres-image.tar"
docker image load --platform linux/arm64 -i "$MEDIA/registry-image.tar"
```

The native archive can be installed using the verified digest from
`members` and the instructions in `linux-candidate.md`. The database inputs
and trust keys for the intended deployment are supplied independently.
Production license approval, signing authority, offline scanner data, and
full disconnected provisioning and recovery qualification remain open.

The stock-client replay in `scripts/conformance_offline_media.py` assembles
and signs disposable test media, refuses a changed image, loads both images
after removing their owned tags, and starts the registry and worker in a
loopback-only Docker namespace. The native GitHub workflow runs the same
check on x64 and ARM64 using prepared Docker, Helm and stock-client tools.
