# cratectl

A self-hosted artifact repository and software supply-chain control plane under
active development. **This is an engineering foundation, not a qualified release.**
The entire product destination is in [GOAL.md](GOAL.md). Progress and unfinished
scope are in [STATUS.md](STATUS.md) and [the capability ledger](docs/qualification/parity.json).
No parity, production readiness, scanning or high-availability claim is made.

Implemented locally: PostgreSQL tenant isolation, immutable filesystem objects,
transactional publication/events/outbox intent, tenant service tokens, manual
digest decisions, repository policy, management CLI, durable worker lanes and
early hosted/proxy/group npm, PyPI, OCI and Maven operations. The
[worker](docs/operator/jobs.md) indexes source events and checks stored-byte
integrity with fenced leases, retries and cancellation. Neither a hash match nor
a manual decision is a malware or vulnerability scan. Pending intent is not
completion.

## Initialize a blank native installation

The [operator console](docs/operator/console.md) is embedded at `/console/`. It uses
the same tenant authorization, policy and durable operations as the CLI/API.

The [native install guide](docs/operator/native-install.md) starts with an empty
PostgreSQL database, creates private administrator/worker configuration and local
TLS trust, then walks through first npm publication, exact-digest approval and
installation. Database and clients are operator-supplied. Production packaging,
the console and full platform/security qualification remain unfinished.

## Build and run the local engineering profile

Use Go 1.27.3, Docker, Python 3.10+, Node/npm. This is a single Mac/Linux development
profile. The commands below create only `cratectl-dev-postgres` and its retained
volume on loopback port 35432. Generated credentials stay in ignored `.private/`.
There is no vendor account, entitlement check, or telemetry dependency.

```sh
make build
python3 scripts/dev.py init
python3 scripts/dev.py bin/cratectld provision --tenant my-team --actor operator --role admin --token-file .private/operator.token
python3 scripts/dev.py bin/cratectld serve --dev-loopback-http --public-url http://127.0.0.1:38443
```

Credentials default to a 24-hour lifetime; `provision --expires-in` sets an explicit
lifetime. Emergency `cratectld revoke --token-file` uses owner authority, records an
audit event, and invalidates later requests. Transactions recheck credentials at
execution, and serving rechecks policy after integrity verification.

The explicit HTTP flag is restricted to a literal loopback listener. For a network
listener, supply a certificate/key from your own CA using `--tls-cert`/`--tls-key`
and an HTTPS `--public-url`; install the CA in the client's trust store. The native initializer supplies local loopback trust; production PKI lifecycle
and deployment packaging remain unfinished.
Database owner credentials are used only by init/migrate/provision/revoke. The server rejects
a database role that owns tenant tables, is superuser, or bypasses RLS. Do not
use this development database setup as a production credential-management system.

In another terminal, create a repository using an idempotency key. A retry with
identical method/path/body returns the original response; changing the request
under the same key returns HTTP 409.

```sh
printf '%s\n' '{"name":"packages","format":"generic","require_review":true}' > .private/repository.json
bin/cratectl --url http://127.0.0.1:38443 --token-file .private/operator.token --method POST --path /api/v1/repositories --body-file .private/repository.json --idempotency-key create-packages-001
```

`require_review: true` prevents unassessed bytes from being served. An admin can
allow or deny an exact path and SHA-256 through the decisions API. With the flag
false, unassessed artifacts are permitted by an explicit repository policy and
remain labelled unassessed. No absent scanner result is labelled clean.

## Current protocol endpoints and limitations

| Format | Endpoint | Current limits |
| --- | --- | --- |
| Generic | `/r/REPOSITORY/PATH` | PUT and authorized GET/HEAD, range, ETag; no lifecycle/export yet |
| Maven | `/r/REPOSITORY/COORDINATE` | hosted files, mutable native metadata, computed checksums; complete Gradle/Ivy/SBT, grouping and snapshot campaigns remain open |
| npm | `/npm/REPOSITORY/` | publish/install scoped packages and dependencies, dist-tag edits and early proxy/group proof; 24 MiB publish document; full search, deprecation, signatures, provenance and lifecycle remain open |
| PyPI | `/pypi/REPOSITORY/` for twine; `/pypi/REPOSITORY/simple/` for pip | streamed multipart files, HTML/JSON simple indexes, yanking, bounded archive identity checks and early proxy/group proof; full client/metadata/signature/lifecycle campaigns remain open |
| OCI | `/v2/REPOSITORY/IMAGE/...` | ORAS hosted/proxy/group multi-layer pulls, resumable hosted uploads, validated indexes, governed referrers, tag/graph policy and per-member cache revalidation; approved token realms and independently configured signed CDN delivery have owned transport/ORAS proof. A pinned Docker Hub/CloudFront Linux arm64 journey has real-service proof; other providers, delete/mount, full Docker/Podman/conformance and graph-policy campaigns remain incomplete; see [operator guide](docs/operator/oci.md) |

Generic/Maven/npm/PyPI/OCI proxy and group paths plus repository actor grants have
early native proof; see [operator configuration](docs/operator/proxy-and-group.md).
Full proxy/group semantics, content selectors, production S3, quotas, global
worker scheduling, scanners, identity federation, console,
replication, migration, governance and the remaining format families are open.
Management list endpoints currently cap at 1,000 rows; full management cursor
pagination is unfinished. Jobs and activity support documented cursors. Native OCI tags/referrers have bounded `n`/`last`
pages and complete upstream page walks; see the OCI operator guide.
Filesystem reads rehash the entire object before sending it. This detects
same-length corruption but adds disk I/O and has not met transfer targets.
OCI graph checks use a single database snapshot, bound traversal to depth 32 and
4096 members, and fail closed for missing graph metadata. Pre-graph development
records need repair/re-import; supported upgrade/backfill remains unfinished.
An uploaded archive or package script is never executed by the server.

## Verification

```sh
make test
make lint
make race
python3 scripts/dev.py make integration
make conformance
```

Integration tests require the real database and fail when it is absent.
Conformance needs native npm, twine/pip, ORAS and Maven/JDK in the paths recorded
in `scripts/conformance.py`; client installation is operator-supplied. The separate
`scripts/conformance_installation.py` journey starts from an empty database and
uses the initializer and verified TLS. Neither test installs a blank machine. Each run creates private fixtures,
starts/stops its own server and retains a sanitized evidence JSON. Assertions
cover only the listed journeys, not complete ecosystem conformance. `make security`
and `make packaging` deliberately fail until the full required campaigns exist.

[API contract](api/openapi.yaml), [architecture](docs/adr/0001-foundations.md),
[threat model](docs/threat-model.md), [licensing hold](docs/licensing.md).
Core licensing text requires owner approval before distribution; local engineering
is authorized. There is currently no `ee/` code or license enforcement in core.

To stop the owned database without deleting data:

```sh
docker stop cratectl-dev-postgres
```

Do not prune Docker resources or remove the retained volume as routine cleanup.
