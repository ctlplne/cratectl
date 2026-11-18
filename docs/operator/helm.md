# Render the single-replica Helm deployment

The chart in `deploy/helm/cratectl` runs the registry and worker in one Pod with
one persistent filesystem claim. The `Recreate` strategy stops the old Pod before
starting its replacement. PostgreSQL, the persistent claim, container images and
the externally provisioned TLS and worker credentials are supplied by the operator.
[Kubernetes Deployment strategies](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)

| Value | Required input |
| --- | --- |
| `image` | A cratectl image pinned by SHA-256 digest with `/usr/local/bin/cratectld` inside. |
| `publicURL` | The externally reachable `https://` authority clients will use. |
| `postgres.runtimeSecret` and `postgres.dsnKey` | The Secret and key holding the restricted PostgreSQL connection URL. Use `sslmode=verify-full`. |
| `postgres.caSecret` | An optional Secret containing `ca.crt`. Select `/var/run/cratectl/postgres/ca.crt` with `sslrootcert` in the database connection URL when using it. |
| `tls.existingSecret` | A registry TLS Secret containing `tls.crt` and `tls.key`. |
| `storage.existingClaim` | A filesystem PersistentVolumeClaim writable by UID and GID 65532. |
| `worker.initImage` | A digest-pinned image providing BusyBox-compatible `/bin/sh`, `mkdir`, `head` and `wc`. |
| `worker.existingSecret` and `worker.tokenKeys` | The existing Secret and one or more keys holding cratectl worker credentials for the tenants this worker serves. |

Create all of these resources in the release namespace. Prepare the database with
the current schema using a separate owner-authorized `cratectld migrate`. Supply
the `cratectl_app` connection to the deployment. It needs the migration's runtime
grants and operates without superuser, ownership of tenant tables or BYPASSRLS.
Use `cratectld provision --role worker` to create the scoped worker credentials.
[Native database and credential setup](native-install.md)

The registry receives the TLS mount. A nonroot initializer copies the bounded
worker inputs into private regular files on a small tmpfs before the worker starts.
The main worker receives those files through a read-only mount. Replace the
referenced Secret or restart the Pod to load updated worker inputs. The Pod's
writable filesystem claim retains object data and the pagination key. Helm uses
the existing claim without managing its lifecycle.
[Kubernetes Secret volumes](https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/)

Use the example values to see the required shape and run the checked-in rendering
tests. The example contains placeholder image references.

```sh
python3 scripts/test_helm_chart.py
helm template cratectl deploy/helm/cratectl --namespace cratectl -f /path/to/values.yaml
```

After preparing operator resources in the intended cluster, install using your
namespace and values. The chart provides a ClusterIP HTTPS service on port 38443.
Route the `publicURL` to that service through the cluster's existing ingress or
private routing. Configure clients to trust the issuer of the registry certificate.

```sh
helm upgrade --install cratectl deploy/helm/cratectl --namespace cratectl -f /path/to/values.yaml
```

Current qualification covers Helm lint, configuration rendering and the init
shell's bounded copy behavior. A Kubernetes deployment, native client admission,
storage-driver behavior, backup and rollback, HA and production readiness require
their own qualification.
