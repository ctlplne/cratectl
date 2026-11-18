# Start a blank Compose evaluation

Use an unprivileged Linux or macOS account, a local Docker Compose installation,
Python 3.10 or newer and the repository-pinned Go 1.27.4 SDK. Docker must run a
Linux amd64 or arm64 engine. To try the npm workflow, install a stock npm client
on the host. First stop any other local cratectl instance using port 38443.

```sh
python3 scripts/compose_evaluation.py up --tenant my-team
```

The launcher builds both Linux binaries from the current clean commit and
creates the `cratectl-evaluation` project. It starts the pinned PostgreSQL
16.16 image and waits for TCP readiness inside the Compose network. One
initializer migrates the empty database and creates the initial administrator
and worker credentials. The registry and worker use the `cratectl_app` database
role. It owns no tenant tables and has neither superuser nor BYPASSRLS.

The registry binds only `127.0.0.1:38443` on the host. PostgreSQL listens on port
35432 inside the Compose network and has no host port mapping. The registry
serves HTTPS using the CA generated for this installation. PostgreSQL uses
SCRAM authentication inside the dedicated local Docker network. The database
connection in this evaluation profile uses plaintext transport. Docker
administrators can inspect the database and initializer container environment.

Bootstrap creates no repositories or packages. Here is how to check readiness
and use the native management CLI from the host:

```sh
make build
export CRATECTL_EVAL="$PWD/.private/cratectl-evaluation"
curl --fail --cacert "$CRATECTL_EVAL/installation/ca.crt" https://127.0.0.1:38443/health/ready
bin/cratectl --config "$CRATECTL_EVAL/client.json"
```

The same CLI configuration works with `cratectl npm-config`. Follow the
[first repository and stock npm workflow](native-install.md)
using `$CRATECTL_EVAL/client.json` for `--config`. Keep `--ignore-scripts` for
the inert evaluation package. Initial administrator and worker credentials
expire after 24 hours. The local TLS certificate expires after 30 days.

To render the Compose topology as JSON, run the following command. The renderer
receives empty environment files in place of database credentials.

```sh
python3 scripts/compose_evaluation.py config
```

To stop and later resume the same project from its original clean commit:

```sh
python3 scripts/compose_evaluation.py down
python3 scripts/compose_evaluation.py up
```

`down` retains the database volume, object bytes and private TLS files.
Bootstrap reuses the original tenant and initialization
receipt while its credentials are valid. To evaluate a different commit or a
different initial tenant, choose a fresh `--project cratectl-...` and use that
name with every command. Only one project can publish port 38443 at a time.

This profile covers one local engine with one PostgreSQL instance, one registry
and one worker. Its Linux ARM64 run passed blank bootstrap, trusted TLS, stock
npm, worker processing and restart at `498a078`. Linux x64 execution, production
Helm, controlled upgrades, backup and recovery, replicated storage and
disconnected installation have separate qualification.
[ARM64 qualification](../../evidence/2026-11-18/compose-498a078-arm64.json)

Run the complete owned qualification from a clean commit with the host's native
architecture. It creates and stops a separate Compose project, retains its
database volume and keeps raw logs private.

```sh
python3 scripts/conformance_compose.py --architecture arm64
```
