# First repository from an empty native installation

This profile uses the two cratectl binaries, an empty PostgreSQL 16 database and
an npm client already installed on one Linux or macOS host. It needs no vendor
account. It does not install PostgreSQL or qualify production packaging, a blank
machine, a disconnected bundle or the full operator console.

The database administrator supplies a dedicated empty database and two private
connection files. The owner connection owns the application schema and has
BYPASSRLS for installation and emergency identity maintenance. The runtime login
must be `cratectl_app`, a nonowner without superuser or BYPASSRLS. Precreate that
login with a private SCRAM password; migration grants its database permissions.
The initializer does not change an existing cluster role's password.

For a new dedicated PostgreSQL cluster, an administrator can prepare these roles:

```sql
CREATE ROLE cratectl_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS;
\password cratectl_owner
CREATE ROLE cratectl_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
\password cratectl_app
CREATE DATABASE cratectl OWNER cratectl_owner;
```

Supply each connection URL through your secret manager or an owner-readable file.
Use PostgreSQL TLS and verified database identity for a network database. The
connection names below are paths to those private files, not literal secrets:

```sh
read -r CRATECTL_OWNER_DSN < /private/path/owner.dsn
read -r CRATECTL_DSN < /private/path/runtime.dsn
export CRATECTL_OWNER_DSN CRATECTL_DSN
mkdir -p .private
chmod 700 .private
export CRATECTL_BIN="$PWD/bin"
export CRATECTL_INSTALL="$PWD/.private/evaluation"
"$CRATECTL_BIN/cratectld" init --directory "$CRATECTL_INSTALL" --tenant my-team
```

Initialization creates no repository or sample package. It writes a private
preparation record, migrates only an empty database or this installation's prior
database, and atomically creates one tenant and separate administrator/worker
credentials with an audit receipt. A nonempty unrelated database is rejected
before migration. Both credentials expire in 24 hours by default; choose
`--credential-lifetime` at preparation. This is an initial access credential,
not a permanent identity-provider integration.

Pre-migration inspection reads at most 257 catalog entries and rejects more than
256 application tables. This is a bound on checking a supposedly empty database,
not a limit on tenants, packages or a running installation. Select the intended
dedicated empty database if the check rejects an existing large schema.

The JSON receipt gives configuration paths, credential expiry and the CA's
SHA-256 fingerprint. The generated certificate is for `localhost` on loopback
38443; `--listen` and `--public-url` can select another literal loopback listener
and local authority on the same port. The CA and certificate expire after 30
days. The CA signing key is discarded. Before expiry, replace the server key and
certificate using your own PKI, update its runtime paths and distribute that
trust to clients. Automatic PKI rotation remains unfinished.

Start the service and worker in separate terminals. They read their restricted
database connection from the private file; owner credentials are unnecessary:

```sh
unset CRATECTL_OWNER_DSN CRATECTL_DSN
"$CRATECTL_BIN/cratectld" serve --config "$CRATECTL_INSTALL/runtime.json"
"$CRATECTL_BIN/cratectld" worker --config "$CRATECTL_INSTALL/runtime.json"
```

The generated CLI configuration references the administrator token and public CA.
Create the first npm repository with review required:

```sh
"$CRATECTL_BIN/cratectl" --config "$CRATECTL_INSTALL/client.json"
cat > "$CRATECTL_INSTALL/repository.json" <<'JSON'
{"name":"packages","format":"npm","require_review":true}
JSON
"$CRATECTL_BIN/cratectl" --config "$CRATECTL_INSTALL/client.json" --method POST --path /api/v1/repositories --body-file "$CRATECTL_INSTALL/repository.json" --idempotency-key first-repository-001
"$CRATECTL_BIN/cratectl" npm-config --config "$CRATECTL_INSTALL/client.json" --repository packages --output "$CRATECTL_INSTALL/npmrc"
```

`npm-config` writes an owner-readable file containing the scoped credential and
verified TLS settings. It refuses to overwrite an existing file. Set
`NPM_CONFIG_USERCONFIG` to that file's absolute path, then use stock npm:

```sh
export NPM_CONFIG_USERCONFIG="$CRATECTL_INSTALL/npmrc"
cd /path/to/your/package
npm publish --ignore-scripts
```

The first install is denied until an administrator approves the exact bytes.
Inspect their path and digest:

```sh
"$CRATECTL_BIN/cratectl" --config "$CRATECTL_INSTALL/client.json" --path /api/v1/repositories/packages/artifacts
```

Write those exact returned values to `$CRATECTL_INSTALL/decision.json`, then submit it. An allowed
manual decision is not a vulnerability or malware scan:

```json
{"path":"the returned package path","digest":"the returned SHA-256","decision":"allowed"}
```

```sh
"$CRATECTL_BIN/cratectl" --config "$CRATECTL_INSTALL/client.json" --method PUT --path /api/v1/repositories/packages/decisions --body-file "$CRATECTL_INSTALL/decision.json" --idempotency-key approve-first-package-001
npm install --ignore-scripts YOUR_PACKAGE@YOUR_VERSION
```

Run management commands from the installation working directory or use absolute
configuration paths. Restart the service with the same runtime configuration;
the repository, policy and package bytes persist. Inspect `/api/v1/jobs` for work
completion and `/api/v1/audit` for the authoritative tenant journal. Activity at
`/api/v1/activity` is an asynchronous projection and may lag the journal.

If initialization is interrupted, rerun `init --directory` with the same owner
connection. A local process lock is released when the process exits. The durable
preparation and database receipt reuse the original tokens and trust, including
after a database commit before the ready runtime file was written. Modified
files and conflicting parameters are rejected rather than overwritten. Keep
`prepare.json` private: it contains recovery credentials and the server key.
For an expired or revoked credential, use the existing owner `provision` command
to create a new scoped token, then update the relevant client/worker token path;
restart the worker after changing its identity configuration. Rerunning init
does not extend or rotate credentials.

Explicit CLI/server/worker flags override configuration defaults. `cratectl
--ca-file` can select operator-managed trust; TLS verification stays enabled.
Config files are bounded and reject unknown fields. Production deployment,
credential/PKI lifecycle, operating-system coverage, console accessibility,
upgrade/recovery and the remaining product scope still need qualification.
