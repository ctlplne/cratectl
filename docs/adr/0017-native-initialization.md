# Blank native installation and local trust

The native operator supplies an empty PostgreSQL database, its migration/owner
connection and a restricted runtime login. `cratectld init` prepares a private
installation directory, migrates the database and atomically creates the first
tenant, expiring administrator/worker credentials, audit intent and a bootstrap
receipt. An existing database without this installation's receipt is rejected.
Reruns use the same receipt and credential hashes; they never replace existing
tenant data or silently rotate credentials.

Preparation is durable before database effects. A process lock serializes local
initializers; a PostgreSQL advisory lock serializes database initialization.
Private preparation state permits retry after interruption, including a database
commit before the local ready configuration is written. Owner database authority
is read from the environment only and is never retained in runtime configuration.

The first native profile listens on loopback using a generated local CA and
server certificate. The operator explicitly supplies the CA to the CLI and stock
client. TLS verification stays enabled. Network deployments use operator-managed
certificates and the existing explicit server settings; production PKI lifecycle,
Compose/Helm packaging and disconnected installation remain required work.

Server and worker can read the same private runtime configuration. The CLI reads
a separate configuration containing only its authority, CA path and token path.
Explicit command flags override file defaults. Configuration is bounded, rejects
unknown fields and cannot contain owner database authority. No vendor connection
or account is required. The native initializer does not install PostgreSQL or
package clients and does not establish blank-machine or production qualification.
