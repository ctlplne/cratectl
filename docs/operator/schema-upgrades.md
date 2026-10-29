# Inspecting and applying schema changes

Run the owner CLI with `CRATECTL_OWNER_DSN` supplied through your private process
environment. The runtime config deliberately omits this database authority.

```sh
bin/cratectld migrate --plan
```

The JSON reports the binary's schema version, ordered applied checksums, pending
versions, safety and any legacy-adoption requirement. It does not change schema
or print the connection string. A busy migration closes admission and may make
inspection return a maintenance error; retry after it finishes.

Applied steps are immutable. A missing, reordered, unknown or changed receipt,
changed safety function, disabled forced RLS or weakened tenant policy rejects
the operation. Do not repair that by editing checksums or deleting receipts.
Inspect the selected database, binary source and owner-managed schema changes.
The runtime also rejects superuser/BYPASSRLS, effective table ownership and access
to private receipt metadata, including privileges changed after startup.

For a current database, `bin/cratectld migrate` checks the receipts and safety
without DDL or an exclusive lock. This avoids the prior cumulative replay that
could deadlock a live upload. Schema changes and their receipts commit in one
transaction. A failed or disconnected migrator rolls back its uncommitted work;
inspect the plan before retrying.

An older, unversioned installation needs a maintenance adoption:

1. Take and validate the backup appropriate to your installation. Backup/restore
   qualification remains open; this command is not a backup.
2. Stop every registry and worker using that database, including old binaries.
   Old binaries do not acquire the new transaction gate.
3. Run `bin/cratectld migrate --plan` against the intended database, then
   `bin/cratectld migrate --adopt-legacy`.
4. Confirm the plan is `current`, has no pending versions and reports valid
   safety. Start the matching registry and workers and check readiness and an
   actual native publish/install operation.

The explicit adoption flag acknowledges the maintenance precondition; the CLI
cannot prove that every old process has stopped. Ordinary `migrate` refuses
unversioned data. `init` still requires an empty database or this installation's
matching bootstrap receipt; use migration to upgrade existing installations.

Cooperating new binaries acquire a shared advisory gate before starting each
database transaction. A migration queues an exclusive gate, drains admitted
transactions and declines new work while waiting or applying. Requests receive
503 with `schema_maintenance` and `Retry-After: 1`; keep the credential and retry.
The console retains its active credential and offers **Try again**. Readiness
fails during maintenance; liveness and the console shell remain available.
An incompatible or unsafe schema returns 503 with `schema_incompatible` and
needs owner inspection, rather than reconnecting with another credential.

This gate protects database transactions, not an entire network upload or
download. A real upgrade can interrupt a staged transfer at its next database
check; retry from its last acknowledged state. Repeating a current migration
does not close admission. Version compatibility ranges, expand/contract changes,
whole-transfer draining, independent-node rolling upgrades, downgrade/recovery,
HA and production-scale upgrade behavior remain unqualified.
