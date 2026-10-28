# Owned native database fallback

The normal development profile uses the exact owned `cratectl-dev-postgres`
container and retained `cratectl-dev-postgres-data` volume. If the shared Docker
runtime cannot create tasks, local engineering can use a separate native cluster
without restarting Docker or altering that retained volume.

Run `python3 scripts/bootstrap_native_postgres.py` to download PostgreSQL 16.15
from the official source archive, verify its published SHA-256 and build into
`.cache/postgresql-16.15-install`. The build log and source manifest stay under
`.cache/`. This needs Python 3.14+, a C compiler and make. It installs no global
service or package. The source and checksum share the official download origin;
this is local engineering bootstrap, not signed release-bundle qualification.

Run `CRATECTL_DEV_DATABASE=native python3 scripts/dev.py init`. The helper creates
a fresh private cluster under `.private/cratectl-native-postgres`, private owner
and runtime DSNs in `.private/native-db.json`, and SCRAM credentials. It listens on
127.0.0.1:35432 with Unix sockets disabled, 64 MiB shared buffers and 30 connections.
The app role remains a nonowner, nonsuperuser without BYPASSRLS. The same forced
RLS migration and native-client suite run against this real PostgreSQL server.

Prefix integration/conformance commands with `CRATECTL_DEV_DATABASE=native`.
For example, run `CRATECTL_DEV_DATABASE=native python3 scripts/conformance.py all`.
Use `python3 scripts/native_db.py stop` to stop only this owned data directory,
retaining its state. Stop it before starting the container profile on the same
reserved port. The helper never migrates, replaces or restores container data.

This fallback is a fresh independent local test dataset. It is not a recovery of
the original container volume. Readline, ICU and zlib are disabled in this cached
development build; PostgreSQL-to-app TLS is not configured on this loopback
profile. CPU/RAM container limits do not apply to this native process. Native,
container, production, restore and HA qualification remain distinct results.
