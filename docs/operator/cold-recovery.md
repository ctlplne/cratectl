# Pair and verify a cold physical backup

This procedure covers a single stopped native cratectl installation using
local filesystem objects and PostgreSQL 16. Stop the registry, workers, and
any other writers before recording the checkpoint and copying the local
state. Keep the physical backup and local state from the same maintenance
window. Use a private, operator-controlled backup location. It contains
database data and active private TLS and credential material.

Use an authorized PostgreSQL backup role and matching stock tools to create
a plain physical backup with the WAL required by the backup.
[PostgreSQL base backup](https://www.postgresql.org/docs/16/app-pgbasebackup.html)

```sh
pg_basebackup --pgdata "$PG_BACKUP" --wal-method=stream \
  --manifest-checksums=SHA256 --checkpoint=fast --no-password
```

While writers remain stopped, record the current journal heads in a private
JSON file with an authorized maintenance connection. This query describes
the journal state to compare after restoration.

```sql
SELECT coalesce(json_agg(head ORDER BY head.tenant), '[]'::json)
FROM (
  SELECT tenant, count(*) AS event_count, max(sequence) AS last_sequence,
         (array_agg(hash ORDER BY sequence DESC))[1] AS last_hash
  FROM cratectl.events
  GROUP BY tenant
) AS head;
```

Pair the physical backup with the stopped installation tree, the exact
pagination key, and the checkpoint. Use a new path under a private directory
you already own. PostgreSQL tablespaces with symlinks and mixed-version
physical copies require a different recovery procedure.

```sh
python3 scripts/cold_snapshot.py capture --database "$PG_BACKUP" \
  --installation "$INSTALLATION" --pagination-key "$PAGINATION_KEY" \
  --journal-checkpoint "$JOURNAL_CHECKPOINT" --directory "$SNAPSHOT"
```

Keep the returned manifest SHA-256 through a separate trusted channel. The
verifier checks the complete directory inventory, exact local bytes, and
PostgreSQL's native backup manifest before reporting success.
[PostgreSQL backup verification](https://www.postgresql.org/docs/16/app-pgverifybackup.html)

```sh
python3 scripts/cold_snapshot.py verify "$SNAPSHOT" --sha256 "$TRUSTED_SNAPSHOT_SHA256"
```

Restore the validated database to a new PostgreSQL data directory and the
installation files to a separate private destination. Supply the same
absolute application paths through the new runtime's mounts. Start the
database first, recompute the journal heads, and compare them with the
recorded checkpoint before starting the registry and worker. Check current
policy, the original TLS trust, and stock-client retrieval from a fresh
cache. Keep the verified backup intact through this process.

The pairing tool bounds individual files to 1 GiB, aggregate bytes to
16 GiB, and the complete inventory to 10,000 entries. Protect backup storage
with your existing encryption and access controls. Keep broader S3,
live-copy, mixed-version, independent-host, and recovery-time qualification
separate.
