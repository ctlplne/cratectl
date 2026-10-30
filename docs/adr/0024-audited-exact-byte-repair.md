# 0024: Recover exact retained bytes through a durable repair operation

Status: implementation in progress; qualification is recorded separately.

Repair takes its expected SHA-256 and size from an existing retained artifact
reference. A tenant administrator supplies an independently verified copy and
records its provenance and a reason. A matching digest proves exact byte identity;
it does not establish malware, signature or policy approval. Repair never changes
coordinates, digests, metadata, source epochs, decisions, holds or tombstones.

Use the existing tenant-RLS job/outbox and immutable integrity-observation tables.
A new immutable migration receipt advances runtime admission to schema 5 without
changing frozen steps 1–4 or adding tables. Old workers must reject the database
instead of claiming repair jobs they cannot interpret. Upgrade with registry and
workers stopped; compatible rolling workers remain unqualified.
A preview has no effects. Applying a plan records a bounded integrity job waiting
for its source; workers cannot claim it yet. A streamed, synced, verified source
is accepted idempotently and makes that same job ready. Staged sources and prior
corrupt files remain retained. Their garbage collection is separate work.

The private job payload retains the requesting credential hash for execution-time
authorization. Public job views expose a typed repair target with that value and
local source filenames omitted. Current tenant administrator authority, retained
reference identity and repository source revision apply before source acceptance
and immediately before the worker's filesystem effect. The dedicated worker's
current credential, cancellation state and lease generation also apply.

Hashing and streaming occur outside the tenant write transaction. A short, fenced
worker transaction installs a previously verified file using checked rooted
filesystem handles. Missing targets use a create-only link. Corrupt regular files
are retained by hard link before an atomic replacement. Healthy targets are
preserved. Unsupported entries and changed storage identities fail closed. No
storage path is accepted from an API caller.

A durable intent exists before installation. Installation and database commit
cannot form one atomic transaction: an interruption may leave recovered bytes
without a completion receipt. Repeating the same operation rechecks the actual
bytes and can record verified completion; it never infers success from an attempt.
The job reports success only after current readback and an immutable observation
commit. Cancellation or authorization loss cannot undo bytes already installed.
The journal distinguishes installation evidence from completed verification.

This workflow restores missing/corrupt bytes for supported local storage. Legacy
format-metadata repair, automatic upstream recovery, S3, scheduling, retention/GC,
large-scale recovery and full backup/restore remain separately required outcomes.

Current benchmark references: Sonatype's [Data Repair Tasks](https://help.sonatype.com/en/verify-and-repair-data-consistency-tasks.html)
separate planning from execution and warn about stale plans. JFrog's
[backup documentation](https://docs.jfrog.com/installation/docs/backups) describes
separate binary and metadata recovery. These references do not establish cratectl
parity; their broader recovery outcomes remain in the committed matrix.
