# Durable tenant filesystem inventory

Referenced sweeps cannot account for unreferenced CAS objects, temporary files or
legacy upload files. A tenant administrator may admit an inventory job with a
bounded immutable reference snapshot and a fingerprint of the configured storage
root. The integrity lane enumerates the supported tenant layout, checks observed
CAS files, then checks the reference snapshot. Every page or observation commits
with its cursor, audit and current worker fence. No byte is edited or deleted.

The walk covers tenant-root entries, the SHA-256 prefix directory, every observed
supported prefix, staged files and legacy uploads. Ordered pages use bounded
memory and a per-directory entry budget. Computing a page may rescan a directory;
large-directory I/O cost must remain explicit and unqualified. Unsupported names,
directories and special files remain visible and prevent a clean layout verdict.
Links are recorded without following them. Descriptor-rooted regular-file reads
reject unsupported objects instead of blocking on a named pipe.

Filesystem enumeration is a live walk, not an atomic volume snapshot. Concurrent
entries behind a completed cursor may require the next run. Each entry records
its observed identity and time; hashing detects replacement or mutation. A changed
storage root fences the run. Current reference counts are separate from counts
observed during the walk. Unreferenced-at-observation never means safe to delete.

Completion, layout coverage, byte integrity and security approval stay separate.
Interrupted retries resume; completed redrives recheck the retained observed set
and original reference snapshot in a new pass. A new inventory performs a new
walk. File/target budgets reject admission or stop work without a partial success
receipt. Holds, retention, replicas, GC, scheduling, repair, S3 and consistent
backup/restore remain required; inventory is evidence for those workflows.

Publication creates and links staged/canonical objects under checked tenant
directory descriptors and rechecks the visible root before acknowledging bytes.
Regular readback refuses links/special files; duplicate-object and serving reads
are bounded to the expected size plus one. This rejects unsupported tenant-root
links instead of writing into another namespace. Worker callbacks reauthenticate
before commit, and attempt timeouts stop lease renewal. Native non-Unix behavior
and production filesystem outage/restore semantics remain unqualified.
