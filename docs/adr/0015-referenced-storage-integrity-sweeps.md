# Referenced storage integrity sweeps

Publication checks do not establish coverage of pre-existing bytes. An
administrator can request a sweep of every current artifact and retained OCI
upload-part binding in a repository or tenant. Admission snapshots immutable
repository/digest/size targets and reference counts in the same transaction as
the job, audit and idempotency response. It includes denied and unassessed bytes.
It deduplicates equal bindings and identifies contradictory size declarations.

Snapshot admission has an operator target budget and the existing SQL deadline.
Exceeding either rolls back the whole admission, with an actionable error. No
partial snapshot is acknowledged. A large asynchronous snapshot builder or
temporal reference catalog may become necessary after measured scale work; the
current synchronous snapshot's lock cost must remain visible and unqualified.

The integrity lane reads one target per claim, outside SQL locks, using bounded
paced SHA-256 readback. Each observation, progress cursor and yield commit under
the current job fence and worker credential. A process crash cannot advance the
cursor. Other ready integrity jobs get a turn between targets. Cancellation stops
before accepting another observation. A stopped run resumes its cursor; redriving
a completed run starts another pass over the same snapshot and retains history.

Completing an inspection is different from finding healthy storage. Coverage,
verified counts and issues remain separate. Missing/corrupt bytes, resource
limits, I/O errors, timeouts and inconsistent references never become a clean
verdict. An observation cannot approve policy or establish malware/signature
assessment. Concurrent reference changes cannot transfer an observation to a
different digest; the original snapshot binding remains the inspected object.

This snapshot covers referenced storage. It does not enumerate unreferenced CAS
or temporary files. Full CAS/staged/orphan inventory, safe GC, retention/holds,
scheduled sampling, repair, S3 and consistent backup/restore remain required.
