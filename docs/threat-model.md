# Initial threat model

Assets: tenant package bytes/coordinates, credentials, policy decisions, event
history, release evidence and durable references. Trust boundaries: native
client to server, runtime to database, staged to published bytes, upstream to
proxy, and analysis worker to registry. The last two are not implemented yet.

Attackers include an unauthenticated caller, a reader attempting publication,
a publisher uploading malicious metadata, and one tenant guessing another's
names/digests. An administrator role is tenant-scoped; provider administration
must remain a separate authority. A database owner or filesystem administrator
is inside the deployment trust boundary. A local hash chain detects inconsistent
history but cannot defeat an administrator who rewrites both history and anchors.

Required early regressions: absent/wrong/revoked credentials; forced RLS with an
omitted tenant predicate; same coordinates in different tenants; immutable
redeploy races; partial upload, declared-length/digest mismatch; traversal and
encoded separators; quarantine on direct and metadata paths; idempotent replay
and changed-body conflict; restart persistence; range/conditional GET; audit
chain verification. Limits and native client evidence live in qualification.

Open threat campaigns remain in `remaining.json`: SSRF/DNS rebinding, upstream
credential forwarding, decompression bombs, scanner/plugin escape, signed-link
revocation, federation conflicts, policy races and restore/GC corruption. No
claim of complete security follows from the early regressions.
