# Complete bounded management traversal

Repository and artifact management lists must traverse all currently authorized
records without a fixed total-result ceiling. Use keyset pages in bytewise C
collation, bounded page size (1–1,000, default 1,000 for existing clients), bounded
literal case-insensitive search, and server-provided next/previous cursors. The
console uses 100-row pages and submits search to the server. It never accumulates
all repositories in a selector or silently searches one response as if complete.

Repository grants and ordinary artifact decisions filter SQL before its result
bound. OCI manifest visibility also requires the existing complete child-graph
policy reader. Scan one bounded candidate page, apply that same reader in one
repeatable-read transaction, and retain both visible results and progress through
hidden candidates. An empty visible page can still have a continuation. Do not
fork graph authorization into a second SQL approximation or skip hidden ranges.

Cursors encrypt and authenticate the scan key and direction with AES-256-GCM,
using a separate persisted private key. This prevents the continuation from
revealing a hidden OCI path. Bind authentication to tenant, credential, actor,
role, endpoint/repository and search. Malformed, tampered or differently scoped
cursors fail. A cursor conveys no authorization: forced RLS and current credential,
grant and content policy checks run on every request. The crypto boundary owns
all cipher/random operations.

Native installations store a private pagination key next to runtime configuration;
manual servers can explicitly supply --pagination-key-file. Existing configurations
without the optional field use the same adjacent path. Create a new key privately
and publish it without replacing an existing winner, with file and directory sync.
All replicas must use the same key to exchange cursors. Rotation intentionally
invalidates old cursors; restart the list. The key is separate from TLS and tenant
credentials and is never returned through an API, report or client template.

Each page is a live repeatable-read observation, not a multi-page snapshot.
Concurrent insertions before a cursor require restarting at the first page.
Removals, grant changes and current policy may alter later or reverse pages.
Stable-source forward/reverse traversal, changes, empty OCI pages, cross-scope
rejection, key persistence, race and real-browser navigation require evidence.
Native protocol indexes retain their own format contracts and budgets; management
pagination is not a claim that every native index/lifecycle campaign is complete.
