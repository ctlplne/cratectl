# Inspect a checksum authority incident

This inspection surface is available for retained, privately configured Go proxy
records. Public Go proxy creation and protocol routing remain gated. It does not
establish complete Go proxy support or release readiness.

A checksum authority signs a log of module hashes. An authenticated fork means
the same configured key signed conflicting history. cratectl retains the original
bounded observations and its separately retained signed checkpoints, and blocks
that exact key throughout the tenant. Retrying, changing the source or restoring
the repository cannot reset that block. Selecting an externally trusted new key
is an explicit trust decision; cratectl does not issue keys or signing identities.

An **unverified observation** means the retained data did not authenticate a fork.
It can be an unavailable authority, malformed response, missing proof or an
explicit storage-policy/known-credential omission. It is neither a clean verdict
nor package approval. A false `blocked` state is not a recent authority contact
or health check. Ordinary package review, lifecycle and current proof policy
still apply to serving.

In the console, open **Checksum inspection** on a retained Go proxy repository.
Readers with repository access can inspect the safe checkpoint/key state. Current
tenant administrators can page failure summaries and obtain private export
commands. The view does not automatically download raw bodies or mutate trust.
It refuses commands and pagination when an identifier exceeds JavaScript's exact
integer range; use the CLI/API for exact 64-bit values. Refresh observations after
source changes. A stale source revision must not select different trust silently.

Read current state with the repository's exact observed source revision:

```sh
cratectl --config "$CRATECTL_CLIENT_CONFIG" \
  --path '/api/v1/repositories/REPOSITORY/go/checksum?source_revision=0'
```

Tenant administrators can list original failure identities. Follow `next_after`
only while `more` is true. Each page contains at most 100 summaries; bodies and
signed pins are excluded. This is live traversal, not a snapshot or scale verdict.

```sh
cratectl --config "$CRATECTL_CLIENT_CONFIG" \
  --path '/api/v1/repositories/REPOSITORY/go/checksum/failures?after=0&limit=25'
```

Select the exact `root_path`, historical `source_revision` and `generation` from
one summary. URL-encode the root path. The attachment contains the original
canonical record and may include sensitive source data. Save it privately and
use `--raw-response` to preserve its hashed bytes. The ordinary CLI adds a newline
to management responses for terminal readability; that changes canonical evidence.

```sh
umask 077
cratectl --config "$CRATECTL_CLIENT_CONFIG" --raw-response \
  --path '/api/v1/repositories/REPOSITORY/go/checksum/failures/evidence?root_path=ENCODED_ZIP_ROOT&source_revision=0&generation=2' \
  > go-checksum-failure.json

cratectl go-checksum-verify \
  --evidence-file ./go-checksum-failure.json \
  --key-file "$CRATECTL_CHECKSUM_PUBLIC_KEY" \
  --expected-sha256 "$CRATECTL_TRUSTED_EVIDENCE_SHA256"
```

Supply the public verifier key through an independently trusted channel. Supply
the expected evidence SHA-256 from a trusted audit journal or export manifest;
the download's header and adjacent summary alone do not independently authenticate
its cratectl tenant/repository attribution. The authority's signatures prove log
misbehavior; they do not sign cratectl's attribution fields. Journal chain/export
anchor validation and a complete signed export workflow remain separate work.

The verifier performs no network or database access. It requires an owner-private
regular evidence file of at most 2 MiB and separately supplied public key. It
checks exact SHA-256, canonical encoding, original bounded observations and both
retained signed pins. A proved fork produces a bounded JSON result and exit zero.
A valid but unverified observation produces its classification and a nonzero exit
status. Invalid bytes/trust produce no partial record. Output excludes original
bodies, module/repository attribution and configured key text. Neither result
approves packages or changes any server state.

Inspection of retained evidence remains authorized after repository suspension or
removal. Current administrator credentials and repository authorization are still
checked on every read; suspension does not turn evidence inspection into serving.

Prototype source-12 failure labels lack original proof observations and may lack
historical key attribution. They remain unresolved legacy incidents. Neither an
empty new history page nor an upgrade manufactures proof, clears such an incident
or establishes safe recovery. Legacy incident discovery, conservative quarantine
and a separately reviewed recovery path remain required before public Go proxy
mode is enabled.
