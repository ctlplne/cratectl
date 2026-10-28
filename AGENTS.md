# cratectl engineering contract

Read `GOAL.md`, `STATUS.md`, and `docs/qualification/remaining.json` before work.
The entire goal remains committed scope. Only the owner can remove it.

- Before every commit, verify both author and committer are `imfeelingtheagi <288773099+imfeelingtheagi@users.noreply.github.com>`. Repository hooks enforce this identity.
- Work and commit on `main`; no push, publication, remote changes, or customer changes without explicit authority.
- Use project-owned resources, named `cratectl-*`, on loopback ports 38443 and 35432. Never modify sibling workspaces or their services. Read-only design/licensing references are permitted.
- Preserve `.private/` (0700) and `.cache/` as ignored local state. Never commit credential values. Retain evidence under `evidence/` with candidate identity and limits.
- Core has no entitlement check, telemetry dependency, or `ee/` import. Crypto primitives belong only in `internal/crypto`.
- All durable tenant data has forced PostgreSQL RLS. Runtime connections must be nonsuperuser, nonowner, without BYPASSRLS. Protocol adapters use the common store, authorization and policy path.
- Stage and sync immutable bytes before committing references. Journal, mutation idempotency and job intent share one database transaction. Missing scan evidence never means clean.
- Bound input, transfer concurrency, parser memory and SQL result sizes. Never execute package scripts or deserialize models.
- Add meaningful regression tests beside implementation. Real PostgreSQL and stock clients are required for integration claims. Skips never count as passes.
- Update capability/journey evidence precisely. `implemented but unverified` is distinct from `verified`. Broad release readiness remains false until all required gates run.
- Standard commands: `make build`, `make test`, `make race`, `make lint`, `make integration`, `make conformance`, `make security`, `make packaging`. Unimplemented gates must fail with an explanation.
- Resume from durable records after interruption. No autonomous delegation unless the owner explicitly asks for it.
