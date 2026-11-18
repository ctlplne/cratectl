#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Closed first-attempt evidence for native stock Cargo against PostgreSQL."""
import re

if __package__:
    from .bootstrap_cargo import PINS
    from .terraform_provider_evidence import BASE_CHECKS, postgres_version
else:
    from bootstrap_cargo import PINS
    from terraform_provider_evidence import BASE_CHECKS, postgres_version

CHECKS = (
    'stock Cargo and rustc 1.100.0',
    'registry discovery requires a tenant token and current repository grant',
    'sparse config binds required auth, API and downloads to the same trusted authority',
    'two stock publications retain exact unassessed bytes',
    'sparse index binds immutable checksum and same-registry renamed dependency',
    'concurrent publication retries preserve a single journal effect and require current write authority',
    'conflicting bytes, build metadata and hyphen-underscore aliases preserve retained coordinates',
    'first publication assigns one stable tenant-local owner identity across crates',
    'repository write grant alone cannot publish, yank, or list owners for an owned crate',
    'stock Cargo adds and lists an independently granted co-owner',
    'owner membership cannot override a current repository write revocation',
    'stock owner removal revokes crate mutations and the last owner remains protected',
    'short publication frame leaves no retained reference or journal effect',
    'complete retry binds exactly the original frame bytes to an unassessed reference',
    'unassessed index entries are hidden and direct byte delivery is denied',
    'fresh stock Cargo cannot resolve an unassessed crate',
    'the same tenant owner identity survives registry restart',
    'fresh stock Cargo resolves the transitive graph and downloads exact approved bytes after restart',
    'reader and active hold block yank without changing the index',
    'stock Cargo yank changes only discovery and repeated yank leaves the journal unchanged',
    'stock Cargo rejects a yanked version during fresh resolution',
    'stock Cargo lockfile still fetches both exact approved archives while yanked',
    'stock Cargo unyank restores fresh resolution after restart with the original index entry',
    'common deletion removes discovery and blocks even exact pinned byte access',
    'common restoration restores the original index and exact approved archive',
    'Cargo search requires current tenant and repository access',
    'stock Cargo search excludes a newer unassessed version and prints the approved description',
    'stock Cargo search selects the newer approved authentic release',
    'stock Cargo search falls back to the preceding release while the latest is yanked',
    'protected download still honors both grant revocation and tenant binding',
    'revoked grant refuses current index and direct download even with a populated client cache',
    'revoked writer cannot replay publication or change yank state',
)
SOURCE_PATHS = (
    '.github/workflows/cargo.yml', 'go.mod', 'go.sum', 'Makefile',
    'internal/cargo/coordinates.go', 'internal/cargo/index.go', 'internal/cargo/publish.go',
    'internal/server/cargo.go', 'internal/server/nuget.go', 'internal/server/server.go',
    'internal/store/cargo.go', 'internal/store/cargo_search.go', 'internal/store/store.go', 'internal/store/repository.go',
    'internal/store/artifact_read.go', 'internal/blob/local.go', 'internal/crypto/crypto.go',
    'internal/store/lifecycle_artifact.go', 'internal/store/lifecycle.go', 'internal/server/lifecycle.go',
    'internal/store/cargo_owners.go', 'internal/store/cargo_ownership_schema.go', 'internal/store/migrations.go',
    'scripts/cargo_hosted_fixture.py', 'scripts/conformance_repository_manifest.py',
    'scripts/ci/cargo_evidence.py', 'scripts/ci/bootstrap_cargo.py', 'scripts/ci/fetch_archive.py',
    'scripts/ci/terraform_provider_evidence.py', 'scripts/qualification_contract.py', 'scripts/bounded_client.py',
)


def validate(report):
    fields = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id',
              'source_dirty', 'source_sha256', 'binary_sha256', 'sdk_archives_sha256', 'cargo', 'cargo_sha256',
              'rustc_sha256', 'checks', 'base_checks', 'archive_sha256', 'postgres', 'goal_complete', 'broad_readiness'}
    if type(report) is not dict or set(report) != fields or type(report['schema']) is not int or report['schema'] != 1:
        raise ValueError('invalid stock Cargo evidence inventory')
    if (report['profile'] != 'cratectl-native-cargo-v1' or report['status'] != 'passed'
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in ('X64', 'ARM64')
            or report['source_dirty'] is not False or report['goal_complete'] is not False
            or report['broad_readiness'] is not False or report['checks'] != list(CHECKS)
            or report['base_checks'] != [v for v in BASE_CHECKS if v != 'provider matches the clean candidate']
            or not postgres_version(report['postgres'])):
        raise ValueError('invalid stock Cargo coverage')

    def matches(value, pattern):
        return isinstance(value, str) and re.fullmatch(pattern, value) is not None

    if (not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not matches(report['cargo'], r'cargo 1\.100\.0 \([a-f0-9]{7,40} 2026-11-05\)')
            or any(not matches(report[k], '[a-f0-9]{64}') for k in ('cargo_sha256', 'rustc_sha256'))):
        raise ValueError('invalid stock Cargo identity')
    arch = {'X64': 'amd64', 'ARM64': 'arm64'}[report['runner_arch']]
    if report['sdk_archives_sha256'] != PINS[arch]:
        raise ValueError('invalid stock Cargo distribution pins')
    for name, keys in [('source_sha256', SOURCE_PATHS), ('binary_sha256', ('cratectl', 'cratectld')),
                       ('archive_sha256', ('cratectl-cargo-leaf', 'cratectl-cargo-root', 'cratectl-cargo-root-1.10.0'))]:
        binding = report[name]
        if type(binding) is not dict or set(binding) != set(keys) or any(not matches(v, '[a-f0-9]{64}') for v in binding.values()):
            raise ValueError('invalid stock Cargo digest inventory')
    return report
