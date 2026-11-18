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
    'Cargo group config advertises authenticated reads and rejects publication',
    'first unassessed crate fences a lower duplicate for both index and stock resolution',
    'stock Cargo selects the lower source for a name absent from the first member',
    'stock Cargo uses the approved first source for both index and exact archive bytes',
    'group review policy also applies when the selected member allows unassessed bytes',
    'loss of required member access fences the group before fallback',
    'retired preferred crate still fences the lower duplicate',
    'fresh stock Cargo recovers the same preferred archive after restore and restart',
    'an explicit namespace owner routes stock Cargo to the selected lower source',
    'Cargo proxy config publishes only its own authenticated sparse authority',
    'fresh stock Cargo proxies a transitive graph and both original archives',
    'configured index and download credentials remain bound to separate upstream paths',
    'conditional sparse and archive validation preserves the original bytes',
    'mixed group review hides the pending first proxy even with an approved hosted duplicate',
    'fresh stock Cargo recovers both exact cached bytes across restart during upstream outage',
    'current review hides an upstream checksum pending local authorization',
    'local approval restores stock Cargo discovery and exact byte delivery',
    'retired proxy reference blocks discovery and delivery even when a cache fill is requested',
    'proxy reference restoration retains the exact locally approved archive',
    'a download checksum mismatch leaves no materialized package reference',
    'retry stages the original archive after checksum failure and still requires local approval',
    'an upstream coordinate change refuses the entire refreshed index and its download',
    'upstream yank changes discovery while the same exact pinned bytes remain deliverable',
    'zero-freshness validation admits the request that filled both Cargo cache entries',
    'a transient origin failure can serve the exact revision-bound Cargo bytes within its stale window',
    'a source binding conflict refuses stale Cargo bytes even within the configured window',
    'an interrupted origin transfer leaves no materialized Cargo archive',
    'the exact Cargo archive can be retrieved after an interrupted origin transfer',
    'concurrent Cargo cache misses consume one upstream archive transfer',
    'advancing the Cargo source revision clears inherited validators and requires a new exact-digest decision',
    'an unchanged approved dependency must rebind its exact bytes before discovery in the new source revision',
    'fresh stock Cargo resolves the new approved source revision and exact leaf',
    'mixed group stock Cargo receives the preferred proxy graph and exact revised archive',
    'mixed group can use a hosted crate after a request-scoped zero-freshness proxy absence',
    'explicit Cargo namespace selects one proxy without unselected source grants',
    'withdrawn proxy crate fences the approved hosted duplicate in a mixed group',
    'mixed group refuses to substitute another source during a preferred origin outage',
    'current grants and tenant isolation fence a previously filled Cargo proxy',
    'revoked preferred proxy access also fences the mixed group',
)
ARCHIVES = ('cratectl-cargo-leaf', 'cratectl-cargo-root', 'cratectl-cargo-root-1.10.0',
            'group-preferred', 'group-duplicate', 'group-lower-only', 'proxy-root', 'proxy-leaf', 'proxy-revised-root')
SOURCE_PATHS = (
    '.github/workflows/cargo.yml', 'go.mod', 'go.sum', 'Makefile',
    'internal/cargo/coordinates.go', 'internal/cargo/index.go', 'internal/cargo/publish.go',
    'internal/server/cargo.go', 'internal/server/nuget.go', 'internal/server/server.go',
    'internal/store/cargo.go', 'internal/store/cargo_search.go', 'internal/store/store.go', 'internal/store/repository.go',
    'internal/store/artifact_read.go', 'internal/blob/local.go', 'internal/crypto/crypto.go',
    'internal/store/lifecycle_artifact.go', 'internal/store/lifecycle.go', 'internal/server/lifecycle.go',
    'internal/store/cargo_owners.go', 'internal/store/cargo_ownership_schema.go', 'internal/store/migrations.go',
    'internal/store/cargo_selection.go', 'internal/store/native_source.go', 'internal/server/resolve.go',
    'scripts/cargo_hosted_fixture.py', 'scripts/cargo_group_fixture.py', 'scripts/cargo_ownership_upgrade_fixture.py',
    'scripts/conformance_repository_manifest.py',
    'scripts/ci/cargo_evidence.py', 'scripts/ci/bootstrap_cargo.py', 'scripts/ci/fetch_archive.py',
    'scripts/ci/terraform_provider_evidence.py', 'scripts/qualification_contract.py', 'scripts/bounded_client.py',
    'internal/cargo/sparse.go', 'internal/server/cargo_proxy.go', 'internal/store/cargo_proxy.go',
    'internal/store/cargo_retrieval.go', 'internal/store/retrieval.go', 'internal/store/source_configuration.go',
    'internal/upstream/upstream.go', 'internal/server/credentials.go', 'scripts/cargo_proxy_fixture.py',
    'internal/server/cargo_group.go',
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
                       ('archive_sha256', ARCHIVES)]:
        binding = report[name]
        if type(binding) is not dict or set(binding) != set(keys) or any(not matches(v, '[a-f0-9]{64}') for v in binding.values()):
            raise ValueError('invalid stock Cargo digest inventory')
    archives = report['archive_sha256']
    if (archives['proxy-root'] == archives['cratectl-cargo-root']
            or archives['proxy-leaf'] != archives['cratectl-cargo-leaf']
            or archives['proxy-revised-root'] in (archives['proxy-root'], archives['cratectl-cargo-root'])):
        raise ValueError('Cargo proxy evidence must bind the origin-built root and original stock leaf')
    return report
