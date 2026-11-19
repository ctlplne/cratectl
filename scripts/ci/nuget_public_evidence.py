# SPDX-License-Identifier: BUSL-1.1
"""Closed evidence for stock locked restore through the real NuGet.org origin."""
if __package__:
    from .terraform_provider_evidence import hashes, matches, postgres_version
else:
    from terraform_provider_evidence import hashes, matches, postgres_version


CHECKS = (
    'qualification source is clean',
    'qualification binaries embed exact clean source commit',
    'stock dotnet is available for public origin qualification',
    'public origin replay uses the exact pinned dotnet SDK',
    'both direct public package ZIPs match their independent SHA-256 pins and contain no build assets or scripts',
    'stock dotnet restores the pinned public package graph independent-vendor-bytes',
    'the stock lock binds Polly and its actual Polly.Core dependency independent-vendor-bytes',
    'restored archive bytes and stock content hash match Polly independent-vendor-bytes',
    'restored archive bytes and stock content hash match Polly.Core independent-vendor-bytes',
    'admin: create nuget repository cratectl-nuget-public',
    'public origin archive stages behind exact digest review Polly',
    'public origin archive stages behind exact digest review Polly.Core',
    'stock dotnet restores the pinned public package graph public-origin-through-cratectl',
    'the stock lock binds Polly and its actual Polly.Core dependency public-origin-through-cratectl',
    'restored archive bytes and stock content hash match Polly public-origin-through-cratectl',
    'restored archive bytes and stock content hash match Polly.Core public-origin-through-cratectl',
    'stock dotnet restores the pinned public package graph warm-public-origin-restart',
    'the stock lock binds Polly and its actual Polly.Core dependency warm-public-origin-restart',
    'restored archive bytes and stock content hash match Polly warm-public-origin-restart',
    'restored archive bytes and stock content hash match Polly.Core warm-public-origin-restart',
    'the current exact public package decision can be revoked',
    'a fresh locked restore respects public proxy review revocation',
)
ARCHIVES = {
    "Polly": "22b374e9d74e209d1562e55e7dedcbbdf5b4917db4013450904060f420689910",
    "Polly.Core": "3c0c2c5aaac289e09fffb63cedf57b5cc2a8698d9a6c240db48fb8a32c8c89f9"
}
CONTENT = {
    "Polly": "bdb5ec1a0906f3a9c6f933b063e4a6b6b1ab4479871f40d06b1b482f1fff7770f3fe8709f22cd2358cddbd4da012d59afcb0c3f3324bbc3dc7763124765be486",
    "Polly.Core": "d4c24a771bf8cf00e6896bd8bd5376e03b2b5947e043817cdefa07f1b85bb4b31d3ee1b2f027d3533b20421bf2ae5d5aee1acce9fff27702d5755508d31a2853"
}
PROFILE = 'cratectl-native-nuget-public-lock-v1'
DIGEST = '[a-f0-9]{64}'
SOURCE_PATHS = (
    '.github/workflows/nuget-public.yml', 'Makefile', 'go.mod', 'go.sum', 'global.json',
    'scripts/ci/qualify_nuget_proxy.py', 'scripts/ci/nuget_proxy_evidence.py', 'scripts/ci/nuget_public_evidence.py',
    'scripts/ci/terraform_provider_evidence.py',
    'scripts/conformance.py', 'scripts/conformance_nuget_proxy.py', 'scripts/conformance_nuget_public.py',
    'scripts/qualification_contract.py', 'scripts/bounded_client.py', 'internal/server/nuget.go', 'internal/server/nuget_proxy.go',
    'internal/server/nuget_service_index.go', 'internal/server/resolve.go', 'internal/store/decision.go',
    'internal/store/nuget_proxy.go', 'internal/store/retrieval.go', 'internal/store/repository.go',
    'internal/store/migrations.go', 'internal/upstream/upstream.go',
)
FIELDS = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id', 'source_dirty',
          'source_sha256', 'binary_sha256', 'postgres', 'database_safety', 'checks', 'nuget_public',
          'goal_complete', 'broad_readiness'}


def validate_fixture(native):
    if (type(native) is not dict or set(native) != {'sdk', 'dotnet_sha256', 'version', 'lock_sha256',
                                                    'archive_sha256', 'lock_content_sha512'}
            or native['sdk'] != '10.0.403' or native['version'] != '8.5.2'
            or not matches(native['dotnet_sha256'], DIGEST) or not matches(native['lock_sha256'], DIGEST)
            or native['archive_sha256'] != ARCHIVES or native['lock_content_sha512'] != CONTENT):
        raise ValueError('invalid public NuGet archive or stock lockfile evidence')


def validate(report):
    if (type(report) is not dict or set(report) != FIELDS or type(report['schema']) is not int or report['schema'] != 1
            or report['profile'] != PROFILE or report['status'] != 'passed' or report['database_safety'] is not True
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in ('X64', 'ARM64')
            or report['source_dirty'] is not False or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not hashes(report['binary_sha256'], ('cratectl', 'cratectld')) or not hashes(report['source_sha256'], SOURCE_PATHS)
            or not postgres_version(report['postgres']) or report['checks'] != list(CHECKS)):
        raise ValueError('invalid native public NuGet identity or coverage')
    validate_fixture(report['nuget_public'])
    return report
