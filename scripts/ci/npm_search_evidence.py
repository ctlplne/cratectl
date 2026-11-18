# SPDX-License-Identifier: BUSL-1.1
"""Closed evidence for stock npm hosted and cached search on native Linux."""
if __package__:
    from .terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version
else:
    from terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version


BASE_CHECKS = tuple(check for check in MANIFEST_CHECKS if check != 'provider matches the clean candidate')
HOSTED_CHECKS = (
    'unassessed versions are absent from stock npm search',
    'stock npm returns approved scoped and unscoped names while hiding the pending latest version',
    'the npm search limit returns only the highest ranked package',
    'the second tenant sees its own description at the same coordinate',
    'approving the latest version replaces the search projection',
    'stock npm searches the current latest tag even when it points at an earlier allowed version',
    'retirement removes the tagged version from stock search',
    'stock npm sees the restored tag and exact original archive after restart',
    'an existing stock npm client loses search access after grant revocation',
)
CACHED_CHECKS = (
    'stock npm cached search makes no network fill and fences an unknown preferred source',
    'stock search omits a catalog-only proxy version and its lower duplicate',
    'stock proxy search uses the exact fetched archive description',
    'mixed group review fences the lower duplicate while the preferred bytes await approval',
    'stock group search selects the approved preferred proxy bytes',
    'current proxy absence admits the hosted package in stock group search',
    'stock search replays the same source after restart without upstream requests',
    'invalidating the preferred catalog hides the cached result and its lower duplicate',
    'revoking a selected member grant hides the cached and lower group results',
)
SOURCE_PATHS = (
    '.github/workflows/npm-search.yml', 'Makefile', 'go.mod', 'go.sum',
    'scripts/conformance_repository_manifest.py', 'scripts/npm_search_fixture.py',
    'scripts/ci/npm_search_evidence.py', 'scripts/cargo_proxy_fixture.py',
    'scripts/ci/terraform_provider_evidence.py', 'scripts/qualification_contract.py', 'scripts/bounded_client.py',
    'internal/server/server.go', 'internal/server/npm.go', 'internal/server/npm_search.go',
    'internal/server/npm_remote.go', 'internal/server/npm_proxy.go', 'internal/store/npm.go',
    'internal/store/npm_search.go', 'internal/store/npm_proxy.go', 'internal/store/native_source.go',
    'internal/store/retrieval.go', 'internal/store/artifact_read.go', 'internal/store/repository.go',
    'internal/store/decision.go', 'internal/store/lifecycle_artifact.go', 'internal/store/migrations.go',
)
FIELDS = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id', 'source_dirty', 'source_sha256',
          'binary_sha256', 'archive_sha256', 'postgres', 'npm', 'checks', 'npm_search', 'npm_cached_search',
          'goal_complete', 'broad_readiness'}
DIGEST = '[a-f0-9]{64}'


def validate(report):
    if (type(report) is not dict or set(report) != FIELDS or type(report['schema']) is not int or report['schema'] != 1
            or report['profile'] != 'cratectl-native-npm-search-v1' or report['status'] != 'passed'
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in ('X64', 'ARM64')
            or report['source_dirty'] is not False or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not matches(report['npm'], r'(?:10|11)\.[0-9]{1,3}\.[0-9]{1,3}') or not postgres_version(report['postgres'])
            or not matches(report['archive_sha256'], DIGEST) or not hashes(report['binary_sha256'], ('cratectl', 'cratectld'))
            or not hashes(report['source_sha256'], SOURCE_PATHS) or report['checks'] != list(BASE_CHECKS)):
        raise ValueError('invalid native npm search report identity or base coverage')
    hosted, cached = report['npm_search'], report['npm_cached_search']
    if (type(hosted) is not dict or set(hosted) != {'checks', 'archive_sha256'} or hosted['checks'] != list(HOSTED_CHECKS)
            or type(cached) is not dict or set(cached) != {'checks', 'preferred_archive_sha256'}
            or cached['checks'] != list(CACHED_CHECKS) or not matches(cached['preferred_archive_sha256'], DIGEST)):
        raise ValueError('invalid native npm search checks or cached archive identity')
    archives = hosted['archive_sha256']
    if (type(archives) is not list or len(archives) != 4 or not all(matches(item, DIGEST) for item in archives)
            or len(set(archives)) != 4 or cached['preferred_archive_sha256'] in archives):
        raise ValueError('invalid hosted npm archive identities')
    return report
