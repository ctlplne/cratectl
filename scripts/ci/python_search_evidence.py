# SPDX-License-Identifier: BUSL-1.1
"""Closed pip and Twine evidence for hosted and cached Python search."""
if __package__:
    from .terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version
else:
    from terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version


BASE_CHECKS = tuple(check for check in MANIFEST_CHECKS if check != 'provider matches the clean candidate')
HOSTED_CHECKS = (
    'stock pip search hides hosted files awaiting review',
    'stock pip normalizes the package name and returns the allowed original summary',
    'stock pip finds a package by its archive-derived summary',
    'the independently authorized tenant sees its own package at the same coordinate',
    'stock pip search uses PEP 440 ordering for visible releases',
    'stock pip search only returns a release with a non-yanked visible file',
    'stock pip search and exact wheel download recover after restart',
    'stock pip search respects revocation of its repository read grant',
)
CACHED_CHECKS = (
    'cold Python search makes no upstream request and hides an unknown preferred source',
    'Python search omits an index-only source and its lower filename collision',
    'stock pip search recognizes the exact cached wheel and its embedded summary',
    'mixed group review hides the pending preferred wheel and its lower collision',
    'stock group search selects the approved cached wheel',
    'a current proxy absence permits stock discovery of a different hosted project',
    'current upstream yanks hide a preferred cached wheel without selecting its lower collision',
    'restored catalog discovery survives restart without contacting the origin during search',
    'expired catalog authority fences both cached and lower search results',
    'stock Python group search honors selected member grant changes',
)
SOURCE_PATHS = (
    '.github/workflows/python-search.yml', 'Makefile', 'go.mod', 'go.sum',
    'scripts/conformance_repository_manifest.py', 'scripts/python_search_fixture.py',
    'scripts/ci/python_search_evidence.py', 'scripts/cargo_proxy_fixture.py',
    'scripts/ci/terraform_provider_evidence.py', 'scripts/qualification_contract.py', 'scripts/bounded_client.py',
    'internal/server/server.go', 'internal/server/pypi.go', 'internal/server/python_search.go',
    'internal/server/python_read.go', 'internal/server/python_index.go', 'internal/server/python_archive.go',
    'internal/server/python_proxy.go', 'internal/store/python.go', 'internal/store/python_search.go',
    'internal/store/literal_search.go', 'internal/store/native_source.go', 'internal/store/retrieval.go',
    'internal/store/artifact_read.go', 'internal/store/repository.go', 'internal/store/decision.go',
    'internal/store/lifecycle_artifact.go', 'internal/store/migrations.go',
)
FIELDS = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id', 'source_dirty', 'source_sha256',
          'binary_sha256', 'archive_sha256', 'postgres', 'npm', 'checks', 'python_search', 'python_cached_search',
          'goal_complete', 'broad_readiness'}
DIGEST = '[a-f0-9]{64}'


def validate(report):
    if (type(report) is not dict or set(report) != FIELDS or type(report['schema']) is not int or report['schema'] != 1
            or report['profile'] != 'cratectl-native-python-search-v1' or report['status'] != 'passed'
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in ('X64', 'ARM64')
            or report['source_dirty'] is not False or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not matches(report['npm'], r'(?:10|11)\.[0-9]{1,3}\.[0-9]{1,3}') or not postgres_version(report['postgres'])
            or not matches(report['archive_sha256'], DIGEST) or not hashes(report['binary_sha256'], ('cratectl', 'cratectld'))
            or not hashes(report['source_sha256'], SOURCE_PATHS) or report['checks'] != list(BASE_CHECKS)):
        raise ValueError('invalid native Python search report identity or base coverage')
    hosted, cached = report['python_search'], report['python_cached_search']
    if (type(hosted) is not dict or set(hosted) != {'checks', 'archive_sha256', 'pip', 'twine'}
            or hosted['checks'] != list(HOSTED_CHECKS) or hosted['pip'] != '26.1.2' or hosted['twine'] != '7.0.0'
            or type(cached) is not dict or set(cached) != {'checks', 'preferred_archive_sha256'}
            or cached['checks'] != list(CACHED_CHECKS) or not matches(cached['preferred_archive_sha256'], DIGEST)):
        raise ValueError('invalid native Python search checks, tools, or archive identity')
    archives = hosted['archive_sha256']
    if (type(archives) is not list or len(archives) != 3 or not all(matches(item, DIGEST) for item in archives)
            or len(set(archives)) != 3 or cached['preferred_archive_sha256'] in archives):
        raise ValueError('invalid hosted Python archive identities')
    return report
