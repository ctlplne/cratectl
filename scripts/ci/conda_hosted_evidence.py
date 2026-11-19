# SPDX-License-Identifier: BUSL-1.1
"""Closed native Linux evidence for the stock Conda hosted archive profile."""

import hashlib

from conda_hosted_fixture import PINS, VERSION, fixtures
if __package__:
    from .terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version
else:
    from terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version

PROFILE = 'cratectl-native-conda-hosted-tar-bz2-v1'
BASE_CHECKS = tuple(item for item in MANIFEST_CHECKS if item != 'provider matches the clean candidate')
CHECKS = (
    'the native stock micromamba version and release digest match',
    'platform metadata requires the current repository and tenant grants',
    'five exact platform and noarch coordinates publish original SHA-256 identities',
    'unreviewed archives stay out of both indexes and cannot be downloaded',
    'the archive platform and immutable bytes must match the coordinate',
    'approved repodata binds each isolated platform, build, constraint and archive digest',
    'the isolated reader receives exact approved archive bytes under trusted TLS',
    'stock micromamba downloads the native graph and selects the newest compatible noarch build',
    'fresh stock micromamba links the two exact inert archives after restart',
    'current digest denial removes both compatible noarch builds and their bytes',
    'fresh stock micromamba refuses the graph after compatible build denial',
)
FILES = (
    '.github/workflows/conda-hosted.yml', 'Makefile', 'go.mod', 'go.sum',
    'scripts/ci/conda_hosted_evidence.py', 'scripts/ci/terraform_provider_evidence.py',
    'scripts/conda_hosted_fixture.py', 'scripts/conformance_repository_manifest.py', 'scripts/bounded_client.py',
    'scripts/qualification_contract.py', 'internal/conda/package.go', 'internal/conda/package_test.go',
    'internal/server/conda.go', 'internal/server/conda_integration_test.go', 'internal/server/server.go',
    'internal/store/conda.go', 'internal/store/artifact_read.go', 'internal/store/lifecycle_artifact.go',
    'internal/store/repository.go', 'internal/store/migrations.go', 'internal/blob/local.go',
)
FIELDS = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id', 'source_dirty', 'source_sha256',
          'binary_sha256', 'archive_sha256', 'postgres', 'npm', 'checks', 'conda_hosted', 'goal_complete', 'broad_readiness'}
SUBDIR = {'X64': 'linux-64', 'ARM64': 'linux-aarch64'}


def validate(report):
    if (type(report) is not dict or set(report) != FIELDS or report['profile'] != PROFILE
            or type(report['schema']) is not int or report['schema'] != 1 or report['status'] != 'passed'
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in SUBDIR or report['source_dirty'] is not False
            or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not matches(report['npm'], r'(?:10|11)\.[0-9]{1,3}\.[0-9]{1,3}') or not postgres_version(report['postgres'])
            or not matches(report['archive_sha256'], '[a-f0-9]{64}') or not hashes(report['source_sha256'], FILES)
            or not hashes(report['binary_sha256'], ('cratectl', 'cratectld')) or report['checks'] != list(BASE_CHECKS)):
        raise ValueError('invalid hosted Conda identity or native check scope')
    native = SUBDIR[report['runner_arch']]
    packages = fixtures(native)
    expected = {package.path: hashlib.sha256(package.archive()).hexdigest() for package in packages}
    selected = {package.path: expected[package.path] for package in packages[:2]}
    if report['conda_hosted'] != {'client_version': VERSION, 'client_sha256': PINS[native], 'subdir': native,
                                  'checks': list(CHECKS), 'archive_sha256': expected, 'selected': selected}:
        raise ValueError('invalid stock micromamba tool or exact dependency graph')
    return report
