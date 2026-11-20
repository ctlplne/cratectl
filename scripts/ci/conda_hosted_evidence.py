# SPDX-License-Identifier: BUSL-1.1
"""Closed native Linux evidence for the stock Conda hosted archive profile."""

import hashlib

from conda_hosted_fixture import PINS, VERSION, fixtures
from conda_group_fixture import group_packages
if __package__:
    from .terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version
else:
    from terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version

PROFILE = 'cratectl-native-conda-hosted-tar-bz2-v1'
GROUP_PROFILE = 'cratectl-native-conda-hosted-and-ordered-group-tar-bz2-v1'
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
GROUP_CHECKS = (
    'the Conda group requires grants on the endpoint and all owning channels',
    'unreviewed retained Conda builds stay out of both current group indexes',
    'when the preferred source lacks the name the lower source supplies its native and foreign builds',
    'an unreviewed preferred owner fences the earlier view and all lower platforms for its name',
    'the approved graph uses two pinned platform snapshots and retains only the current owner builds',
    'stock micromamba fetches the exact Conda group dependency graph through the advertised snapshot URLs',
    'fresh stock micromamba links the original inert Conda group archives after restart',
    'current denial removes the native app and refuses the prior exact snapshot URL without fallback',
    'fresh stock micromamba refuses the Conda group graph after the owning digest is denied',
    'revoking an underlying grant stops Conda group metadata and the previously advertised noarch download',
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
GROUP_FILES = (*FILES, 'scripts/conda_group_fixture.py', 'internal/server/conda_group_integration_test.go',
               'internal/server/resolve.go', 'internal/store/conda_group.go', 'internal/store/source_configuration.go')
FIELDS = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id', 'source_dirty', 'source_sha256',
          'binary_sha256', 'archive_sha256', 'postgres', 'npm', 'checks', 'conda_hosted', 'goal_complete', 'broad_readiness'}
SUBDIR = {'X64': 'linux-64', 'ARM64': 'linux-aarch64'}


def group_selected(source):
    return b'--conda-group' in source('.github/workflows/conda-hosted.yml').split()


def validate(report):
    if type(report) is not dict or set(report) != FIELDS or report['profile'] not in (PROFILE, GROUP_PROFILE):
        raise ValueError('invalid hosted Conda report or profile')
    grouped = report['profile'] == GROUP_PROFILE
    files = GROUP_FILES if grouped else FILES
    if (type(report['schema']) is not int or report['schema'] != 1 or report['status'] != 'passed'
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in SUBDIR or report['source_dirty'] is not False
            or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not matches(report['npm'], r'(?:10|11)\.[0-9]{1,3}\.[0-9]{1,3}') or not postgres_version(report['postgres'])
            or not matches(report['archive_sha256'], '[a-f0-9]{64}') or not hashes(report['source_sha256'], files)
            or not hashes(report['binary_sha256'], ('cratectl', 'cratectld')) or report['checks'] != list(BASE_CHECKS)):
        raise ValueError('invalid hosted Conda identity or native check scope')
    native = SUBDIR[report['runner_arch']]
    packages = fixtures(native)
    expected = {package.path: hashlib.sha256(package.archive()).hexdigest() for package in packages}
    selected = {package.path: expected[package.path] for package in packages[:2]}
    native_report = {'client_version': VERSION, 'client_sha256': PINS[native], 'subdir': native,
                     'checks': list(CHECKS), 'archive_sha256': expected, 'selected': selected}
    if grouped:
        app, dependency, collision, lower_only, foreign = group_packages(native)
        digest = lambda package: hashlib.sha256(package.archive()).hexdigest()
        native_report['group'] = {'checks': list(GROUP_CHECKS), 'selected': {p.path: digest(p) for p in (app, dependency)},
                                  'lower_collision_sha256': digest(collision), 'lower_only_sha256': digest(lower_only),
                                  'foreign_sha256': digest(foreign)}
    if report['conda_hosted'] != native_report:
        raise ValueError('invalid stock micromamba tool or exact dependency graph')
    return report
