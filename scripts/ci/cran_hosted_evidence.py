# SPDX-License-Identifier: BUSL-1.1
"""Closed Linux evidence for governed hosted CRAN source discovery and delivery."""

import hashlib

from cran_hosted_fixture import COORDINATES, EARLIER, LATEST, SELECTED_LIBRARY, TOOLS, filename, make_archive
if __package__:
    from .terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version
else:
    from terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version

PROFILE = 'cratectl-native-hosted-cran-source-v1'
INSTALL_PROFILE = 'cratectl-native-hosted-cran-source-install-v1'
PROFILES = {
    (False, False): PROFILE,
    (True, False): INSTALL_PROFILE,
    (False, True): 'cratectl-native-hosted-cran-source-history-v1',
    (True, True): 'cratectl-native-hosted-cran-source-install-and-history-v1',
}
SCOPE = {profile: mode for mode, profile in PROFILES.items()}
BASE_CHECKS = tuple(item for item in MANIFEST_CHECKS if item != 'provider matches the clean candidate')
CHECKS = (
    'the stock R interpreter and its distribution match the exact native tool pin',
    'native CRAN metadata requires the current repository and tenant grants',
    'four exact CRAN coordinates publish their original SHA-256 identities',
    'unreviewed CRAN archives stay out of both indexes and their direct bytes are denied',
    'CRAN rejects mismatched source metadata and changed bytes at an immutable coordinate',
    'plain and gzip CRAN indexes retain all four reviewed DESCRIPTION and byte bindings',
    'stock R selects numeric versions and downloads the exact native source graph',
    'a fresh stock R process retrieves the same exact dependency graph after restart',
    'new CRAN indexes and direct downloads enforce current digest denial',
    'stock R falls back to the approved version and refuses the revoked exact archive',
)
INSTALL_CHECKS = ('stock R installs the verified inert source graph first',
                  'stock R installs the verified inert source graph after-restart')
HISTORY_CHECKS = (
    'the governed directory lists the one reviewed historical source version',
    'stock R follows the historical link and retrieves the exact retained archive',
    'current review removes the old link and fences the exact archive URL',
    'fresh stock R refuses the historical download after the digest is denied',
    'stock R retrieves the unchanged historical bytes after reapproval',
)
LAUNCHER = 'scripts/ci/cran_private_launcher.sh'
FILES = (
    '.github/workflows/cran-hosted.yml', 'Makefile', 'go.mod', 'go.sum',
    'scripts/ci/cran_hosted_evidence.py', 'scripts/ci/terraform_provider_evidence.py',
    'scripts/cran_hosted_fixture.py', 'scripts/conformance_repository_manifest.py', 'scripts/bounded_client.py',
    'scripts/qualification_contract.py', 'internal/cran/package.go', 'internal/cran/package_test.go',
    'internal/server/cran.go', 'internal/server/cran_integration_test.go', 'internal/server/server.go',
    'internal/store/cran.go', 'internal/store/artifact_read.go', 'internal/store/lifecycle_artifact.go',
    'internal/store/repository.go', 'internal/store/migrations.go', 'internal/blob/local.go',
)
INSTALL_FILES = (*FILES, LAUNCHER)
VERSION_FILES = ('internal/cran/version.go', 'internal/cran/version_test.go')
FIELDS = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id', 'source_dirty', 'source_sha256',
          'binary_sha256', 'archive_sha256', 'postgres', 'npm', 'checks', 'cran_hosted', 'goal_complete', 'broad_readiness'}
HOST = {'X64': 'x86_64', 'ARM64': 'aarch64'}


def selected_scopes(source):
    flags = source('.github/workflows/cran-hosted.yml').split()
    return b'--cran-install' in flags, b'--cran-history' in flags


def source_files(installed, history):
    baseline = INSTALL_FILES if installed else FILES
    return baseline + VERSION_FILES if history else baseline


def validate(report):
    if type(report) is not dict or report.get('profile') not in SCOPE:
        raise ValueError('invalid hosted CRAN profile')
    installed, history = SCOPE[report['profile']]
    files = source_files(installed, history)
    if (set(report) != FIELDS
            or type(report['schema']) is not int or report['schema'] != 1 or report['status'] != 'passed'
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in HOST or report['source_dirty'] is not False
            or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not matches(report['npm'], r'(?:10|11)\.[0-9]{1,3}\.[0-9]{1,3}') or not postgres_version(report['postgres'])
            or not matches(report['archive_sha256'], '[a-f0-9]{64}') or not hashes(report['source_sha256'], files)
            or not hashes(report['binary_sha256'], ('cratectl', 'cratectld')) or report['checks'] != list(BASE_CHECKS)):
        raise ValueError('invalid hosted CRAN identity or native check scope')
    version, digest = TOOLS['Linux', HOST[report['runner_arch']]]
    archives = {filename(c): hashlib.sha256(make_archive(c)).hexdigest() for c in COORDINATES}
    selected = {filename(c): archives[filename(c)] for c in (LATEST, SELECTED_LIBRARY)}
    native = report['cran_hosted']
    if type(native) is not dict or not matches(native.get('binary_sha256'), '[a-f0-9]{64}'):
        raise ValueError('invalid stock R binary digest')
    expected = {'version': version, 'distribution_sha256': digest, 'binary_sha256': native['binary_sha256'],
                'checks': list(CHECKS), 'archive_sha256': archives, 'selected': selected}
    if installed:
        expected['installation'] = {'checks': list(INSTALL_CHECKS), 'launcher_sha256': report['source_sha256'][LAUNCHER]}
    if history:
        name = filename(EARLIER)
        expected['history'] = {'checks': list(HISTORY_CHECKS), 'file': name, 'sha256': archives[name]}
    if native != expected:
        raise ValueError('invalid stock R tool or exact CRAN source graph')
    return report
