# SPDX-License-Identifier: BUSL-1.1
"""Closed source-bound native Linux APT signed repository qualification."""
if __package__:
    from .terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, matches, hashes, postgres_version
else:
    from terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, matches, hashes, postgres_version


BASE_CHECKS = tuple(item for item in MANIFEST_CHECKS if item != 'provider matches the clean candidate')
APT_CHECKS = (
    'stock APT, dpkg and GnuPG are available',
    'stock APT has an observed native platform and apt-secure tools',
    'APT metadata requires the scoped repository grant',
    'stock dpkg emits an exact accepted Debian archive cratectl-apt-app',
    'stock dpkg emits an exact accepted Debian archive cratectl-apt-library',
    'unreviewed Debian archives and dependency metadata remain private',
    'the signed-input package index retains the exact dependency and archive bindings',
    'external GnuPG signed the exact published Release input',
    'repository review applies to the retained InRelease digest',
    'the original InRelease and by-hash indexes serve exact bytes',
    'stock APT verifies and indexes the signed repository first-consumer',
    'stock APT resolves and downloads the exact application and dependency first-consumer',
    'stock APT refuses untrusted-signature',
    'stock APT verifies and indexes the signed repository after-restart',
    'stock APT resolves and downloads the exact application and dependency after-restart',
    'current policy fences stale signed metadata and the denied package',
    'stock APT refuses retired-index',
)
PROFILE = 'cratectl-native-debian-apt-signed-v1'
SUITE_PROFILE = 'cratectl-native-debian-apt-signed-suites-v1'
APT_SUITE_CHECKS = (
    *APT_CHECKS[:5], 'stock dpkg emits an exact accepted Debian archive cratectl-apt-app-foreign',
    *APT_CHECKS[5:7], 'the named suite isolates native archives and exposes the common dependency in both indexes',
    *APT_CHECKS[7:],
)
DIGEST = '[a-f0-9]{64}'
SOURCE_PATHS = (
    '.github/workflows/debian-apt.yml', 'Makefile', 'go.mod', 'go.sum',
    'scripts/ci/debian_apt_evidence.py', 'scripts/ci/terraform_provider_evidence.py',
    'scripts/debian_apt_fixture.py', 'scripts/conformance_repository_manifest.py', 'scripts/bounded_client.py',
    'scripts/qualification_contract.py', 'internal/debian/archive.go', 'internal/debian/control.go', 'internal/debian/release.go',
    'internal/server/debian.go', 'internal/server/debian_release.go', 'internal/server/debian_integration_test.go',
    'internal/server/server.go', 'internal/store/debian.go', 'internal/store/debian_release.go', 'internal/store/artifact_read.go',
    'internal/store/repository.go', 'internal/store/migrations.go', 'internal/store/lifecycle_artifact.go',
)
SUITE_SOURCE_PATHS = (*SOURCE_PATHS, 'internal/debian/distribution.go')
FIELDS = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id', 'source_dirty', 'source_sha256',
          'binary_sha256', 'archive_sha256', 'postgres', 'npm', 'checks', 'debian_apt', 'goal_complete', 'broad_readiness'}


def suite_selected(source):
    return b'--debian-apt-suite' in source('.github/workflows/debian-apt.yml').split()


def validate_run(apt, arch, *, named=False):
    archives = ('cratectl-apt-app', 'cratectl-apt-library')
    indexes = ('Packages', 'Packages.gz')
    checks = APT_CHECKS
    if named:
        archives = (*archives, 'cratectl-apt-app-foreign')
        indexes = tuple(f'main/binary-{architecture}/{name}' for architecture in ('amd64', 'arm64') for name in indexes)
        checks = APT_SUITE_CHECKS
    if (type(apt) is not dict or set(apt) != {'checks', 'apt', 'architecture', 'gpg', 'archive_sha256', 'release_sha256', 'index_sha256'}
            or apt['checks'] != list(checks) or apt['architecture'] != arch
            or not matches(apt['apt'], rf'apt 2\.[0-9.]{{2,16}} \({arch}\)') or not matches(apt['gpg'], r'gpg \(GnuPG\) 2\.[0-9.]{2,16}')
            or not hashes(apt['archive_sha256'], archives)
            or not hashes(apt['index_sha256'], indexes) or not matches(apt['release_sha256'], DIGEST)):
        raise ValueError('invalid Debian APT, release or archive scope')


def validate(report):
    if type(report) is not dict or report.get('profile') not in (PROFILE, SUITE_PROFILE):
        raise ValueError('invalid hosted Debian profile')
    named = report['profile'] == SUITE_PROFILE
    fields = FIELDS | {'debian_apt_suite'} if named else FIELDS
    source_paths = SUITE_SOURCE_PATHS if named else SOURCE_PATHS
    if (set(report) != fields or type(report['schema']) is not int or report['schema'] != 1
            or report['status'] != 'passed' or report['runner_os'] != 'Linux'
            or report['runner_arch'] not in ('X64', 'ARM64') or report['source_dirty'] is not False
            or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not matches(report['npm'], r'(?:10|11)\.[0-9]{1,3}\.[0-9]{1,3}') or not postgres_version(report['postgres'])
            or not matches(report['archive_sha256'], DIGEST) or not hashes(report['source_sha256'], source_paths)
            or not hashes(report['binary_sha256'], ('cratectl', 'cratectld')) or report['checks'] != list(BASE_CHECKS)):
        raise ValueError('invalid hosted Debian identity or base coverage')
    arch = {'X64': 'amd64', 'ARM64': 'arm64'}[report['runner_arch']]
    validate_run(report['debian_apt'], arch)
    if named:
        validate_run(report['debian_apt_suite'], arch, named=True)
    return report
