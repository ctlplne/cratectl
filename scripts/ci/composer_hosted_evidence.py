# SPDX-License-Identifier: BUSL-1.1
"""Closed source-bound evidence for the native Composer hosted ZIP profile."""
if __package__:
    from .terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version
else:
    from terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version
from composer_hosted_fixture import COMPOSER_SHA256, COMPOSER_VERSION, COORDINATES

PROFILE = 'cratectl-native-composer-hosted-zip-v1'
GROUP_PROFILE = 'cratectl-native-composer-hosted-and-group-zip-v1'
BASE_CHECKS = tuple(item for item in MANIFEST_CHECKS if item != 'provider matches the clean candidate')
CHECKS = (
    'the stock Composer PHAR matches the pinned publisher digest',
    'the native PHP runtime executes the pinned Composer version',
    'repository metadata requires the current scoped grant',
    'the four owned stable ZIP coordinates publish unchanged',
    'unknown manifests and changed immutable coordinates are refused',
    'unreviewed distributions remain hidden from Composer',
    'Composer v2 advertises exact approved archive identities and native dependencies',
    'the registry delivers each original ZIP under current review',
    'stock Composer selects and locks the exact scoped dependency graph first',
    'stock Composer caches exact ZIPs and installs their inert contents first',
    'stock Composer selects and locks the exact scoped dependency graph after-restart',
    'stock Composer caches exact ZIPs and installs their inert contents after-restart',
    'the native lockfile stays byte-identical after service restart',
    'policy removes the denied version and refuses direct retrieval',
    'stock Composer refuses to install a newly denied locked archive',
)
GROUP_CHECKS = (
    *CHECKS[:6], 'the read-only group requires digest-pinned downloads from the first owning member',
    *CHECKS[6:], 'the currently denied preferred archive prevents fallback to the lower member',
)
FILES = (
    '.github/workflows/composer-hosted.yml', 'Makefile', 'go.mod', 'go.sum',
    'scripts/ci/composer_hosted_evidence.py', 'scripts/ci/terraform_provider_evidence.py',
    'scripts/composer_hosted_fixture.py', 'scripts/conformance_repository_manifest.py', 'scripts/bounded_client.py',
    'scripts/qualification_contract.py', 'internal/composer/package.go', 'internal/composer/package_test.go',
    'internal/server/composer.go', 'internal/server/composer_integration_test.go', 'internal/server/server.go',
    'internal/store/composer.go', 'internal/store/artifact_read.go', 'internal/store/lifecycle_artifact.go',
    'internal/store/repository.go', 'internal/store/migrations.go', 'internal/ziparchive/archive.go',
)
GROUP_FILES = (*FILES, 'internal/store/composer_group.go', 'internal/server/resolve.go')
FIELDS = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id', 'source_dirty', 'source_sha256',
          'binary_sha256', 'archive_sha256', 'postgres', 'npm', 'checks', 'composer_hosted', 'goal_complete', 'broad_readiness'}
DIGEST = '[a-f0-9]{64}'


def group_selected(source):
    return b'--composer-group' in source('.github/workflows/composer-hosted.yml').split()


def validate(report):
    if type(report) is not dict or report.get('profile') not in (PROFILE, GROUP_PROFILE):
        raise ValueError('invalid Composer profile')
    grouped = report['profile'] == GROUP_PROFILE
    fields = FIELDS | {'composer_group'} if grouped else FIELDS
    paths = GROUP_FILES if grouped else FILES
    if (set(report) != fields or type(report['schema']) is not int or report['schema'] != 1
            or report['status'] != 'passed' or report['runner_os'] != 'Linux'
            or report['runner_arch'] not in ('X64', 'ARM64') or report['source_dirty'] is not False
            or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not matches(report['npm'], r'(?:10|11)\.[0-9]{1,3}\.[0-9]{1,3}') or not postgres_version(report['postgres'])
            or not matches(report['archive_sha256'], DIGEST) or not hashes(report['source_sha256'], paths)
            or not hashes(report['binary_sha256'], ('cratectl', 'cratectld')) or report['checks'] != list(BASE_CHECKS)):
        raise ValueError('invalid Composer candidate or PostgreSQL scope')
    validate_run(report['composer_hosted'])
    if grouped:
        validate_run(report['composer_group'], grouped=True)
    return report


def validate_run(native, *, grouped=False):
    fields = {'checks', 'composer_version', 'composer_sha256', 'php_version', 'archive_sha256', 'lock_sha256'}
    if grouped:
        fields.add('collision_sha256')
    if (type(native) is not dict or set(native) != fields
            or native['checks'] != list(GROUP_CHECKS if grouped else CHECKS) or native['composer_version'] != COMPOSER_VERSION
            or native['composer_sha256'] != COMPOSER_SHA256 or not matches(native['php_version'], r'8\.[0-9]{1,2}\.[0-9]{1,3}')
            or not hashes(native['archive_sha256'], tuple(f'{name}@{version}' for name, version in COORDINATES))
            or not matches(native['lock_sha256'], DIGEST)):
        raise ValueError('invalid stock Composer coverage or client identity')
    if grouped and (not matches(native['collision_sha256'], DIGEST) or native['collision_sha256'] in native['archive_sha256'].values()):
        raise ValueError('invalid Composer group collision evidence')
