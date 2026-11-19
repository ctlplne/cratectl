# SPDX-License-Identifier: BUSL-1.1
"""Closed source-bound evidence for the native Composer hosted ZIP profile."""
if __package__:
    from .terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version
else:
    from terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version
from composer_hosted_fixture import APP, LIBRARY, COMPOSER_SHA256, COMPOSER_VERSION, COORDINATES, EXTRA_COORDINATES
from composer_search_fixture import HIDDEN, MATCH, NEIGHBOR

PROFILE = 'cratectl-native-composer-hosted-zip-v1'
GROUP_PROFILE = 'cratectl-native-composer-hosted-and-group-zip-v1'
VERSIONS_PROFILE = 'cratectl-native-composer-hosted-group-and-versions-v1'
PROXY_PROFILE = 'cratectl-native-composer-checksum-proxy-v1'
SEARCH_PROFILE = 'cratectl-native-composer-hosted-discovery-v1'
LIFECYCLE_PROFILE = 'cratectl-native-composer-retained-lifecycle-v1'
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
VERSION_CHECKS = (
    'Composer metadata keeps named development versions separate from numbered prereleases',
    'stock Composer selects and locks the exact scoped dependency graph development',
    'stock Composer caches exact ZIPs and installs their inert contents development',
    'stock Composer selects and locks the exact scoped dependency graph prerelease',
    'stock Composer caches exact ZIPs and installs their inert contents prerelease',
    'stock Composer selects and locks the exact scoped dependency graph development-after-restart',
    'stock Composer caches exact ZIPs and installs their inert contents development-after-restart',
    'the development lockfile stays byte-identical after service restart',
    'current policy removes only the denied development archive from discovery',
    'stock Composer refuses to install a newly denied development archive',
)
PROXY_CHECKS = (
    'restricted Composer proxy requires an explicit reader grant before upstream access',
    'the repository hides unassessed metadata and gates exact archive intake',
    'metadata and archives use separate approved credential scopes',
    'reviewed discovery emits the local immutable distribution locators',
    'stock Composer locks the exact approved proxy dependency graph first',
    'stock Composer installs the exact proxy ZIPs and inert files first',
    'stock Composer locks the exact approved proxy dependency graph after-restart',
    'stock Composer installs the exact proxy ZIPs and inert files after-restart',
    'the locked graph installs after restart with the origin offline and zero further requests',
    'current app denial hides its metadata while the dependency remains indexed',
    'stock Composer refuses a locked proxy archive after digest denial',
    'an advertised archive move outside approved authority stops metadata before a download',
)
SEARCH_CHECKS = (
    'Composer hosted discovery requires current repository and tenant access',
    'stock Composer full text search uses the inspected archive description and current policy',
    'stock Composer name search uses the governed native package list',
    'Composer list wildcards preserve the literal underscore in an owned package name',
    'stock Composer package type search excludes unsupported package kinds',
    'fresh stock Composer discovery suppresses the revoked package after restart',
)
LIFECYCLE_CHECKS = (
    'stock Composer locks and installs the exact approved archive before retirement',
    'preview keeps the reviewed Composer reference downloadable',
    'retirement hides the retained version from native discovery and downloads',
    'stock Composer refuses the retired archive in a retained lockfile',
    'restored reference reappears in fresh stock Composer discovery',
    'stock Composer installs the exact restored ZIP from the unchanged lockfile',
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
PROXY_FILES = (*GROUP_FILES, 'scripts/composer_proxy_fixture.py', 'scripts/cargo_proxy_fixture.py',
               'internal/composer/catalog.go', 'internal/composer/catalog_test.go', 'internal/server/composer_proxy.go',
               'internal/server/composer_proxy_integration_test.go', 'internal/store/composer_proxy.go',
               'internal/store/retrieval.go', 'internal/store/native_source.go', 'internal/store/source_configuration.go')
SEARCH_FILES = (*PROXY_FILES, 'scripts/composer_search_fixture.py', 'internal/server/composer_search.go',
                'internal/server/composer_search_integration_test.go', 'internal/store/composer_search.go')
LIFECYCLE_FILES = (*SEARCH_FILES, 'internal/server/composer_lifecycle_integration_test.go',
                   'internal/server/lifecycle.go', 'internal/store/lifecycle.go')
FIELDS = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id', 'source_dirty', 'source_sha256',
          'binary_sha256', 'archive_sha256', 'postgres', 'npm', 'checks', 'composer_hosted', 'goal_complete', 'broad_readiness'}
DIGEST = '[a-f0-9]{64}'


def group_selected(source):
    return b'--composer-group' in source('.github/workflows/composer-hosted.yml').split()


def versions_selected(source):
    return b'--composer-versions' in source('.github/workflows/composer-hosted.yml').split()


def proxy_selected(source):
    return b'--composer-proxy' in source('.github/workflows/composer-hosted.yml').split()


def search_selected(source):
    return b'--composer-search' in source('.github/workflows/composer-hosted.yml').split()


def lifecycle_selected(source):
    return b'--composer-lifecycle' in source('.github/workflows/composer-hosted.yml').split()


def validate(report):
    if type(report) is not dict or report.get('profile') not in (PROFILE, GROUP_PROFILE, VERSIONS_PROFILE, PROXY_PROFILE, SEARCH_PROFILE, LIFECYCLE_PROFILE):
        raise ValueError('invalid Composer profile')
    grouped = report['profile'] != PROFILE
    lifecycle = report['profile'] == LIFECYCLE_PROFILE
    discovered = lifecycle or report['profile'] == SEARCH_PROFILE
    proxied = discovered or report['profile'] == PROXY_PROFILE
    versions = proxied or report['profile'] == VERSIONS_PROFILE
    fields = FIELDS | {'composer_group'} if grouped else FIELDS
    paths = GROUP_FILES if grouped else FILES
    if proxied:
        fields = fields | {'composer_proxy'}
        paths = PROXY_FILES
    if discovered:
        fields = fields | {'composer_search'}
        paths = SEARCH_FILES
    if lifecycle:
        paths = LIFECYCLE_FILES
    if (set(report) != fields or type(report['schema']) is not int or report['schema'] != 1
            or report['status'] != 'passed' or report['runner_os'] != 'Linux'
            or report['runner_arch'] not in ('X64', 'ARM64') or report['source_dirty'] is not False
            or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not matches(report['npm'], r'(?:10|11)\.[0-9]{1,3}\.[0-9]{1,3}') or not postgres_version(report['postgres'])
            or not matches(report['archive_sha256'], DIGEST) or not hashes(report['source_sha256'], paths)
            or not hashes(report['binary_sha256'], ('cratectl', 'cratectld')) or report['checks'] != list(BASE_CHECKS)):
        raise ValueError('invalid Composer candidate or PostgreSQL scope')
    validate_run(report['composer_hosted'], versions=versions)
    if grouped:
        validate_run(report['composer_group'], grouped=True)
    if proxied:
        result = report['composer_proxy']
        if (type(result) is not dict or set(result) != {'checks', 'archive_sha256', 'lock_sha256'}
                or result['checks'] != list(PROXY_CHECKS) or not hashes(result['archive_sha256'], (APP, LIBRARY))
                or result['archive_sha256'][APP] == result['archive_sha256'][LIBRARY]
                or not matches(result['lock_sha256'], DIGEST)):
            raise ValueError('invalid governed Composer proxy report')
    if discovered:
        result = report['composer_search']
        search_fields = {'checks', 'archive_sha256', 'lifecycle'} if lifecycle else {'checks', 'archive_sha256'}
        if (type(result) is not dict or set(result) != search_fields or result['checks'] != list(SEARCH_CHECKS)
                or not hashes(result['archive_sha256'], (MATCH, NEIGHBOR, HIDDEN))):
            raise ValueError('invalid Composer hosted discovery report')
        if lifecycle:
            retired = result['lifecycle']
            if (type(retired) is not dict or set(retired) != {'checks', 'restored_archive_sha256', 'unchanged_lock_sha256'}
                    or retired['checks'] != list(LIFECYCLE_CHECKS) or retired['restored_archive_sha256'] != result['archive_sha256'][MATCH]
                    or not matches(retired['unchanged_lock_sha256'], DIGEST)):
                raise ValueError('invalid Composer retained lifecycle report')
    return report


def validate_run(native, *, grouped=False, versions=False):
    fields = {'checks', 'composer_version', 'composer_sha256', 'php_version', 'archive_sha256', 'lock_sha256'}
    if grouped:
        fields.add('collision_sha256')
    if versions:
        fields.add('version_forms')
    if (type(native) is not dict or set(native) != fields
            or native['checks'] != list(GROUP_CHECKS if grouped else CHECKS) or native['composer_version'] != COMPOSER_VERSION
            or native['composer_sha256'] != COMPOSER_SHA256 or not matches(native['php_version'], r'8\.[0-9]{1,2}\.[0-9]{1,3}')
            or not hashes(native['archive_sha256'], tuple(f'{name}@{version}' for name, version in COORDINATES))
            or not matches(native['lock_sha256'], DIGEST)):
        raise ValueError('invalid stock Composer coverage or client identity')
    if grouped and (not matches(native['collision_sha256'], DIGEST) or native['collision_sha256'] in native['archive_sha256'].values()):
        raise ValueError('invalid Composer group collision evidence')
    if versions:
        result = native['version_forms']
        if (type(result) is not dict or set(result) != {'checks', 'archive_sha256', 'development_lock_sha256', 'prerelease_lock_sha256'}
                or result['checks'] != list(VERSION_CHECKS) or not matches(result['development_lock_sha256'], DIGEST)
                or not matches(result['prerelease_lock_sha256'], DIGEST)
                or result['development_lock_sha256'] == result['prerelease_lock_sha256']
                or not hashes(result['archive_sha256'], tuple(f'{name}@{version}' for name, version in EXTRA_COORDINATES))):
            raise ValueError('invalid Composer development or prerelease evidence')
