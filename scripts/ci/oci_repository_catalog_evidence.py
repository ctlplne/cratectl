# SPDX-License-Identifier: BUSL-1.1
"""Closed stock ORAS catalog evidence for native Linux."""
if __package__:
    from .terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version
else:
    from terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version


BASE_CHECKS = tuple(check for check in MANIFEST_CHECKS if check != 'provider matches the clean candidate')
CATALOG_CHECKS = (
    'stock ORAS follows the server’s one-entry linked catalog pages in lexical order',
    'stock ORAS applies the exclusive full-name catalog cursor',
    'stock ORAS sees only the independently authenticated tenant’s names',
    'an approved manifest with unassessed dependencies stays out of the catalog',
    'stock ORAS lists the review-gated name once its complete graph is allowed',
    'stock ORAS catalog immediately omits a graph with a denied layer',
    'stock ORAS honors revocation of the restricted repository read grant',
    'stock ORAS catalog and exact independent same-coordinate pulls recover after restart',
    'stock ORAS catalog excludes suspended repositories and retains the other tenant’s listings',
)
SOURCE_PATHS = (
    '.github/workflows/oci-repository-catalog.yml', 'Makefile', 'go.mod', 'go.sum',
    'scripts/conformance_repository_manifest.py', 'scripts/oci_repository_catalog_fixture.py',
    'scripts/ci/oci_repository_catalog_evidence.py', 'scripts/ci/fetch_archive.py',
    'scripts/ci/terraform_provider_evidence.py', 'scripts/qualification_contract.py', 'scripts/bounded_client.py',
    'cmd/cratectld/main.go', 'internal/server/server.go', 'internal/server/oci.go', 'internal/server/oci_repository_catalog.go',
    'internal/server/oci_discovery_page.go', 'internal/server/oci_manifest.go', 'internal/server/oci_read.go',
    'internal/store/oci_repository_catalog.go', 'internal/store/artifact_read.go', 'internal/store/lifecycle.go',
    'internal/store/oci.go', 'internal/store/oci_descriptor.go', 'internal/store/repository.go', 'internal/store/decision.go',
    'internal/store/store.go', 'internal/store/migrations.go',
)
ARCHIVE_PINS = {
    'X64': '66fb0ad7206f3f6fa77ed5b552049d364ccf4b50b1684554f731f76302b52ca0',
    'ARM64': 'b84269e78dfc2d5329a4aab373da3200de95e6c138338cf6c66c10c0a3f248c1',
}
FIELDS = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id', 'source_dirty', 'source_sha256',
          'binary_sha256', 'archive_sha256', 'postgres', 'npm', 'checks', 'oci_repository_catalog', 'oras_archive_sha256',
          'goal_complete', 'broad_readiness'}
DIGEST = '[a-f0-9]{64}'


def distinct_digests(values, count):
    return type(values) is list and len(values) == count and all(matches(item, DIGEST) for item in values) and len(set(values)) == count


def validate(report):
    if (type(report) is not dict or set(report) != FIELDS or type(report['schema']) is not int or report['schema'] != 1
            or report['profile'] != 'cratectl-native-oci-repository-catalog-v1' or report['status'] != 'passed'
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in ('X64', 'ARM64')
            or report['source_dirty'] is not False or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not matches(report['npm'], r'(?:10|11)\.[0-9]{1,3}\.[0-9]{1,3}') or not postgres_version(report['postgres'])
            or report['oras_archive_sha256'] != ARCHIVE_PINS[report['runner_arch']]
            or not matches(report['archive_sha256'], DIGEST) or not hashes(report['binary_sha256'], ('cratectl', 'cratectld'))
            or not hashes(report['source_sha256'], SOURCE_PATHS) or report['checks'] != list(BASE_CHECKS)):
        raise ValueError('invalid native OCI repository catalog identity or base coverage')
    catalog = report['oci_repository_catalog']
    if (type(catalog) is not dict or set(catalog) != {'oras', 'oras_sha256', 'checks', 'manifest_sha256', 'payload_sha256'}
            or catalog['oras'] != '1.3.6' or not matches(catalog['oras_sha256'], DIGEST) or catalog['checks'] != list(CATALOG_CHECKS)
            or not distinct_digests(catalog['manifest_sha256'], 3) or not distinct_digests(catalog['payload_sha256'], 2)):
        raise ValueError('invalid native OCI repository catalog checks, tool or artifact identity')
    return report
