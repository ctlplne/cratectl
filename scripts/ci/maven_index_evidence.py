# SPDX-License-Identifier: BUSL-1.1
"""Closed stock Apache Indexer evidence for native Linux."""
if __package__:
    from .terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version
else:
    from terraform_provider_evidence import BASE_CHECKS as MANIFEST_CHECKS, hashes, matches, postgres_version


BASE_CHECKS = tuple(check for check in MANIFEST_CHECKS if check != 'provider matches the clean candidate')
MAVEN_INDEX_CHECKS = (
    'an ungranted same-tenant reader is forbidden from the native index',
    'stock Maven Indexer reads an empty full index while the POM awaits review',
    'stock Maven Indexer finds only the first fully admitted release',
    'stock Maven Indexer preserves both version and digest identities in repository order',
    'stock Maven Indexer holds independent same-coordinate tenant inventories',
    'the stock index and its exact JAR bytes recover after registry restart',
    'current POM denial removes that coordinate from the stock full index',
    'a conditional native index request honors read grant revocation',
)
CACHED_CHECKS = (
    'stock Maven Indexer reads a cold proxy index without contacting its origin',
    'an exact cached JAR alone cannot advertise a release without its POM',
    'stock Maven Indexer lists the exact checksum-validated pair without an upstream search',
    'an invalidated POM hides the cached release without consulting the origin',
    'an explicit POM fetch restores the current stock index record',
    'stock cached Maven discovery and exact JAR bytes survive restart',
    'current POM policy hides the cached pair without a source result leak',
)
GROUP_CHECKS = (
    'an ungranted preferred source hides the ordered Maven group coordinate',
    'unknown preferred source state fences an ordered Maven index without an origin request',
    'a current JAR absence alone cannot admit an ordered Maven release',
    'stock Maven Indexer reads a group release from independently selected JAR and POM members',
    'revoking the consulted preferred source grant removes the group release',
    'restoring the grant and current absence restores discovery with zero origin reads',
    'expired preferred POM absence fences group indexing without contacting the origin',
)
SOURCE_PATHS = (
    '.github/workflows/maven-index.yml', 'Makefile', 'go.mod', 'go.sum',
    'scripts/conformance_repository_manifest.py', 'scripts/maven_index_fixture.py', 'scripts/fixtures/maven-index/MavenIndexStock.java',
    'scripts/ci/maven_index_evidence.py', 'scripts/ci/terraform_provider_evidence.py', 'scripts/qualification_contract.py',
    'scripts/bounded_client.py', 'internal/server/server.go', 'internal/server/maven_index.go', 'internal/server/maven_metadata.go',
    'internal/store/maven_index.go', 'internal/store/decision.go', 'internal/store/repository.go', 'internal/store/lifecycle.go',
    'internal/store/store.go', 'internal/store/migrations.go',
)
CACHED_SOURCE_PATHS = SOURCE_PATHS + (
    'internal/server/resolve.go', 'internal/store/retrieval.go', 'internal/store/native_source.go',
    'internal/store/npm_proxy.go', 'internal/store/artifact_read.go', 'internal/store/source_configuration.go',
)
INDEXER_SHA256 = '7aebdcebb934f1e4f1b9583348a8a0cb4881862ac7263b40e5122b7c5ec1c3aa'
PROFILE = 'cratectl-native-maven-hosted-index-v1'
CACHED_PROFILE = 'cratectl-native-maven-repository-index-v2'
FIELDS = {'schema', 'profile', 'candidate', 'status', 'runner_os', 'runner_arch', 'run_id', 'source_dirty', 'source_sha256',
          'binary_sha256', 'archive_sha256', 'postgres', 'npm', 'checks', 'maven_index', 'goal_complete', 'broad_readiness'}
DIGEST = '[a-f0-9]{64}'


def cached_selected(source):
    return b'--maven-index-cached --maven-index-ci-architecture' in source('.github/workflows/maven-index.yml')


def validate(report):
    cached = isinstance(report, dict) and report.get('profile') == CACHED_PROFILE
    if (type(report) is not dict or set(report) != FIELDS or type(report['schema']) is not int or report['schema'] != 1
            or report['profile'] not in (PROFILE, CACHED_PROFILE) or report['status'] != 'passed'
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in ('X64', 'ARM64')
            or report['source_dirty'] is not False or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or not matches(report['candidate'], '[a-f0-9]{40}') or not matches(report['run_id'], '[1-9][0-9]{0,17}')
            or not matches(report['npm'], r'(?:10|11)\.[0-9]{1,3}\.[0-9]{1,3}') or not postgres_version(report['postgres'])
            or not matches(report['archive_sha256'], DIGEST) or not hashes(report['binary_sha256'], ('cratectl', 'cratectld'))
            or not hashes(report['source_sha256'], CACHED_SOURCE_PATHS if cached else SOURCE_PATHS)
            or report['checks'] != list(BASE_CHECKS)):
        raise ValueError('invalid native Maven repository index identity or base coverage')
    index = report['maven_index']
    fields = {'checks', 'reader', 'reader_sha256', 'java', 'archive_sha256', 'jar_sha256'}
    if cached:
        fields.add('cached')
    if (type(index) is not dict or set(index) != fields
            or index['checks'] != list(MAVEN_INDEX_CHECKS) or index['reader'] != '7.1.6' or index['reader_sha256'] != INDEXER_SHA256
            or not matches(index['java'], r'openjdk 21\.0\.13 [0-9]{4}-[0-9]{2}-[0-9]{2} LTS')
            or not matches(index['archive_sha256'], DIGEST)):
        raise ValueError('invalid native Maven repository index checks or tool identity')
    jars = index['jar_sha256']
    if type(jars) is not list or len(jars) != 3 or not all(matches(item, DIGEST) for item in jars) or len(set(jars)) != 3:
        raise ValueError('invalid native Maven JAR identities')
    if cached:
        proxy = index['cached']
        if (type(proxy) is not dict or set(proxy) != {'checks', 'archive_sha256', 'jar_sha256', 'pom_sha256', 'groups'}
                or proxy['checks'] != list(CACHED_CHECKS) or proxy['jar_sha256'] != jars[1]
                or not matches(proxy['archive_sha256'], DIGEST) or not matches(proxy['pom_sha256'], DIGEST)):
            raise ValueError('invalid cached Maven index scope or exact pair binding')
        group = proxy['groups']
        if type(group) is not dict or set(group) != {'checks', 'archive_sha256'} or group['checks'] != list(GROUP_CHECKS) or not matches(group['archive_sha256'], DIGEST):
            raise ValueError('invalid ordered Maven index scope or archive binding')
    return report
