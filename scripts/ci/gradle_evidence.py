# SPDX-License-Identifier: BUSL-1.1
"""Reviewed native Gradle fields; no arbitrary client output or private paths."""
import re

FIXTURES = ('dependency', 'application_1', 'application_2', 'other_dependency',
            'other_application_1', 'local_application_3', 'snapshot_first', 'snapshot_second')
STAGES = ['client_identity', 'publication', 'review_and_tenants', 'reader_publication_denied',
          'proxy_group', 'policy_and_restart', 'snapshots', 'revocation']
PHASES = {'client_identity', 'publication', 'review', 'proxy_group', 'policy', 'snapshots', 'revocation', 'complete'}
DIAGNOSTICS = {'http_401', 'http_403', 'http_404', 'fixture_compilation', 'variant_selection',
               'dependency_resolution', 'publication', 'verification', 'jvm'}


def safe_gradle_contract(value, status):
    fields = {'version', 'distribution_sha256', 'launcher_sha256', 'fixture_source_sha256',
              'fixture_sha256', 'completed', 'phase', 'diagnostics', 'java_version', 'java_launcher_sha256', 'java_release_sha256'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('Gradle evidence fields are outside the reviewed profile')
    if not isinstance(value['version'], str) or not re.fullmatch(r'9\.\d{1,3}\.\d{1,3}', value['version']):
        raise ValueError('Gradle version is outside the pinned profile')
    if not isinstance(value['java_version'], str) or not re.fullmatch(r'21\.\d{1,3}\.\d{1,3}\+\d{1,3}(?:-LTS)?', value['java_version']):
        raise ValueError('Java runtime must identify the bounded actual build')
    for name in ['distribution_sha256', 'launcher_sha256', 'fixture_source_sha256', 'java_launcher_sha256', 'java_release_sha256']:
        if not isinstance(value[name], str) or not re.fullmatch('[0-9a-f]{64}', value[name]):
            raise ValueError('Gradle identity must be a SHA256 digest')
    if not isinstance(value['phase'], str) or value['phase'] not in PHASES:
        raise ValueError('Gradle phase must use the fixed stage vocabulary')
    completed = value['completed']
    if not isinstance(completed, list) or len(completed) > len(STAGES) or completed != STAGES[:len(completed)]:
        raise ValueError('Gradle completed stages must be the ordered mandatory prefix')
    diagnostics = value['diagnostics']
    if not isinstance(diagnostics, list) or len(diagnostics) > len(DIAGNOSTICS) or any(not isinstance(c, str) or c not in DIAGNOSTICS for c in diagnostics) or len(set(diagnostics)) != len(diagnostics):
        raise ValueError('Gradle diagnostic codes must use the fixed vocabulary')
    fixtures = value['fixture_sha256']
    allowed = {name + '_' + ext for name in FIXTURES for ext in ['jar', 'pom', 'module']}
    if not isinstance(fixtures, dict) or not set(fixtures) <= allowed or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in fixtures.values()):
        raise ValueError('Gradle fixture identities are outside the bounded owned set')
    if status == 'passed' and (value['phase'] != 'complete' or completed != STAGES or set(fixtures) != allowed or diagnostics):
        raise ValueError('Passed Gradle evidence requires every fixture and mandatory stage')
    return {**value, 'fixture_sha256': dict(sorted(fixtures.items())), 'diagnostics': sorted(diagnostics)}
