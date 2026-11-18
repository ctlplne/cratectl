# SPDX-License-Identifier: BUSL-1.1
"""Validate safe evidence from the disconnected saved-image replay."""

import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qualification_contract import CURRENT_SCHEMA, CURRENT_TENANT_TABLES


NODE = 'node:22-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7'
CHECKS = ('verified-signed-media', 'wrong-trust-refused', 'changed-image-refused', 'both-tags-absent-before-load',
          'both-loaded-image-ids-exact', 'blank-imported-database', 'imported-bootstrap', 'scoped-imported-runtime',
          'deployed-image-ids-exact', 'no-published-ports')
COMMON = ('only-loopback-in-imported-image-namespace', 'native-linux-arch-nonroot-client',
          'verified-native-cli-archive', 'imported-registry-trusted-tls')
PHASES = {
    'fresh': (*COMMON, 'registry-empty-after-imported-bootstrap', 'private-stock-npm-input',
              'stock-npm-published-to-imported-image', 'unassessed-package-refused',
              'exact-approved-package-downloaded', 'imported-worker-completed-durable-intents'),
    'restarted': (*COMMON, 'private-stock-npm-input', 'registry-restart-retains-approved-reference',
                  'fresh-cache-installs-identical-bytes-after-restart'),
}
SOURCE_PATHS = (
    '.github/workflows/offline-media.yml', 'scripts/ci/offline_media_evidence.py', 'scripts/ci/bootstrap_oci_clients.sh',
    'scripts/ci/fetch_archive.py', 'scripts/conformance_offline_media.py', 'scripts/fixtures/offline-media/client.py',
    'scripts/linux_offline_media.py', 'scripts/linux_candidate_sbom.py', 'scripts/install_linux_candidate.py',
    'scripts/verify_linux_candidate.py', 'scripts/package_linux.py', 'scripts/compose_evaluation.py',
    'scripts/bounded_client.py', 'deploy/compose/Dockerfile', 'deploy/compose/.dockerignore',
    'deploy/compose/compose.yaml', 'deploy/compose/init-database.sql', 'deploy/helm/cratectl/Chart.yaml',
    'deploy/helm/cratectl/values.yaml', 'deploy/helm/cratectl/values.schema.json',
    'deploy/helm/cratectl/templates/_helpers.tpl', 'deploy/helm/cratectl/templates/deployment.yaml',
    'deploy/helm/cratectl/templates/service.yaml', 'deploy/helm/cratectl/templates/worker-identities.yaml',
    'Makefile', 'go.mod', 'go.sum', 'scripts/qualification_contract.py',
)
FIELDS = {'schema', 'profile', 'candidate', 'runner_os', 'runner_arch', 'run_id', 'source_dirty', 'status',
          'runtime_phases', 'checks', 'image_configuration_sha256', 'manifest_sha256', 'archive_sha256',
          'source_sha256', 'forced_tenant_tables', 'database_schema', 'goal_complete', 'broad_readiness'}


def matches(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def validate(report, *, local=False):
    if (type(report) is not dict or set(report) != FIELDS or type(report['schema']) is not int or report['schema'] != 1
            or report['profile'] != 'cratectl-native-offline-media-v1' or not matches(report['candidate'], '[a-f0-9]{40}')
            or (report['run_id'] is not None if local else not matches(report['run_id'], '[1-9][0-9]{0,17}'))
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in ('X64', 'ARM64')
            or report['status'] != 'passed' or report['source_dirty'] is not False
            or report['checks'] != list(CHECKS)
            or type(report['database_schema']) is not int or report['database_schema'] != CURRENT_SCHEMA
            or type(report['forced_tenant_tables']) is not int or report['forced_tenant_tables'] != CURRENT_TENANT_TABLES
            or report['goal_complete'] is not False or report['broad_readiness'] is not False
            or any(not matches(report[key], '[a-f0-9]{64}') for key in ('manifest_sha256', 'archive_sha256'))):
        raise ValueError('invalid offline media identity or coverage')
    phases = report['runtime_phases']
    if type(phases) is not list or len(phases) != len(PHASES):
        raise ValueError('invalid offline media runtime phase inventory')
    for (name, checks), phase in zip(PHASES.items(), phases):
        if (type(phase) is not dict or set(phase) != {'phase', 'checks', 'artifact_digest', 'npm'}
                or phase['phase'] != name or phase['checks'] != list(checks) or phase['npm'] != '10.9.9'
                or not matches(phase['artifact_digest'], '[a-f0-9]{64}')):
            raise ValueError('invalid offline media runtime phase')
    if phases[0]['artifact_digest'] != phases[1]['artifact_digest']:
        raise ValueError('artifact identity differs after isolated restart')
    for field, keys, pattern in (('source_sha256', SOURCE_PATHS, '[a-f0-9]{64}'),
                                 ('image_configuration_sha256', ('postgres', 'registry'), 'sha256:[a-f0-9]{64}')):
        binding = report[field]
        if type(binding) is not dict or set(binding) != set(keys) or any(not matches(value, pattern) for value in binding.values()):
            raise ValueError('invalid offline media digest inventory')
    return report
