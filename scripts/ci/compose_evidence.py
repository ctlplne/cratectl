# SPDX-License-Identifier: BUSL-1.1
"""Verify the closed safe summary for the local Compose evaluation."""

import re


CHECKS = (
    'clean-source', 'linux-cli', 'linux-daemon', 'owned-topology', 'forced-rls',
    'schema', 'safe-render', 'registry-scope', 'worker-scope', 'private-cli-config',
    'tls-trust', 'blank-installation', 'private-npm-config', 'stock-publish',
    'review-refusal', 'approved-install', 'worker-receipts', 'shutdown',
    'fresh-install-after-restart', 'retained-volume',
)
SOURCE_PATHS = (
    '.github/workflows/compose-evaluation.yml', 'deploy/compose/.dockerignore',
    'deploy/compose/Dockerfile', 'deploy/compose/compose.yaml', 'deploy/compose/init-database.sql',
    'scripts/compose_evaluation.py', 'scripts/conformance_compose.py',
    'scripts/ci/compose_evidence.py', 'scripts/bounded_client.py', 'Makefile', 'go.mod', 'go.sum',
)
FIELDS = {
    'schema', 'profile', 'candidate', 'run_id', 'runner_os', 'runner_arch', 'status',
    'source_dirty', 'checks', 'compose_version', 'npm_version', 'go_version', 'database_schema',
    'forced_rls_tenant_tables', 'binary_sha256', 'source_sha256', 'runtime_image_id',
    'goal_complete', 'broad_readiness',
}


def match(pattern, value):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def safe_compose_contract(report):
    if (type(report) is not dict or set(report) != FIELDS or type(report['schema']) is not int
            or report['schema'] != 1 or report['profile'] != 'cratectl-compose-evaluation-v1'
            or not match('[a-f0-9]{40}', report['candidate'])
            or not match('[1-9][0-9]{0,17}', report['run_id'])
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in ('X64', 'ARM64')
            or report['status'] != 'passed' or report['source_dirty'] is not False
            or report['checks'] != list(CHECKS) or report['database_schema'] != 18
            or type(report['forced_rls_tenant_tables']) is not int or not 1 <= report['forced_rls_tenant_tables'] <= 512
            or report['goal_complete'] is not False or report['broad_readiness'] is not False):
        raise ValueError('invalid Compose summary identity, coverage or scope')
    if (not match(r'v?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:[-+][a-zA-Z0-9.\-]{1,50})?', report['compose_version'])
            or not match(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', report['npm_version'])
            or report['go_version'] != '1.27.4' or not match('sha256:[a-f0-9]{64}', report['runtime_image_id'])):
        raise ValueError('invalid Compose tool or image identity')
    for label, names in (('binary_sha256', ('cratectl', 'cratectld')), ('source_sha256', SOURCE_PATHS)):
        binding = report[label]
        if type(binding) is not dict or set(binding) != set(names) or any(
                not match('[a-f0-9]{64}', digest) for digest in binding.values()):
            raise ValueError('invalid Compose digest inventory')
    return report
