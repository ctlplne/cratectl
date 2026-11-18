# SPDX-License-Identifier: BUSL-1.1
"""Closed report for installation without a network inside the target."""

import re


IMAGE = ('docker.io/library/python:3.14.10-slim-bookworm'
         '@sha256:3fe1a0b6c2d6b2ebb572906cdabeca75aeb558c0c17db5ffefbcf8094871c32b')
CHECKS = ('nonroot-native-linux', 'only-loopback', 'empty-target', 'trusted-install',
          'manifest-and-modes', 'installed-digests', 'cli-execution', 'server-execution',
          'bad-digest-cleanup', 'other-platform-cleanup', 'existing-candidate-preserved', 'unsafe-target-refused')
DRIVER_PATHS = ('scripts/ci/qualify_linux_install.py', 'scripts/ci/linux_install_evidence.py',
                'scripts/install_linux_candidate.py', 'scripts/verify_linux_candidate.py',
                'scripts/package_linux.py', 'scripts/bounded_client.py')
SOURCE_PATHS = (*DRIVER_PATHS, '.github/workflows/linux-install.yml', 'Makefile', 'go.mod', 'go.sum')
FIELDS = {'schema', 'profile', 'candidate', 'run_id', 'runner_os', 'runner_arch', 'status',
          'source_dirty', 'checks', 'python_image', 'archive_sha256', 'binary_sha256',
          'source_sha256', 'goal_complete', 'broad_readiness'}


def matches(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def validate(report, *, local=False):
    if (type(report) is not dict or set(report) != FIELDS or type(report['schema']) is not int
            or report['schema'] != 1 or report['profile'] != 'cratectl-native-linux-install-v1'
            or not matches(report['candidate'], '[a-f0-9]{40}')
            or (report['run_id'] is not None if local else not matches(report['run_id'], '[1-9][0-9]{0,17}'))
            or report['runner_os'] != 'Linux' or report['runner_arch'] not in ('X64', 'ARM64')
            or report['status'] != 'passed' or report['source_dirty'] is not False
            or report['checks'] != list(CHECKS) or report['python_image'] != IMAGE
            or not matches(report['archive_sha256'], '[a-f0-9]{64}')
            or report['goal_complete'] is not False or report['broad_readiness'] is not False):
        raise ValueError('invalid Linux installation identity or coverage')
    for field, keys in (('binary_sha256', ('cratectl', 'cratectld')), ('source_sha256', SOURCE_PATHS)):
        binding = report[field]
        if type(binding) is not dict or set(binding) != set(keys) or any(
                not matches(value, '[a-f0-9]{64}') for value in binding.values()):
            raise ValueError('invalid Linux installation digest inventory')
    return report
