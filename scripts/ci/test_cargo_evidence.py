#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import copy
import unittest

from cargo_evidence import BASE_CHECKS, CHECKS, PINS, SOURCE_PATHS, validate


class CargoEvidenceTests(unittest.TestCase):
    def test_native_report_requires_all_checks_and_pins_for_its_own_architecture(self):
        digest = 'a' * 64
        report = {'schema': 1, 'profile': 'cratectl-native-cargo-v1', 'candidate': 'b' * 40,
                  'status': 'passed', 'runner_os': 'Linux', 'runner_arch': 'ARM64', 'run_id': '1234',
                  'source_dirty': False, 'source_sha256': dict.fromkeys(SOURCE_PATHS, digest),
                  'binary_sha256': dict.fromkeys(('cratectl', 'cratectld'), digest),
                  'sdk_archives_sha256': PINS['arm64'], 'cargo': 'cargo 1.100.0 (3acc79c0c 2026-11-05)',
                  'cargo_sha256': digest, 'rustc_sha256': digest, 'checks': list(CHECKS),
                  'base_checks': [check for check in BASE_CHECKS if check != 'provider matches the clean candidate'],
                  'archive_sha256': dict.fromkeys(('cratectl-cargo-leaf', 'cratectl-cargo-root'), digest),
                  'postgres': 'postgres (PostgreSQL) 16.16', 'goal_complete': False, 'broad_readiness': False}
        self.assertEqual(validate(report), report)
        for field, value in [('source_dirty', True), ('runner_arch', 'X64'), ('checks', list(CHECKS)[:-1]),
                             ('broad_readiness', True), ('archive_sha256', {}), ('source_sha256', {}),
                             ('postgres', 'postgres (PostgreSQL) 16.42'), ('token', 'private-owned-example')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                changed = copy.deepcopy(report)
                changed[field] = value
                validate(changed)


if __name__ == '__main__':
    unittest.main()
