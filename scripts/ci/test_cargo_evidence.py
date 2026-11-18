#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import copy
import unittest

from cargo_evidence import ARCHIVES, BASE_CHECKS, CHECKS, PINS, SOURCE_PATHS, validate
import cargo_public_evidence


class CargoEvidenceTests(unittest.TestCase):
    def controlled_report(self):
        digest = 'a' * 64
        report = {'schema': 1, 'profile': 'cratectl-native-cargo-v1', 'candidate': 'b' * 40,
                  'status': 'passed', 'runner_os': 'Linux', 'runner_arch': 'ARM64', 'run_id': '1234',
                  'source_dirty': False, 'source_sha256': dict.fromkeys(SOURCE_PATHS, digest),
                  'binary_sha256': dict.fromkeys(('cratectl', 'cratectld'), digest),
                  'sdk_archives_sha256': PINS['arm64'], 'cargo': 'cargo 1.100.0 (3acc79c0c 2026-11-05)',
                  'cargo_sha256': digest, 'rustc_sha256': digest, 'checks': list(CHECKS),
                  'base_checks': [check for check in BASE_CHECKS if check != 'provider matches the clean candidate'],
                  'archive_sha256': dict.fromkeys(ARCHIVES, digest),
                  'postgres': 'postgres (PostgreSQL) 16.16', 'goal_complete': False, 'broad_readiness': False}
        report['archive_sha256']['proxy-root'] = 'c' * 64
        report['archive_sha256']['proxy-revised-root'] = 'd' * 64
        report['archive_sha256']['proxy-other-tenant-root'] = 'e' * 64
        return report

    def test_native_report_requires_all_checks_and_pins_for_its_own_architecture(self):
        report = self.controlled_report()
        self.assertEqual(validate(report), report)
        for field, value in [('source_dirty', True), ('runner_arch', 'X64'), ('checks', list(CHECKS)[:-1]),
                             ('broad_readiness', True), ('archive_sha256', {}), ('source_sha256', {}),
                             ('postgres', 'postgres (PostgreSQL) 16.42'), ('token', 'private-owned-example')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                changed = copy.deepcopy(report)
                changed[field] = value
                validate(changed)
        report['archive_sha256']['proxy-root'] = report['archive_sha256']['cratectl-cargo-root']
        with self.assertRaisesRegex(ValueError, 'origin-built root and original stock leaf'):
            validate(report)

    def test_public_report_requires_both_exact_archives_and_the_canonical_lockfile_checks(self):
        public = cargo_public_evidence
        report = self.controlled_report()
        report.update(profile='cratectl-native-cargo-public-v1', public_source_sha256=dict.fromkeys(public.SOURCE_PATHS, 'a' * 64),
                      public_origin={'checks': list(public.CHECKS), 'index': public.INDEX, 'download_base': public.DOWNLOAD,
                                     'archive_sha256': {f'{name}-{version}.crate': digest
                                                        for name, (version, digest) in public.PACKAGES.items()},
                                     'lock_sha256': 'b' * 64, 'canonical_lock_sha256': 'c' * 64})
        self.assertEqual(public.validate(report), report)
        for field, value in [('checks', list(public.CHECKS)[:-1]), ('archive_sha256', {}),
                             ('canonical_lock_sha256', 'b' * 64), ('download_base', public.INDEX)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                changed = copy.deepcopy(report)
                changed['public_origin'][field] = value
                public.validate(changed)
        del report['public_source_sha256'][public.SOURCE_PATHS[0]]
        with self.assertRaisesRegex(ValueError, 'source digest inventory'):
            public.validate(report)


if __name__ == '__main__':
    unittest.main()
