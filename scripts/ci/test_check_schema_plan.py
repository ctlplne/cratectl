#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned migration-plan stand-ins; these tests neither migrate nor contact PG."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

from check_schema_plan import CURRENT_SCHEMA, MAX_PLAN_BYTES, read_plan

ROOT = Path(__file__).resolve().parents[2]


def current():
    return {'binary_version': CURRENT_SCHEMA, 'database_state': 'current',
            'applied': [{'version': n, 'checksum': format(n, '064x')} for n in range(1, CURRENT_SCHEMA + 1)],
            'pending': [], 'requires_legacy_adoption': False, 'safety_valid': True}


class SourceSchemaPlan(unittest.TestCase):
    def test_current_target_passes_and_previous_qualified_version_does_not(self):
        self.assertEqual(read_plan(json.dumps(current()).encode()), current())
        old = current()
        old['binary_version'] -= 1
        old['applied'].pop()
        with self.assertRaises(ValueError):
            read_plan(json.dumps(old).encode())
        # The target is explicitly committed source, never an observed DB value.
        self.assertEqual(CURRENT_SCHEMA, 18)

    def test_incomplete_unsafe_or_malformed_receipts_never_pass(self):
        for kind in ['future', 'pending', 'legacy', 'unsafe', 'truthy', 'state', 'missing-receipt',
                     'duplicate-version', 'bad-checksum', 'null-receipts', 'extra-field', 'alias-field', 'bool-version']:
            value = copy.deepcopy(current())
            if kind == 'future': value['binary_version'] += 1
            elif kind == 'pending': value['pending'] = [CURRENT_SCHEMA + 1]
            elif kind == 'legacy': value['requires_legacy_adoption'] = True
            elif kind == 'unsafe': value['safety_valid'] = False
            elif kind == 'truthy': value['safety_valid'] = 'true'
            elif kind == 'state': value['database_state'] = 'pending'
            elif kind == 'missing-receipt': value['applied'].pop()
            elif kind == 'duplicate-version': value['applied'][-1]['version'] -= 1
            elif kind == 'bad-checksum': value['applied'][-1]['checksum'] = 'untrusted'
            elif kind == 'null-receipts': value['applied'] = None
            elif kind == 'extra-field': value['private_context'] = 'owned-private-standin'
            elif kind == 'alias-field': value['Safety_Valid'] = value.pop('safety_valid')
            elif kind == 'bool-version': value['applied'][0]['version'] = True
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                read_plan(json.dumps(value).encode())
        for raw in [b'', b'null', b'{}\n{}', b'NaN', b'x' * (MAX_PLAN_BYTES + 1),
                    json.dumps(current()).replace('"safety_valid":', '"safety_valid":true,"safety_valid":').encode()]:
            with self.subTest(raw_bytes=len(raw)), self.assertRaises(ValueError):
                read_plan(raw)

    def test_bootstrap_and_browser_dependencies_use_source_contract(self):
        bootstrap = (ROOT / 'scripts/ci/bootstrap_linux.sh').read_text()
        self.assertIn('.cache/ci-build/cratectld migrate --plan | python scripts/ci/check_schema_plan.py', bootstrap)
        self.assertNotRegex(bootstrap, r'\["binary_version"\]\s*==\s*\d+')
        browser = (ROOT / '.github/workflows/browser-repair.yml').read_text()
        for path in ['scripts/ci/bootstrap_linux.sh', 'scripts/ci/check_schema_plan.py', 'scripts/qualification_contract.py']:
            self.assertIn("- '" + path + "'", browser)

    def test_pipeline_reports_fixed_categories_without_echoing_bad_input(self):
        script = ROOT / 'scripts/ci/check_schema_plan.py'
        for value, accepted in [(current(), True), ({'private-context': 'owned-private-standin'}, False)]:
            result = subprocess.run([sys.executable, str(script)], input=json.dumps(value).encode(),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
            self.assertEqual(result.returncode == 0, accepted)
            if not accepted:
                self.assertEqual(result.stdout, b'')
                self.assertNotIn(b'owned-private-standin', result.stderr)


if __name__ == '__main__':
    unittest.main()
