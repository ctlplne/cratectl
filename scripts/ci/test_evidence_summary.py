#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Exercise report collection with a real disposable Git index and private fields."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from evidence_summary import summarize

ROOT = Path(__file__).resolve().parents[2]


class EvidenceSummary(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cratectl-ci-evidence-', dir=ROOT / '.cache')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        subprocess.run(['git', 'init', '-q', '-b', 'main', str(self.root)], check=True)
        (self.root / 'evidence').mkdir()
        self.environment = {'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': 'fixture', 'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64'}

    def write(self, name, data):
        path = self.root / 'evidence' / name
        path.write_text(json.dumps(data))
        return path

    def test_same_date_tracked_overwrite_and_new_report_are_both_exported(self):
        path = self.write('rules.json', {'candidate': 'b' * 40})
        subprocess.run(['git', 'add', 'evidence/rules.json'], cwd=self.root, check=True)
        self.write('rules.json', {'source_parent': 'a' * 40, 'passed': True, 'results': [{}, {}], 'credential': 'private-synthetic-value'})
        self.write('native.json', {'candidate': 'a' * 40, 'status': 'failed', 'checks': ['one'], 'failure': 'private-synthetic-value'})
        report = summarize(self.root, self.environment)
        self.assertEqual([(r['report'], r['status']) for r in report['records']], [('native.json', 'failed'), ('rules.json', 'passed')])
        self.assertEqual(report['records'][1]['cases'], 2)
        self.assertNotIn('private-synthetic-value', json.dumps(report))
        self.assertTrue(all('credential' not in record for record in report['records']))

    def test_stale_candidate_and_external_symlink_do_not_become_evidence(self):
        path = self.write('stale.json', {'candidate': 'b' * 40})
        with self.assertRaises(SystemExit):
            summarize(self.root, self.environment)
        path.unlink()
        outside = self.root / 'private.json'
        outside.write_text(json.dumps({'candidate': 'a' * 40, 'credential': 'private-synthetic-value'}))
        (self.root / 'evidence/escaped.json').symlink_to(outside)
        self.assertEqual(summarize(self.root, self.environment)['records'], [])

    def test_historical_identity_is_retained_without_arbitrary_fields(self):
        self.write('baseline.json', {'candidate': 'a' * 40, 'status': 'passed', 'baselines': [{'schema': 2, 'source': 'b' * 40, 'binary_sha256': 'c' * 64, 'private_log': 'private-synthetic-value'}]})
        record = summarize(self.root, self.environment)['records'][0]
        self.assertEqual(record['baselines'][0]['source'], 'b' * 40)
        self.assertNotIn('private-synthetic-value', json.dumps(record))


if __name__ == '__main__':
    unittest.main()
