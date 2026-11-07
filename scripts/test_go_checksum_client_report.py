#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned export-boundary controls; no stock Go, TLS listener or database runs."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_go_checksum_client as probe


class ChecksumReportBoundary(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cratectl-checksum-report-', dir=probe.ROOT / '.cache')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        private = self.root / '.private'
        private.mkdir(mode=0o700)
        public = self.root / 'public.json'
        public.write_text('{"owned":"public stand-in"}')
        certificate = self.root / 'docs/qualification/ci-diagnostics-recipient.pem'
        certificate.parent.mkdir(parents=True)
        certificate.write_text('owned public recipient stand-in')
        self.progress = {**probe.PROGRESS, 'controls': dict.fromkeys(probe.CONTROLS, 'passed'), 'go_version':'1.27.3', 'go_binary_sha256':'b'*64}
        self.records = []
        for name, value in [('ROOT', self.root), ('PUBLIC', public), ('PROGRESS', self.progress), ('PRIVATE_RECORDS', self.records)]:
            p = patch.object(probe, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.dict(probe.os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_RUN_ID':'123456', 'GITHUB_SHA':'a'*40})
        p.start()
        self.addCleanup(p.stop)

    def export(self, status):
        def git(command, **_):
            return 'a' * 40 + '\n' if command[1:3] == ['rev-parse', 'HEAD'] else b''
        with patch.object(probe.subprocess, 'check_output', side_effect=git):
            probe.export_ci_report(status)

    def test_pass_requires_every_named_control(self):
        self.progress['controls'].pop('zip-mismatch')
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            self.export('passed')
        self.assertFalse((self.root / '.cache/ci-go-checksum-client-summary.json').exists())
        self.progress['controls']['zip-mismatch'] = 'passed'
        self.progress['go_binary_sha256'] = None
        with self.assertRaisesRegex(ValueError, 'binary identity'):
            self.export('passed')
        self.progress['go_binary_sha256'] = 'b'*64
        self.export('passed')
        report = json.loads((self.root / '.cache/ci-go-checksum-client-summary.json').read_text())
        self.assertEqual(report['controls'], dict.fromkeys(probe.CONTROLS, 'passed'))
        self.assertEqual(report['status'], 'passed')

    def test_failed_raw_context_is_sealed_and_never_in_safe_summary(self):
        raw = self.root / '.private/go-checksum-client-owned-zip-mismatch.json'
        raw.write_text('{"private_context":"owned-sensitive-response-standin"}')
        raw.chmod(0o600)
        self.records.append(raw)
        self.progress['controls']['zip-mismatch'] = 'failed'
        sealed = []
        def seal(payload, certificate):
            sealed.append(payload)
            return b'owned cipher stand-in'
        with patch('ci_native_diagnostics.seal', side_effect=seal):
            self.export('failed')
        summary = (self.root / '.cache/ci-go-checksum-client-summary.json').read_text()
        report = json.loads(summary)
        self.assertNotIn('owned-sensitive-response-standin', summary)
        self.assertNotIn('body_base64', summary)
        self.assertNotIn('.private', summary)
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['encrypted_diagnostics']['records'], 1)
        self.assertEqual((self.root / '.cache/ci-go-checksum-client.cms').read_bytes(), b'owned cipher stand-in')
        payload = json.loads(sealed[0])
        self.assertEqual(payload['candidate'], 'a' * 40)
        self.assertEqual(len(payload['records']), 1)

    def test_unknown_outcome_or_oversized_record_never_exports_plaintext(self):
        with patch.dict(probe.os.environ, {'GITHUB_SHA':'b'*40}):
            with self.assertRaisesRegex(ValueError, 'run/source'):
                self.export('failed')
        with self.assertRaisesRegex(ValueError, 'Unknown'):
            self.export('unknown')
        self.progress['controls']['unexpected'] = 'passed'
        with self.assertRaisesRegex(ValueError, 'Unknown'):
            self.export('failed')
        del self.progress['controls']['unexpected']
        raw = self.root / '.private/go-checksum-client-owned-zip-mismatch.json'
        raw.write_bytes(b'x' * ((256 << 10) + 1))
        raw.chmod(0o600)
        self.records.append(raw)
        with self.assertRaises(ValueError):
            self.export('failed')
        self.assertFalse((self.root / '.cache/ci-go-checksum-client-summary.json').exists())
        self.assertFalse((self.root / '.cache/ci-go-checksum-client.cms').exists())


if __name__ == '__main__':
    unittest.main()
