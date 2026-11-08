# SPDX-License-Identifier: BUSL-1.1
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from go_export_portable_diagnostics import collect


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cratectl-portable-diagnostic-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        subprocess.run(['git', 'init', '-q', '-b', 'main', self.root], check=True)
        self.run = '0123456789'
        self.folder = self.root / '.private/go-export-portability' / self.run
        self.folder.mkdir(parents=True)
        self.folder.chmod(0o700)
        self.report = self.root / 'evidence/2026-11-07' / ('go-export-portability-' + self.run + '.json')
        self.report.parent.mkdir(parents=True)
        self.log = self.folder / ('command-' + 'b' * 32 + '.log')
        self.log.write_bytes(b'owned-stderr')
        self.log.chmod(0o600)
        Path(str(self.log) + '.stdout').write_bytes(b'owned-stdout')
        Path(str(self.log) + '.stdout').chmod(0o600)
        self.value = {'candidate': 'a' * 40, 'run': self.run, 'status': 'failed',
                      'failure': 'Owned native assertion failed',
                      'go_export_portability_contract': {'profile': 'hosted-export-cross-runner-v1', 'role': 'consumer', 'source_run_id': '123'},
                      'commands': [{'exit': 1, 'private_log': str(self.log.relative_to(self.root))}]}

    def save(self):
        self.report.write_text(json.dumps(self.value))

    def test_only_exact_command_streams_are_selected_without_keys_or_inputs(self):
        (self.folder / 'signer-private.pem').write_text('private-key-synthetic-value')
        self.save()
        payload = collect(self.root, 'a' * 40, '123', 'consumer')
        streams = payload['failures'][0]['commands'][0]['streams']
        self.assertEqual([base64.b64decode(s['head_b64']) for s in streams], [b'owned-stderr', b'owned-stdout'])
        self.assertNotIn('private-key-synthetic-value', json.dumps(payload))
        self.assertTrue(all(s['complete'] for s in streams))

    def test_wrong_source_run_role_private_path_and_symlink_are_rejected(self):
        self.save()
        for candidate, run_id, role in [('c' * 40, '123', 'consumer'), ('a' * 40, '124', 'consumer'), ('a' * 40, '123', 'producer')]:
            with self.subTest(context=(candidate, run_id, role)), self.assertRaises(ValueError):
                collect(self.root, candidate, run_id, role)
        self.value['commands'][0]['private_log'] = str((self.folder / 'signer-private.pem').relative_to(self.root))
        self.save()
        with self.assertRaises(ValueError):
            collect(self.root, 'a' * 40, '123', 'consumer')
        self.value['commands'][0]['private_log'] = str(self.log.relative_to(self.root))
        self.save()
        secret = self.root / 'private-input'
        secret.write_text('never-select-this')
        self.log.unlink()
        self.log.symlink_to(secret)
        with self.assertRaises((ValueError, OSError)):
            collect(self.root, 'a' * 40, '123', 'consumer')

    def test_large_log_retains_exact_identity_and_bounded_head_tail(self):
        body = b'x' * (2 << 20)
        self.log.write_bytes(body)
        self.save()
        stream = collect(self.root, 'a' * 40, '123', 'consumer')['failures'][0]['commands'][0]['streams'][0]
        self.assertEqual(stream['bytes'], len(body))
        self.assertEqual(stream['sha256'], hashlib.sha256(body).hexdigest())
        self.assertFalse(stream['complete'])
        self.assertEqual(len(base64.b64decode(stream['head_b64'])), 512 << 10)
        self.assertEqual(len(base64.b64decode(stream['tail_b64'])), 512 << 10)

    def test_successful_or_absent_reports_never_become_empty_diagnostic_success(self):
        self.save()
        self.value['status'] = 'passed'
        self.save()
        with self.assertRaises(ValueError):
            collect(self.root, 'a' * 40, '123', 'consumer')

    def common(self):
        folder = self.root / '.private/go-common-export-portability' / self.run
        folder.mkdir(parents=True, mode=0o700)
        log = folder / ('command-' + 'c' * 32 + '.log')
        log.write_bytes(b'owned-common-stderr')
        log.chmod(0o600)
        Path(str(log) + '.stdout').write_bytes(b'owned-common-stdout')
        Path(str(log) + '.stdout').chmod(0o600)
        report = self.report.with_name('go-common-export-portability-' + self.run + '.json')
        value = {**self.value, 'go_common_export_portability_contract':
                 {'profile': 'hosted-common-export-cross-runner-v1', 'role': 'consumer', 'source_run_id': '123'},
                 'commands': [{'exit': 1, 'private_log': str(log.relative_to(self.root))}]}
        del value['go_export_portability_contract']
        report.write_text(json.dumps(value))
        return folder, report, value

    def requirement(self):
        folder = self.root / '.private/go-requirement-export-portability' / self.run
        folder.mkdir(parents=True, mode=0o700)
        log = folder / ('command-' + 'd' * 32 + '.log')
        log.write_bytes(b'owned-requirement-stderr')
        log.chmod(0o600)
        Path(str(log) + '.stdout').write_bytes(b'owned-requirement-stdout')
        Path(str(log) + '.stdout').chmod(0o600)
        report = self.report.with_name('go-requirement-export-portability-' + self.run + '.json')
        value = {**self.value, 'go_requirement_export_portability_contract':
                 {'profile': 'hosted-requirement-export-cross-runner-v1', 'role': 'consumer', 'source_run_id': '123'},
                 'commands': [{'exit': 1, 'private_log': str(log.relative_to(self.root))}]}
        del value['go_export_portability_contract']
        report.write_text(json.dumps(value))
        return folder, report, value

    def test_requirement_and_all_three_profiles_preserve_only_bounded_command_streams(self):
        self.save()
        self.common()
        folder, _, _ = self.requirement()
        (folder / 'fixture.json').write_text('private-synthetic-fixture-must-not-escape')
        payload = collect(self.root, 'a' * 40, '123', 'consumer')
        self.assertEqual(payload['schema'], 3)
        self.assertEqual(payload['profile'], 'hosted-export-command-diagnostics-v3')
        self.assertEqual(len(payload['failures']), 3)
        requirement = next(x for x in payload['failures'] if x['profile'] == 'hosted-requirement-export-cross-runner-v1')
        self.assertEqual([base64.b64decode(x['head_b64']) for x in requirement['commands'][0]['streams']],
                         [b'owned-requirement-stderr', b'owned-requirement-stdout'])
        self.assertNotIn('private-synthetic-fixture-must-not-escape', json.dumps(payload))

    def test_requirement_namespace_cannot_select_other_profile_logs_or_private_inputs(self):
        folder, report, value = self.requirement()
        for path in [self.log, folder / 'fixture.json', folder / 'signer-private.pem']:
            value['commands'][0]['private_log'] = str(path.relative_to(self.root))
            report.write_text(json.dumps(value))
            with self.subTest(path=path), self.assertRaises(ValueError):
                collect(self.root, 'a' * 40, '123', 'consumer')

    def test_common_command_capture_excludes_inputs_and_private_pid(self):
        folder, _, _ = self.common()
        (folder / 'ack-cli.pid').write_text('12345\n')
        (folder / 'fixture.json').write_text('owned-private-input-not-for-diagnostics')
        payload = collect(self.root, 'a' * 40, '123', 'consumer')
        self.assertEqual(payload['schema'], 2)
        self.assertEqual(payload['failures'][0]['profile'], 'hosted-common-export-cross-runner-v1')
        streams = payload['failures'][0]['commands'][0]['streams']
        self.assertEqual([base64.b64decode(s['head_b64']) for s in streams], [b'owned-common-stderr', b'owned-common-stdout'])
        self.assertNotIn('owned-private-input-not-for-diagnostics', json.dumps(payload))

    def test_common_cannot_select_legacy_namespace_or_private_member(self):
        folder, report, value = self.common()
        for path in [self.log, folder / 'ack-cli.pid', folder / 'signer-private.pem']:
            value['commands'][0]['private_log'] = str(path.relative_to(self.root))
            report.write_text(json.dumps(value))
            with self.subTest(path=path), self.assertRaises(ValueError):
                collect(self.root, 'a' * 40, '123', 'consumer')

    def test_both_failed_profiles_keep_their_own_bounded_original_streams(self):
        self.save()
        self.common()
        payload = collect(self.root, 'a' * 40, '123', 'consumer')
        self.assertEqual({f['profile'] for f in payload['failures']}, {'hosted-common-export-cross-runner-v1', 'hosted-export-cross-runner-v1'})
        self.assertEqual(len(payload['failures']), 2)


if __name__ == '__main__':
    unittest.main()
