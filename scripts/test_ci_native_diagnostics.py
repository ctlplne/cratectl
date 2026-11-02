#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Real CMS round trips, authentication failures and owned-file collection."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from ci_native_diagnostics import collect, seal, unseal, write_new

ROOT = Path(__file__).resolve().parents[1]


class EncryptedNativeDiagnostics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='cratectl-cms-', dir=ROOT / '.cache')
        cls.folder = Path(cls.temporary.name)
        cls.key, cls.cert = cls.folder / 'recipient.key', cls.folder / 'recipient.pem'
        completed = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '1', '-subj', '/CN=cratectl-synthetic-ci-test', '-keyout', str(cls.key), '-out', str(cls.cert)], capture_output=True, timeout=30)
        if completed.returncode:
            raise AssertionError('real OpenSSL recipient fixture could not be generated')
        cls.wrong_key = cls.folder / 'wrong.key'
        completed = subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(cls.wrong_key)], capture_output=True, timeout=30)
        if completed.returncode:
            raise AssertionError('real wrong-key fixture could not be generated')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_authenticated_roundtrip_and_tamper_rejection(self):
        raw = b'private-synthetic-value\x00\xff\n' * 100
        ciphertext = seal(raw, self.cert)
        self.assertNotIn(raw[:23], ciphertext)
        self.assertEqual(unseal(ciphertext, self.key, self.cert), raw)
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 1
        for bad in (bytes(tampered), ciphertext[:-1], b'not CMS'):
            with self.subTest(length=len(bad)), self.assertRaises(ValueError):
                unseal(bad, self.key, self.cert)
        with self.assertRaises(ValueError):
            unseal(ciphertext, self.wrong_key, self.cert)
        with self.assertRaises(ValueError):
            seal(raw, self.folder / 'missing.pem')

    def test_collection_selects_failed_owned_logs_and_excludes_credentials(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-cms-input-', dir=self.folder) as temp:
            root = Path(temp)
            folder = root / '.private/oci-client-conformance' / ('1' * 10)
            folder.mkdir(parents=True)
            log = folder / ('command-' + '2' * 32 + '.log')
            log.write_bytes(b'private-synthetic-command-error')
            (folder / 'admin.token').write_text('private-synthetic-credential-value')
            (folder / 'registry.log').write_bytes(b'private-synthetic-registry-error')
            command = {'label': 'owned command', 'private_log': str(log.relative_to(root)), 'expected_success': True, 'exit': 1}
            report = {'candidate': 'a' * 40, 'run': '1' * 10, 'status': 'failed', 'phase': 'authentication', 'commands': [command, {**command, 'expected_success': False}], 'credential': 'private-synthetic-credential-value'}
            progress = folder / 'progress.json'
            progress.write_text(json.dumps(report))
            payload, count = collect(root, 'a' * 40)
            self.assertEqual(count, 1)
            data = json.loads(payload)
            commands = data['failures'][0]['commands']
            self.assertEqual(len(commands), 1)
            self.assertEqual(base64.b64decode(commands[0]['output_base64']), log.read_bytes())
            self.assertNotIn('private-synthetic-credential-value', payload.decode())
            log.unlink()
            log.symlink_to(folder / 'admin.token')
            with self.assertRaises(ValueError):
                collect(root, 'a' * 40)
            with self.assertRaises(ValueError):
                collect(root, 'b' * 40)

    def test_private_outputs_cannot_replace_existing_files_or_symlinks(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-cms-output-', dir=self.folder) as temp:
            path = Path(temp) / 'output'
            write_new(Path(temp), path, b'private-synthetic-value')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_new(Path(temp), path, b'replacement')
            link = Path(temp) / 'link'
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                write_new(Path(temp), link, b'replacement')
            self.assertEqual(path.read_bytes(), b'private-synthetic-value')
            parent = Path(temp) / 'escaped'
            parent.symlink_to(self.folder, target_is_directory=True)
            with self.assertRaises(OSError):
                write_new(Path(temp), parent / 'must-not-exist', b'replacement')


if __name__ == '__main__':
    unittest.main()
