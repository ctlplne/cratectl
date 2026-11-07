#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Exercise fixture bounds and receipt/stdout capture without a package SDK."""
import base64
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

from conformance_go_export_portable import CAPSULE_LIMIT, FILES, LIMITS, decode_fixture, private_file_proxy, read_capsule, run_capture, verify_network_probe, write_private


def fixture():
    files = {name: b'owned-public-data' for name in FILES}
    files['signer-public.pem'] = b'-----BEGIN PUBLIC KEY-----\nowned\n-----END PUBLIC KEY-----\n'
    files['checkpoint.sig'] = b'x' * 64
    return {'profile': 'cratectl.go.export.portable.fixture.v1', 'candidate': 'a' * 40,
            'source_run_id': '123', 'source_job': 'produce', 'source_runner_sha256': 'b' * 64,
            'source_os': 'linux', 'source_arch': 'amd64', 'tenant': 'schema-team',
            'repository': 'exported', 'module': 'go.cratectl.invalid/Owned/intake', 'version': 'v1.0.0',
            'export_id': 'c' * 64, 'created_sequence': 7,
            'through': {'tenant': 'schema-team', 'sequence': 8, 'hash': 'd' * 64},
            'zip_h1': 'h1:' + base64.b64encode(b'a' * 32).decode(),
            'mod_h1': 'h1:' + base64.b64encode(b'b' * 32).decode(),
            'files': {name: base64.b64encode(body).decode() for name, body in files.items()}}


class FixtureTests(unittest.TestCase):
    def decode(self, value):
        return decode_fixture(json.dumps(value).encode(), 'a' * 40, '123')

    def test_exact_synthetic_inventory_decodes_without_claiming_package_validity(self):
        value, files = self.decode(fixture())
        self.assertEqual(set(files), FILES)
        self.assertEqual(value['created_sequence'], 7)
        self.assertEqual(len(files['checkpoint.sig']), 64)

    def test_unknown_private_members_and_wrong_context_are_rejected(self):
        mutations = [{'candidate': 'f' * 40}, {'source_run_id': '124'}, {'source_job': 'consume'},
                     {'source_arch': 'arm64'}, {'source_os': 'darwin'}, {'tenant': 'customer'},
                     {'repository': 'customer'}, {'module': 'example.com/customer'}, {'version': 'v2.0.0'},
                     {'created_sequence': True}, {'created_sequence': 1 << 63}, {'export_id': 'x' * 64},
                     {'zip_h1': 'h1:invalid'}, {'private_key': 'unreviewed'}]
        for change in mutations:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    self.decode({**fixture(), **change})
        for name in ['signer-private.pem', 'runtime.json', 'admin.token', '../original.zip']:
            value = fixture()
            value['files'][name] = base64.b64encode(b'private-synthetic-value').decode()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.decode(value)

    def test_missing_invalid_and_oversized_members_reject_before_product_use(self):
        for name in FILES:
            value = fixture()
            del value['files'][name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                self.decode(value)
        for replacement in ['invalid-base64!', '', None, 12]:
            value = fixture()
            value['files']['original.zip'] = replacement
            with self.subTest(encoded=replacement), self.assertRaises(ValueError):
                self.decode(value)
        for name in ['manifest.json', 'signer-public.pem', 'checkpoint.sig']:
            value = fixture()
            value['files'][name] = base64.b64encode(b'x' * (LIMITS[name] + 1)).decode()
            with self.subTest(oversize=name), self.assertRaises(ValueError):
                self.decode(value)
        value = fixture()
        value['files']['original.mod'] = base64.b64encode(b'-----BEGIN PRIVATE KEY-----\nprivate-synthetic-value').decode()
        with self.assertRaises(ValueError):
            self.decode(value)
        with self.assertRaises(ValueError):
            decode_fixture(b' ' * (CAPSULE_LIMIT + 1), 'a' * 40, '123')

    def test_duplicate_json_and_incomplete_or_wrong_tenant_anchor_reject(self):
        raw = json.dumps(fixture()).encode().replace(b'"created_sequence": 7', b'"created_sequence": 7, "created_sequence": 7')
        with self.assertRaises(ValueError):
            decode_fixture(raw, 'a' * 40, '123')
        for change in [{'sequence': 6}, {'tenant': 'other'}, {'hash': 'x'}, {'sequence': True}, {'sequence': 1 << 63}, {'extra': True}]:
            value = fixture()
            value['through'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.decode(value)

    def test_capsule_symlink_and_existing_private_file_are_not_followed_or_overwritten(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-portable-unit-') as directory:
            root = Path(directory)
            target = root / 'input.json'
            write_private(target, json.dumps(fixture()).encode())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(read_capsule(target), target.read_bytes())
            alias = root / 'alias.json'
            alias.symlink_to(target)
            with self.assertRaises(OSError):
                read_capsule(alias)
            with self.assertRaises(FileExistsError):
                write_private(alias, b'changed')
            self.assertEqual(self.decode(json.loads(target.read_bytes()))[0]['repository'], 'exported')

    def test_private_stderr_is_separate_from_success_receipt_and_expected_exit(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-portable-capture-') as directory:
            root = Path(directory)
            env = {k: os.environ[k] for k in ['PATH', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH'] if k in os.environ}
            code, output = run_capture([sys.executable, '-c', 'import sys;print("receipt");print("private-synthetic-value",file=sys.stderr)'], root, env, root / 'command.log')
            self.assertEqual((code, output), (0, b'receipt\n'))
            self.assertIn(b'private-synthetic-value', (root / 'command.log').read_bytes())
            code, output = run_capture([sys.executable, '-c', 'import sys;print("rejected",file=sys.stderr);sys.exit(1)'], root, env, root / 'reject.log')
            self.assertEqual((code, output), (1, b''))
            with self.assertRaises(ValueError):
                run_capture(['/cratectl-owned-nonexistent-command'], root, env, root / 'missing.log')

    def test_namespace_observation_requires_a_new_empty_network_and_original_uid(self):
        probe = {'namespace': 124, 'uid': 1001, 'gid': 1001, 'interfaces': ['lo'], 'ipv4_routes': [], 'ipv6_routes': []}
        self.assertEqual(len(verify_network_probe(json.dumps(probe).encode(), 123, 1001, 1001)), 64)
        for change in [{'namespace': 123}, {'namespace': -1}, {'namespace': True}, {'uid': 0},
                       {'gid': 0}, {'interfaces': ['lo', 'eth0']}, {'ipv4_routes': ['upstream route']},
                       {'ipv4_routes': ''}, {'ipv6_routes': ['upstream eth0']}, {'extra': True}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_network_probe(json.dumps({**probe, **change}).encode(), 123, 1001, 1001)

    def test_file_proxy_has_no_network_fallback_or_escape_and_preserves_spaces(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-portable-proxy-') as directory:
            root = Path(directory)
            output = root / 'offline export'
            proxy = output / 'proxy'
            proxy.mkdir(parents=True)
            value = proxy.as_uri()
            self.assertEqual(private_file_proxy(value, output), value)
            for invalid in [value + ',direct', value + '|https://example.invalid',
                            'https://example.invalid/proxy', value + '?extra=1', value + '#fragment',
                            root.as_uri(), (proxy / 'missing').as_uri(), '\n' + value]:
                with self.subTest(value=invalid), self.assertRaises(ValueError):
                    private_file_proxy(invalid, output)


if __name__ == '__main__':
    unittest.main()
