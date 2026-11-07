#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned transport stand-ins only; no package SDK or signature is authenticated."""
import base64
import json
from pathlib import Path
import tempfile
import unittest

from go_common_export_fixture import (CAPSULE_LIMIT, MEMBER_LIMIT, MODULE_PREFIX,
                                      decode_common_fixture, read_common_capsule)
from ci.go_common_export_portability_evidence import FILES


def fixture():
    files = {name: base64.b64encode(b'owned-inert-data').decode() for name in FILES}
    files['checkpoint.sig'] = base64.b64encode(b'x' * 64).decode()
    files['signer-public.pem'] = base64.b64encode(b'-----BEGIN PUBLIC KEY-----\nowned\n-----END PUBLIC KEY-----\n').decode()
    return {'profile': 'cratectl.go.common-export.portable.fixture.v1', 'candidate': 'a' * 40,
            'source_run_id': '123', 'source_job': 'produce', 'source_runner_sha256': 'b' * 64,
            'source_os': 'linux', 'source_arch': 'amd64', 'tenant': 'schema-team',
            'set_id': 'c' * 64, 'created_sequence': 7,
            'through': {'tenant': 'schema-team', 'sequence': 8, 'hash': 'd' * 64},
            'root_count': 8, 'root_module': MODULE_PREFIX + '/node0', 'files': files}


class FixtureTests(unittest.TestCase):
    def decode(self, value):
        return decode_common_fixture(json.dumps(value).encode(), 'a' * 40, '123')

    def test_exact_owned_original_inventory_decodes_without_conveying_authenticity(self):
        value, members = self.decode(fixture())
        self.assertEqual(set(members), FILES)
        self.assertEqual(len(members), 31)
        self.assertEqual(value['created_sequence'], 7)

    def test_wrong_context_private_or_unexpected_members_are_refused(self):
        changes = [{'candidate': 'b' * 40}, {'source_run_id': '124'}, {'source_job': 'consume'},
                   {'source_os': 'darwin'}, {'source_arch': 'arm64'}, {'root_count': True},
                   {'root_count': 7}, {'root_module': 'customer.invalid/private'}, {'tenant': 'customer'},
                   {'created_sequence': True}, {'created_sequence': 9}, {'set_id': []},
                   {'source_runner_sha256': 'not-a-hash'}, {'api_token': 'private-synthetic-value'}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.decode({**fixture(), **change})
        for name in ['admin.token', 'external-private.pem', '../root.000.zip', 'root.008.zip']:
            value = fixture()
            value['files'][name] = base64.b64encode(b'private-synthetic-data').decode()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.decode(value)
        for name in FILES:
            value = fixture()
            del value['files'][name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                self.decode(value)

    def test_ambiguous_json_and_checkpoint_bindings_refuse(self):
        raw = json.dumps(fixture()).encode().replace(b'"root_count": 8', b'"root_count": 8, "root_count": 8')
        with self.assertRaises(ValueError):
            decode_common_fixture(raw, 'a' * 40, '123')
        for change in [{'sequence': True}, {'sequence': 6}, {'sequence': 1 << 63},
                       {'hash': 'wrong'}, {'tenant': 'other'}, {'unknown': True}]:
            value = fixture()
            value['through'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.decode(value)
        for bad in [b'null', b'[]', json.dumps(fixture()).encode() + b'{}', b' ' * (CAPSULE_LIMIT + 1)]:
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                decode_common_fixture(bad, 'a' * 40, '123')

    def test_base64_private_key_and_per_member_bounds_refuse(self):
        for encoded in ['', None, True, 'invalid!', 'YR==', base64.b64encode(b'PRIVATE KEY').decode(),
                        base64.b64encode(b'x' * (MEMBER_LIMIT + 1)).decode()]:
            value = fixture()
            value['files']['root.007.info'] = encoded
            with self.subTest(size=len(encoded) if isinstance(encoded, str) else None), self.assertRaises(ValueError):
                self.decode(value)
        for name, raw in [('checkpoint.sig', b'x' * 63), ('signer-public.pem', b'not-a-public-key-envelope')]:
            value = fixture()
            value['files'][name] = base64.b64encode(raw).decode()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.decode(value)

    def test_combined_limit_refuses_even_when_every_member_and_capsule_fit(self):
        value = fixture()
        for n in range(3):
            value['files']['root.%03d.zip' % n] = base64.b64encode(b'x' * (360 << 10)).decode()
        self.assertLess(len(json.dumps(value).encode()), CAPSULE_LIMIT)
        with self.assertRaises(ValueError):
            self.decode(value)

    def test_capsule_reader_refuses_symlinks_links_oversize_and_preserves_original(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-common-capsule-') as directory:
            path = Path(directory) / 'fixture.json'
            raw = json.dumps(fixture()).encode()
            path.write_bytes(raw)
            self.assertEqual(read_common_capsule(path), raw)
            alias = Path(directory) / 'alias'
            alias.symlink_to(path)
            with self.assertRaises(ValueError):
                read_common_capsule(alias)
            alias.unlink()
            alias.hardlink_to(path)
            with self.assertRaises(ValueError):
                read_common_capsule(path)
            alias.unlink()
            self.assertEqual(path.read_bytes(), raw)
            with path.open('wb') as output:
                output.truncate(CAPSULE_LIMIT + 1)
            with self.assertRaises(ValueError):
                read_common_capsule(path)


if __name__ == '__main__':
    unittest.main()
