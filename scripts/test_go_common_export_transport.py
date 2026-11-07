#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Independent-channel metadata stand-ins; never a native trust qualification."""
from pathlib import Path
import unittest

from conformance_go_common_export_portable import bind_common_transport, digest, original_arguments


class ChannelTests(unittest.TestCase):
    def fixture(self):
        value = {'source_runner_sha256': 'a' * 64}
        raw = b'owned original capsule'
        files = {'signer-public.pem': b'owned public-key bytes'}
        environment = {'CRATECTL_COMMON_FIXTURE_SHA256': digest(raw),
                       'CRATECTL_COMMON_PUBLIC_KEY_SHA256': digest(files['signer-public.pem']),
                       'CRATECTL_COMMON_SOURCE_RUNNER_SHA256': value['source_runner_sha256']}
        return value, raw, files, environment

    def test_all_separate_fingerprints_and_distinct_observed_runner_required(self):
        value, raw, files, environment = self.fixture()
        bind_common_transport(value, raw, files, 'b' * 64, environment)
        for key in environment:
            changed = dict(environment)
            changed[key] = 'c' * 64
            with self.subTest(key=key), self.assertRaises(ValueError):
                bind_common_transport(value, raw, files, 'b' * 64, changed)
        with self.assertRaises(ValueError):
            bind_common_transport(value, raw, files, 'a' * 64, environment)

    def test_adjacent_key_or_copied_metadata_without_channel_cannot_bind(self):
        value, raw, files, _ = self.fixture()
        with self.assertRaises(ValueError):
            bind_common_transport(value, raw, files, 'b' * 64, {})
        _, _, _, environment = self.fixture()
        with self.assertRaises(ValueError):
            bind_common_transport(value, raw + b' ', files, 'b' * 64, environment)
        with self.assertRaises(ValueError):
            bind_common_transport(value, raw, {'signer-public.pem': b'other key'}, 'b' * 64, environment)

    def test_native_arguments_select_exact_head_and_separate_key_without_network_config(self):
        value = {'set_id': 'c' * 64, 'tenant': 'schema-team', 'created_sequence': 7,
                 'through': {'sequence': 8, 'hash': 'd' * 64}}
        args = original_arguments(Path('/owned/cratectl'), value, Path('/owned/collection'), Path('/owned/output'), Path('/owned/independent.pem'))
        self.assertNotIn('--config', args)
        self.assertEqual(args[args.index('--checkpoint-key-file') + 1], '/owned/independent.pem')
        self.assertEqual(args[args.index('--journal-through-hash') + 1], 'd' * 64)
        self.assertEqual(args[args.index('--set-id') + 1], 'c' * 64)


if __name__ == '__main__':
    unittest.main()
