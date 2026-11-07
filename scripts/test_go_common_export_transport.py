#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Independent-channel metadata stand-ins; never a native trust qualification."""
from pathlib import Path
import json
import sys
import tempfile
import unittest

from conformance_go_common_export_portable import bind_common_transport, digest, original_arguments, prepare_source_fixture
from conformance_go_export_portable import run_capture


class ChannelTests(unittest.TestCase):
    def test_producer_launch_uses_supported_owned_process_budget(self):
        # Actual bounded subprocess, with an owned Python stand-in for Go. This
        # reaches the runner's admission guard that rejected the native source;
        # no PostgreSQL, package code or stock-client qualification is claimed.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / 'fixture'
            executable = root / 'go-standin'
            executable.write_text('#!' + sys.executable + '\n'
                                  'import json,os,sys\n'
                                  'print(json.dumps({"arguments":sys.argv[1:],'
                                  '"output":os.environ["CRATECTL_GO_COMMON_EXPORT_PORTABLE_OUT"]}))\n')
            executable.chmod(0o700)

            def command(arguments, *, command_env, cwd, timeout, combined):
                code, output = run_capture(arguments, cwd, command_env, root / 'owned.log',
                                           timeout=timeout, combined=combined)
                self.assertEqual(code, 0)
                return output

            result = json.loads(prepare_source_fixture(executable, root, fixture, command))
            self.assertEqual(result['output'], str(fixture))
            self.assertIn('-tags=integration', result['arguments'])
            self.assertIn('^TestGoModuleCommonSetOfflineNativeGraphAndUncertainAcknowledgement$', result['arguments'])

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
