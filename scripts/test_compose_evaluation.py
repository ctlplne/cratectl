#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1

import json
import os
from pathlib import Path
import tempfile
import unittest

from compose_evaluation import prepare_client, prepare_inputs, private_directory, read_state, state_for


class ComposeEvaluationTests(unittest.TestCase):
    def test_prepare_reuses_private_credentials_and_refuses_implicit_upgrade(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-compose-test-') as root:
            directory = Path(root)
            state = state_for(directory, 'up', 'owned', 'a' * 40)
            prepare_inputs(directory, state)
            prepare_client(directory)
            self.assertEqual(len({state[key] for key in ('postgres', 'owner', 'runtime')}), 3)
            self.assertEqual(state_for(directory, 'up', None, 'a' * 40), state)
            with self.assertRaisesRegex(ValueError, 'original source and tenant'):
                state_for(directory, 'up', 'owned', 'b' * 40)
            with self.assertRaisesRegex(ValueError, 'original source and tenant'):
                state_for(directory, 'up', 'other', 'a' * 40)
            self.assertIn('postgres://cratectl_app:', (directory / 'init.env').read_text())
            self.assertNotIn(state['postgres'], (directory / 'init.env').read_text())
            self.assertNotIn('CRATECTL_OWNER_DSN', (directory / 'postgres.env').read_text())
            self.assertEqual(json.loads((directory / 'client.json').read_text())['token_file'],
                             str(directory / 'installation/admin.token'))
            for name in ('evaluation.json', 'init.env', 'postgres.env', 'client.json'):
                self.assertEqual((directory / name).stat().st_mode & 0o777, 0o600)
            for name in ('installation', 'pagination'):
                self.assertEqual((directory / name).stat().st_mode & 0o777, 0o700)

    def test_state_reader_refuses_broad_links_and_oversized_files(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-compose-test-') as root:
            directory = Path(root)
            path = directory / 'evaluation.json'
            path.write_text('{}')
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'private regular file'):
                read_state(path)
            path.chmod(0o600)
            path.write_bytes(b' ' * 1025)
            with self.assertRaisesRegex(ValueError, 'size limit'):
                read_state(path)
            link = directory / 'cratectl-link'
            os.symlink(path, link)
            with self.assertRaises(OSError):
                read_state(link)
            directory.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'mode 0700'):
                private_directory(directory)


if __name__ == '__main__':
    unittest.main()
