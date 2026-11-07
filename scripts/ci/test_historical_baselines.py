#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned Git/manifest stand-ins; actual ancestry/native rebuild stays in upgrades."""
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, call

import build_upgrade_baselines as builder

ROOT = Path(__file__).resolve().parents[2]
HEAD = 'a' * 40


class HistoricalBaselines(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((ROOT / 'docs/qualification/upgrade-baselines.json').read_bytes())

    def test_complete_current_inventory_and_every_owned_output_is_validated(self):
        rows = builder.baselines()
        self.assertEqual([row['schema'] for row in rows], [None, *range(2, 18)])
        self.assertEqual(rows[-1]['source'], 'bb6f7288f3ec9df94c3f3100b9a5b2df81df64d0')
        for scenario in ['missing17', 'reordered', 'duplicate-schema', 'duplicate-source', 'invalid-source', 'duplicate-output', 'outside-output', 'wrong-binary']:
            document = copy.deepcopy(self.document)
            rows = document['baselines']
            if scenario == 'missing17': rows.pop()
            elif scenario == 'reordered': rows[1], rows[2] = rows[2], rows[1]
            elif scenario == 'duplicate-schema': rows[2]['schema'] = rows[1]['schema']
            elif scenario == 'duplicate-source': rows[2]['source'] = rows[1]['source']
            elif scenario == 'invalid-source': rows[2]['source'] = 'unqualified'
            elif scenario == 'duplicate-output': rows[2]['binary'] = rows[1]['binary']
            elif scenario == 'outside-output': rows[2]['binary'] = '../outside/cratectld'
            elif scenario == 'wrong-binary': rows[2]['binary'] = '.cache/owned/another-command'
            with tempfile.TemporaryDirectory(prefix='cratectl-history-manifest-', dir=ROOT / '.cache') as temporary:
                owned = Path(temporary)
                path = owned / 'docs/qualification/upgrade-baselines.json'
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(document))
                with self.subTest(scenario=scenario), patch.object(builder, 'ROOT', owned), self.assertRaises(ValueError):
                    builder.baselines()

    def test_check_with_owned_git_standin_checks_all17_sources_without_native_resources(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['builder', '--check']), patch.object(builder.subprocess, 'check_output', return_value=HEAD + '\n') as revision, patch.object(builder.subprocess, 'run') as ancestry, patch.object(builder.platform, 'machine', side_effect=AssertionError('native setup before check returned')), patch('sys.stdout', output):
            builder.main()
        revision.assert_called_once_with(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True)
        self.assertEqual(ancestry.call_args_list, [call(['git', 'merge-base', '--is-ancestor', row['source'], HEAD], cwd=ROOT, check=True) for row in self.document['baselines']])
        self.assertIn('17 pinned historical sources are reachable; no build or worktree created', output.getvalue())

    def test_missing_history_refuses_before_any_native_build_or_worktree(self):
        source = self.document['baselines'][0]['source']
        command = ['git', 'merge-base', '--is-ancestor', source, HEAD]
        with patch.object(sys, 'argv', ['builder', '--check']), patch.object(builder.subprocess, 'check_output', return_value=HEAD + '\n'), patch.object(builder.subprocess, 'run', side_effect=subprocess.CalledProcessError(128, command)) as ancestry, patch.object(builder.platform, 'machine', side_effect=AssertionError('native setup after missing ancestry')), self.assertRaises(subprocess.CalledProcessError):
            builder.main()
        ancestry.assert_called_once_with(command, cwd=ROOT, check=True)


if __name__ == '__main__':
    unittest.main()
