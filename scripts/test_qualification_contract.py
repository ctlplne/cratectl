#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Qualification artifact selection must stay inside its owned workspace."""
import os
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

from qualification_contract import CURRENT_SCHEMA, candidate_artifact_names, candidate_binary_directory, validate_historical_build, dotnet_sdk_pin

ROOT = Path(__file__).resolve().parents[1]


class CandidateArtifacts(unittest.TestCase):
    def test_every_pinned_historical_lifecycle_input_is_admitted_before_resource_setup(self):
        manifest=json.loads((ROOT/'docs/qualification/upgrade-baselines.json').read_text())
        # The real driver parses before loading binaries, credentials or opening
        # a database. --help makes this a local, resource-free CLI contract test.
        for baseline in [row['schema'] for row in manifest['baselines'] if row['schema'] is not None]:
            with self.subTest(baseline=baseline):
                result=subprocess.run([sys.executable,ROOT/'scripts/conformance_lifecycle.py','--baseline-version',str(baseline),'--help'],capture_output=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr.decode())
        for baseline in [0,1,CURRENT_SCHEMA,CURRENT_SCHEMA+1]:
            with self.subTest(rejected=baseline):
                result=subprocess.run([sys.executable,ROOT/'scripts/conformance_lifecycle.py','--baseline-version',str(baseline),'--help'],capture_output=True,timeout=5)
                self.assertEqual(result.returncode,2)
                self.assertIn(b'invalid choice',result.stderr)

    def test_dotnet_sdk_selection_requires_an_exact_stable_pin(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-sdk-pin-',dir=ROOT/'.cache') as temporary:
            root=Path(temporary);path=root/'global.json'
            sdk={'version':'10.0.403','rollForward':'disable','allowPrerelease':False}
            path.write_text(json.dumps({'sdk':sdk}));self.assertEqual(dotnet_sdk_pin(root),'10.0.403')
            for change in [{'version':'10.0.x'},{'version':'10.0.403-rc.1'},{'version':'11.0.100'},
                           {'rollForward':'latestPatch'},{'allowPrerelease':True},{'allowPrerelease':0},{'paths':['/foreign/sdk']}]:
                path.write_text(json.dumps({'sdk':{**sdk,**change}}))
                with self.subTest(change=change),self.assertRaises(ValueError):dotnet_sdk_pin(root)
            for document in [None, 1, [], 'sdk', {}, {'sdk':None}, {'sdk':sdk,'other':{}}]:
                path.write_text(json.dumps(document))
                with self.subTest(document=document),self.assertRaises(ValueError):dotnet_sdk_pin(root)
            path.write_text('{')
            with self.assertRaises(ValueError):dotnet_sdk_pin(root)
            path.write_text(' '*4097)
            with self.assertRaises(ValueError):dotnet_sdk_pin(root)

    def test_historical_identity_rejects_wrong_source_dirty_and_cross_built_bytes(self):
        source = '1' * 40
        values = {'vcs': 'git', 'vcs.revision': source, 'vcs.modified': 'false', 'GOOS': 'linux', 'GOARCH': 'amd64'}
        def metadata(settings):
            return '\n'.join('\tbuild\t' + key + '=' + value for key, value in settings.items())
        self.assertEqual(validate_historical_build(metadata(values), source, 'linux', 'amd64'), values)
        for key, value in [('vcs.revision', '2' * 40), ('vcs.modified', 'true'), ('GOOS', 'darwin'), ('GOARCH', 'arm64')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_historical_build(metadata({**values, key: value}), source, 'linux', 'amd64')
        with self.assertRaises(ValueError):
            validate_historical_build('', source, 'linux', 'amd64')

    def test_active_default_and_explicit_candidate_precedence(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(candidate_binary_directory(), ROOT / 'bin')
            self.assertEqual(candidate_artifact_names(), ['bin/cratectld', 'bin/cratectl'])
        with patch.dict(os.environ, {'CRATECTL_QUALIFICATION_BIN_DIR': '.cache/candidate-production'}):
            self.assertEqual(candidate_artifact_names(), ['.cache/candidate-production/cratectld', '.cache/candidate-production/cratectl'])
            self.assertEqual(candidate_binary_directory('.cache/candidate-race'), ROOT / '.cache/candidate-race')

    def test_sibling_absolute_and_symlink_escape_are_rejected(self):
        with self.assertRaises(ValueError):
            candidate_binary_directory(ROOT.parent / 'sibling/bin')
        with self.assertRaises(ValueError):
            candidate_binary_directory('../sibling/bin')
        with tempfile.TemporaryDirectory(prefix='cratectl-selector-', dir=ROOT / '.cache') as temporary:
            link = Path(temporary) / 'escaped'
            link.symlink_to('/private/tmp', target_is_directory=True)
            with self.assertRaises(ValueError):
                candidate_binary_directory(link)


if __name__ == '__main__':
    unittest.main()
