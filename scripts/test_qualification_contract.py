#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Qualification artifact selection must stay inside its owned workspace."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qualification_contract import candidate_artifact_names, candidate_binary_directory, validate_historical_build

ROOT = Path(__file__).resolve().parents[1]


class CandidateArtifacts(unittest.TestCase):
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
