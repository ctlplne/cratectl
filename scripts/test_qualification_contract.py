#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Qualification artifact selection must stay inside its owned workspace."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qualification_contract import candidate_artifact_names, candidate_binary_directory

ROOT = Path(__file__).resolve().parents[1]


class CandidateArtifacts(unittest.TestCase):
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
