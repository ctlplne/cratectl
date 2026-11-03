#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Invalid profiles cannot become empty passing campaigns or touch a database."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('conformance.py')


class ConformanceProfile(unittest.TestCase):
    def test_unknown_profile_and_flags_fail_before_reading_database_configuration(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-profile-') as directory:
            env = dict(os.environ, CRATECTL_CONFORMANCE_DATABASE_FILE=str(Path(directory) / 'must-not-exist'))
            for arguments in [['unimplemented-profile'], ['gradle', '--require-cleen-build']]:
                result = subprocess.run([sys.executable, SCRIPT, *arguments], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertIn('usage:', result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assertNotIn('must-not-exist', result.stderr)

    def test_help_needs_no_database_or_client_runtime(self):
        result = subprocess.run([sys.executable, SCRIPT, '--help'], env=dict(os.environ, CRATECTL_CONFORMANCE_DATABASE_FILE='/nonexistent/cratectl-profile'), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn('gradle', result.stdout)
        self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
