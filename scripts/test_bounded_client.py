#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from bounded_client import ClientLimitError, run_owned_client


class BoundedClient(unittest.TestCase):
    def test_nonzero_result_and_bounded_tail_are_not_success(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-client-') as directory:
            code, output = run_owned_client([sys.executable, '-c', 'import sys;print("owned"*20000);sys.exit(7)'], directory, dict(os.environ))
            self.assertEqual(code, 7)
            self.assertEqual(len(output), 65536)

    def test_deadline_stops_owned_descendants(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-client-') as directory:
            marker = Path(directory) / 'late-child'
            program = 'import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",' + repr('import time,signal;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(.6);Path(' + repr(str(marker)) + ').write_text("unexpected")') + ']);time.sleep(30)'
            with self.assertRaisesRegex(ClientLimitError, 'unconfirmed'):
                run_owned_client([sys.executable, '-c', program], directory, dict(os.environ), timeout=.2)
            time.sleep(.7)
            self.assertFalse(marker.exists(), 'owned descendant outlived cancellation')

    def test_output_budget_is_a_failure(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-client-') as directory:
            with self.assertRaisesRegex(ClientLimitError, 'output budget'):
                run_owned_client([sys.executable, '-c', 'import sys,time;sys.stdout.write("x"*10000);sys.stdout.flush();time.sleep(30)'], directory, dict(os.environ), output_limit=1024)


if __name__ == '__main__':
    unittest.main()
