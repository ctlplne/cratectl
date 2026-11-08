# SPDX-License-Identifier: BUSL-1.1
"""Owned shell/process stand-in for inherited signal behavior, never a SDK claim."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

from go_requirement_offline_native import ACK_PROBE_EXEC, PROBE_EXEC


class AcknowledgementTests(unittest.TestCase):
    def test_ack_wrapper_restores_default_sigpipe_before_owned_exec(self):
        # Python ignores SIGPIPE on startup. The ordinary wrapper preserves that;
        # the explicit acknowledgement-loss wrapper must reset it before exec.
        # The shell is a stand-in for the candidate CLI, without network tooling.
        with tempfile.TemporaryDirectory(prefix='cratectl-ack-standin-') as directory:
            for name, wrapper, expected in [('ordinary', PROBE_EXEC, 42), ('ack', ACK_PROBE_EXEC, -signal.SIGPIPE)]:
                probe = Path(directory) / (name + '.json')
                read_fd, write_fd = os.pipe()
                os.close(read_fd)
                try:
                    result = subprocess.run([sys.executable, '-c', wrapper, str(probe), 'print("{}")',
                                             '/bin/sh', '-c', 'kill -PIPE $$; exit 42'], stdout=write_fd,
                                            stderr=subprocess.PIPE, timeout=10, check=False)
                finally:
                    os.close(write_fd)
                self.assertEqual(result.returncode, expected, result.stderr[:1024])
                self.assertEqual(json.loads(probe.read_bytes()), {})


if __name__ == '__main__':
    unittest.main()
