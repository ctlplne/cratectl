# SPDX-License-Identifier: BUSL-1.1
"""Bound an owned POSIX client process group and its private output."""
import os
import signal
import subprocess
import tempfile
import time


class ClientLimitError(RuntimeError):
    pass


def run_owned_client(argv, cwd, environment, timeout=120, output_limit=8 << 20):
    if os.name != 'posix' or not 0 < timeout <= 300 or not 1 <= output_limit <= 8 << 20:
        raise ValueError('Owned client requires POSIX and bounded time/output')
    with tempfile.TemporaryFile(dir=cwd) as output:
        process = subprocess.Popen([str(a) for a in argv], cwd=cwd, env=environment,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + timeout
            while True:
                if os.fstat(output.fileno()).st_size > output_limit:
                    raise ClientLimitError('Owned client exceeded its private output budget')
                if process.poll() is not None:
                    break
                if time.monotonic() >= deadline:
                    raise ClientLimitError('Owned client deadline expired; remote mutation outcome is unconfirmed')
                time.sleep(.025)
            size = os.fstat(output.fileno()).st_size
            if size > output_limit:
                raise ClientLimitError('Owned client exceeded its private output budget')
            output.seek(max(0, size - 65536))
            return process.returncode, output.read(65536).decode('utf-8', errors='replace')
        finally:
            # Every descendant was started in this owned session; never signal
            # the caller's process group or another workspace's services.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)

