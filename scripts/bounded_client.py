# SPDX-License-Identifier: BUSL-1.1
"""Bound an owned POSIX client process group and its private output."""
import os
import selectors
import signal
import subprocess
import tempfile
import time


class ClientLimitError(RuntimeError):
    pass


def run_owned_client(argv, cwd, environment, timeout=120, output_limit=8 << 20, *, input_text=None, capture_limit=65536):
    if os.name != 'posix' or not 0 < timeout <= 300 or not 1 <= output_limit <= 8 << 20 or not 1 <= capture_limit <= 8 << 20:
        raise ValueError('Owned client requires POSIX and bounded time/output')
    if input_text is not None and (not isinstance(input_text,str) or len(input_text)>1<<20):
        raise ValueError('Owned client input must be bounded UTF-8 text')
    input_bytes = input_text.encode('utf-8') if input_text is not None else b''
    if len(input_bytes)>1<<20:
        raise ValueError('Owned client input must be bounded UTF-8 text')
    # Private, unlinked seekable input cannot deadlock with a full output pipe.
    # Empty input supplies EOF; all these owned client commands are noninteractive.
    with tempfile.TemporaryFile(dir=cwd) as source:
        source.write(input_bytes); source.seek(0)
        process = subprocess.Popen([str(a) for a in argv], cwd=cwd, env=environment,
                                   stdin=source, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        with process.stdout as output, selectors.DefaultSelector() as selector:
            try:
                os.set_blocking(output.fileno(),False)
                selector.register(output,selectors.EVENT_READ)
                deadline = time.monotonic() + timeout
                captured = bytearray(); total = 0; output_open = True
                while True:
                    remaining = deadline-time.monotonic()
                    if remaining <= 0:
                        raise ClientLimitError('Owned client deadline expired; remote mutation outcome is unconfirmed')
                    ready = selector.select(min(.025,remaining))
                    for _key, _events in ready:
                        chunk = os.read(output.fileno(),65536)
                        if not chunk:
                            selector.unregister(output); output_open = False
                            continue
                        total += len(chunk)
                        if total > output_limit:
                            raise ClientLimitError('Owned client exceeded its private output budget')
                        captured.extend(chunk)
                        if len(captured)>capture_limit: del captured[:-capture_limit]
                    if process.poll() is not None and (not output_open or not ready):
                        break
                return process.returncode, captured.decode('utf-8',errors='replace')
            finally:
                # Signal only descendants still in this owned process group,
                # never the caller. Explicit new sessions can escape.
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

