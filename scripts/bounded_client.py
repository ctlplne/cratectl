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


def _owned_client_exit_code(process):
    # Observe exit without reaping the session leader. Its reserved PID keeps
    # the owned process-group identity from being reused before final signals.
    if process.returncode is not None:
        return process.returncode
    status=os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
    if status is None:
        return None
    return status.si_status if status.si_code==os.CLD_EXITED else -status.si_status


def _wait_for_owned_group_removal(group, timeout=3):
    # Darwin can return EPERM when a group contains only zombies. Do not treat
    # that errno as success: require observed group removal. Probe only with
    # signal zero, so PID reuse cannot turn this wait into a new kill request.
    deadline=time.monotonic()+timeout
    while True:
        try:
            os.killpg(group,0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass
        remaining=deadline-time.monotonic()
        if remaining<=0:
            return False
        time.sleep(min(.01,remaining))


def run_owned_client(argv, cwd, environment, timeout=120, output_limit=8 << 20, *, input_text=None, capture_limit=65536, poll_hook=None, output_sink=None):
    if os.name != 'posix' or not all(hasattr(os,name)for name in ['waitid','WNOWAIT','P_PID','WEXITED','WNOHANG','CLD_EXITED']) or not 0 < timeout <= 300 or not 1 <= output_limit <= 8 << 20 or not 1 <= capture_limit <= 8 << 20:
        raise ValueError('Owned client requires POSIX nonreaping exit observation and bounded time/output')
    if input_text is not None and (not isinstance(input_text,str) or len(input_text)>1<<20):
        raise ValueError('Owned client input must be bounded UTF-8 text')
    if poll_hook is not None and not callable(poll_hook):
        raise ValueError('Owned client poll hook must be callable')
    if output_sink is not None and not callable(getattr(output_sink,'write',None)):
        raise ValueError('Owned client output sink must accept private bytes')
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
                    if poll_hook is not None:
                        poll_hook()
                    remaining = deadline-time.monotonic()
                    if remaining <= 0:
                        raise ClientLimitError('Owned client deadline expired; remote mutation outcome is unconfirmed')
                    ready = selector.select(min(.025,remaining))
                    # The parent can write and exit between a selector timeout
                    # and exit observation. Read once after exit, even when the
                    # old readiness snapshot was empty. If a descendant holds
                    # an empty pipe open, stop here and let cleanup retire it.
                    exit_code=_owned_client_exit_code(process)
                    if not ready and exit_code is not None:
                        if not output_open:
                            break
                        try:
                            chunk = os.read(output.fileno(),65536)
                        except BlockingIOError:
                            break
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > output_limit:
                            raise ClientLimitError('Owned client exceeded its private output budget')
                        if output_sink is not None:
                            output_sink.write(chunk)
                        captured.extend(chunk)
                        if len(captured)>capture_limit: del captured[:-capture_limit]
                        continue
                    for _key, _events in ready:
                        chunk = os.read(output.fileno(),65536)
                        if not chunk:
                            selector.unregister(output); output_open = False
                            continue
                        total += len(chunk)
                        if total > output_limit:
                            raise ClientLimitError('Owned client exceeded its private output budget')
                        if output_sink is not None:
                            output_sink.write(chunk)
                        captured.extend(chunk)
                        if len(captured)>capture_limit: del captured[:-capture_limit]
                    exit_code=_owned_client_exit_code(process)
                    if exit_code is not None and not output_open:
                        break
                return exit_code, captured.decode('utf-8',errors='replace')
            finally:
                # Signal only descendants still in this owned process group,
                # never the caller. Explicit new sessions can escape.
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # Still require the final hard kill or confirmed removal.
                    # A denied graceful signal alone never establishes cleanup.
                    pass
                deadline=time.monotonic()+3
                while _owned_client_exit_code(process) is None:
                    remaining=deadline-time.monotonic()
                    if remaining<=0: break
                    time.sleep(min(.01,remaining))
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # The leader can now be reaped: no more termination
                    # signals follow, only bounded disappearance probes.
                    if _owned_client_exit_code(process) is not None:
                        process.wait(timeout=3)
                    if not _wait_for_owned_group_removal(process.pid):
                        raise
                process.wait(timeout=3)

