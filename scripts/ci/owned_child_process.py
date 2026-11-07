# SPDX-License-Identifier: BUSL-1.1
"""Signal only an observed owned CLI descendant, using a stable Linux pidfd."""
import os
from pathlib import Path
import re
import signal
import stat


def _status(proc, pid):
    try:
        with (proc / str(pid) / 'status').open('rb') as source:
            raw = source.read((16 << 10) + 1)
    except OSError:
        raise ValueError('Owned process identity is no longer available') from None
    if len(raw) > 16 << 10:
        raise ValueError('Owned process status exceeds its bound')
    selected = {}
    for line in raw.splitlines():
        key, _, value = line.partition(b':')
        if key in (b'Uid', b'PPid'):
            if key in selected:
                raise ValueError('Owned process status is ambiguous')
            selected[key] = value.split()
    if set(selected) != {b'Uid', b'PPid'} or len(selected[b'Uid']) != 4 or len(selected[b'PPid']) != 1:
        raise ValueError('Owned process identity is incomplete')
    fields = selected[b'Uid'] + selected[b'PPid']
    if any(not re.fullmatch(rb'[0-9]{1,10}', field) for field in fields):
        raise ValueError('Owned process identity is not canonical')
    return [int(v) for v in selected[b'Uid']], int(selected[b'PPid'][0])


def validate_owned_cli(pid, launcher, executable, uid, namespace, proc=Path('/proc')):
    """Read-only validation; proc can be a filesystem stand-in in local tests."""
    if (type(pid) is not int or not 1 < pid < 1 << 31 or type(launcher) is not int
            or not 1 < launcher < 1 << 31 or type(uid) is not int or uid < 1
            or type(namespace) is not int or namespace < 1):
        raise ValueError('Owned CLI requires exact ordinary-user process bindings')
    proc = Path(proc)

    def identity():
        users, parent = _status(proc, pid)
        try:
            bound = (os.path.samefile(proc / str(pid) / 'exe', executable)
                     and (proc / str(pid) / 'ns/net').stat().st_ino == namespace)
        except OSError:
            raise ValueError('Owned CLI executable or network is no longer available') from None
        if users != [uid] * 4 or not bound:
            raise ValueError('Observed process is not the owned CLI in its verified empty network')
        return parent

    parent = identity()
    seen = {pid}
    current = pid
    for _ in range(9):
        if current == launcher:
            identity()
            return pid
        if parent < 2 or parent in seen:
            break
        seen.add(parent)
        current = parent
        _, parent = _status(proc, current)
    raise ValueError('Observed CLI is not a bounded descendant of the owned launcher')


def kill_owned_cli(launcher, identity_file, executable, namespace):
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise ValueError('Native CLI fault qualification requires Linux process descriptors')
    path = Path(identity_file)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077 or before.st_uid != os.getuid()
            or before.st_nlink != 1 or not 1 <= before.st_size <= 16):
        raise ValueError('Owned CLI PID record is unavailable or not private')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        actual = os.fstat(source.fileno())
        raw = source.read(17)
        after = os.fstat(source.fileno())
    if (not re.fullmatch(rb'[1-9][0-9]{0,9}\n', raw) or not os.path.samestat(before, actual)
            or not os.path.samestat(after, path.lstat()) or actual.st_size != after.st_size
            or actual.st_mtime_ns != after.st_mtime_ns or after.st_nlink != 1):
        raise ValueError('Owned CLI PID record changed or is ambiguous')
    pid = int(raw)
    if not 1 < pid < 1 << 31:
        raise ValueError('Owned CLI PID exceeds its canonical process bound')
    # The descriptor pins the process before validation and signalling. A reused
    # numeric PID cannot cause a signal to be delivered to another process.
    process = os.pidfd_open(pid)
    try:
        validate_owned_cli(pid, launcher.pid, executable, os.getuid(), namespace)
        if launcher.poll() is not None:
            raise ValueError('Owned CLI launcher already terminated')
        signal.pidfd_send_signal(process, signal.SIGKILL)
    finally:
        os.close(process)
    return pid
