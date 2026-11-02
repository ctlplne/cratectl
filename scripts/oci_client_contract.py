# SPDX-License-Identifier: BUSL-1.1
"""Bounded observations of files returned by native package clients."""
import os
from pathlib import Path
import stat


def read_owned_file(root, path, limit):
    """Read one stable regular file without extra hardlinks or any symlink."""
    if type(limit) is not int or not 0 < limit <= 32 << 20:
        raise ValueError('native client observation requires a bounded byte limit')
    root, path = Path(root).absolute(), Path(path).absolute()
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        raise ValueError('native client observation is outside its private root') from None
    if not parts or any(part in ('.', '..') for part in parts):
        raise ValueError('native client observation has an invalid relative path')
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise ValueError('native client observation root could not be opened safely') from None
    descriptor = None
    try:
        for part in parts[:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError('native client observation is not one bounded regular file')
        chunks, length = [], 0
        while length <= limit:
            chunk = os.read(descriptor, min(1 << 20, limit + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        if length > limit or length != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError('native client observation changed or exceeded its byte budget')
        return b''.join(chunks)
    except OSError:
        raise ValueError('native client observation could not be opened safely') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)
