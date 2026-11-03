# SPDX-License-Identifier: BUSL-1.1
"""Bounded observations of files returned by native package clients."""
import os
import io
from pathlib import Path
import stat
import re
import tempfile
import tarfile


def read_owned_tar_file(raw, name, limit):
    """Observe one regular client-copied file without extracting its archive."""
    if not isinstance(raw, bytes) or len(raw) > 8 << 20 or type(limit) is not int or not 0 < limit <= 4 << 20 or not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}', name):
        raise ValueError('native tar observation requires bounded owned input')
    # Preflight physical headers before tarfile processes PAX/GNU metadata.
    # Forged lengths cannot drive unbounded reads, offsets or sparse maps.
    offset, headers, metadata = 0, 0, 0
    ended = False
    while offset + 512 <= len(raw):
        block = raw[offset:offset + 512]
        if not any(block):
            if len(raw) - offset < 1024 or any(raw[offset:]):
                raise ValueError('native tar observation has ambiguous trailing bytes')
            ended = True
            break
        headers += 1
        if headers > 16 or block[156:157] not in (b'0', b'\0', b'x', b'g', b'L'):
            raise ValueError('native tar observation contains extra or special entries')
        field = block[124:136]
        if field[0] & 0x80:
            if field[0] & 0x40:
                raise ValueError('native tar observation has an invalid size')
            size = int.from_bytes(bytes([field[0] & 0x7f]) + field[1:], 'big')
        else:
            field = field.rstrip(b'\0 ').lstrip(b' \0')
            if field and not re.fullmatch(rb'[0-7]{1,12}', field):
                raise ValueError('native tar observation has an invalid size')
            size = int(field or b'0', 8)
        following = offset + 512 + ((size + 511) // 512) * 512
        if following > len(raw):
            raise ValueError('native tar observation is truncated')
        if block[156:157] in (b'x', b'g', b'L'):
            metadata += size
            if metadata > 65536 or b'GNU.sparse.' in raw[offset + 512:offset + 512 + size]:
                raise ValueError('native tar observation has unsupported metadata')
        elif size > limit:
            raise ValueError('native tar observation exceeds its file byte budget')
        offset = following
    if not ended:
        raise ValueError('native tar observation has no complete end marker')
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            members = archive.getmembers()
            if len(members) != 1:
                raise ValueError('native tar observation must contain exactly one file')
            member = members[0]
            if member.name != name or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.linkname or member.sparse is not None or not 0 <= member.size <= limit:
                raise ValueError('native tar observation is not the exact owned regular file')
            source = archive.extractfile(member)
            if source is None:
                raise ValueError('native tar observation has no file bytes')
            with source:
                body = source.read(limit + 1)
            if len(body) != member.size or len(body) > limit:
                raise ValueError('native tar observation has mismatched file length')
            return body
    except (tarfile.TarError, OSError, OverflowError):
        raise ValueError('native tar observation could not be parsed safely') from None


def new_podman_runroot(run):
    """Allocate one private project directory below Podman4's 50-byte limit."""
    if not re.fullmatch('[0-9a-f]{10}', run):
        raise ValueError('Podman runtime directory requires an owned run identity')
    path = Path(tempfile.mkdtemp(prefix='cratectl-podman-' + run + '-', dir='/tmp'))
    if len(os.fsencode(path)) > 50:
        path.rmdir()
        raise ValueError('Podman runtime directory exceeds the native path budget')
    info = path.lstat()
    return path, (info.st_dev, info.st_ino)


def validate_podman_runroot(path, identity):
    """Bind privileged cleanup to the exact directory allocated by this run."""
    path = Path(path)
    if path.parent != Path('/tmp') or not re.fullmatch(r'cratectl-podman-[0-9a-f]{10}-[a-z0-9_]{8}', path.name) or len(os.fsencode(path)) > 50:
        raise ValueError('Podman runtime cleanup target is not an owned directory')
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
        raise ValueError('Podman runtime cleanup target changed identity')


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
