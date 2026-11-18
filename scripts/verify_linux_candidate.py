#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Check a Linux candidate archive against a separately trusted SHA-256."""

import argparse
from contextlib import nullcontext
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tarfile
import tempfile
import zlib

from package_linux import BINARIES, MAX_BINARY, SOURCE_INPUTS


MAX_MANIFEST = 64 << 10
MAX_ARCHIVE = 2 * MAX_BINARY + (1 << 20)
MACHINES = {'linux/amd64': 62, 'linux/arm64': 183}
SHA256 = re.compile('[a-f0-9]{64}')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def copy_bounded(source, destination, maximum):
    digest = hashlib.sha256()
    remaining = maximum
    while block := source.read(min(128 << 10, remaining + 1)):
        require(len(block) <= remaining, 'archive exceeds its byte limit')
        remaining -= len(block)
        digest.update(block)
        destination.write(block)
    destination.seek(0)
    return digest.hexdigest()


def unique_members(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), 'manifest contains a duplicate JSON field')
    return result


def manifest_from(raw):
    manifest = json.loads(raw.decode('ascii'), object_pairs_hook=unique_members)
    fields = {'schema', 'profile', 'candidate', 'go_version', 'platform', 'binaries', 'source_sha256', 'distribution_approved'}
    require(type(manifest) is dict and set(manifest) == fields and type(manifest['schema']) is int and manifest['schema'] == 1
            and manifest['profile'] == 'cratectl-linux-binary-candidate-v1' and manifest['distribution_approved'] is False,
            'manifest profile or scope is invalid')
    require(type(manifest['candidate']) is str and re.fullmatch('[a-f0-9]{40}', manifest['candidate'])
            and type(manifest['go_version']) is str and re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', manifest['go_version'])
            and type(manifest['platform']) is str and manifest['platform'] in MACHINES, 'manifest source identity is invalid')
    files = manifest['binaries']
    require(type(files) is dict and set(files) == set(BINARIES), 'manifest executable inventory differs')
    for value in files.values():
        require(type(value) is dict and set(value) == {'bytes', 'sha256'} and type(value['bytes']) is int
                and 64 <= value['bytes'] <= MAX_BINARY and type(value['sha256']) is str and SHA256.fullmatch(value['sha256']),
                'manifest executable identity is invalid')
    hashes = manifest['source_sha256']
    require(type(hashes) is dict and set(hashes) == set(SOURCE_INPUTS)
            and all(type(value) is str and SHA256.fullmatch(value) for value in hashes.values()), 'manifest source inventory differs')
    return manifest


def entry(stream, name, mode, maximum):
    header = stream.read(tarfile.BLOCKSIZE)
    require(len(header) == tarfile.BLOCKSIZE and header[156:157] == b'0' and header[257:265] == b'ustar\x0000',
            'archive requires canonical regular USTAR members')
    item = tarfile.TarInfo.frombuf(header, 'ascii', 'strict')
    require(item.name == name and not (item.linkname or item.uname or item.gname)
            and item.mode == mode and item.uid == item.gid == item.mtime == 0
            and 0 < item.size <= maximum, 'archive member differs from expected identity: ' + name)
    return item


def padding(stream, size):
    count = -size % tarfile.BLOCKSIZE
    require(stream.read(count) == bytes(count), 'archive member has invalid padding')


def elf_digest(stream, size, machine, output=None):
    header = stream.read(64)
    require(len(header) == 64 and header[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', header, 18)[0] == machine,
            'executable ELF class or architecture differs')
    digest = hashlib.sha256(header)
    if output is not None:
        output.write(header)
    remaining = size - len(header)
    while remaining:
        block = stream.read(min(remaining, 128 << 10))
        require(block, 'executable member is truncated')
        remaining -= len(block)
        digest.update(block)
        if output is not None:
            output.write(block)
    return digest.hexdigest()


def verify(path, expected, *, install_for=None, staging=None):
    require(isinstance(expected, str) and SHA256.fullmatch(expected), 'a separately trusted lowercase SHA-256 is required')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with (os.fdopen(os.open(path, flags), 'rb') as source, tempfile.TemporaryFile() as snapshot,
          tempfile.TemporaryFile() as unpacked):
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_ARCHIVE, 'a bounded regular candidate archive is required')
        require(copy_bounded(source, snapshot, MAX_ARCHIVE) == expected, 'compressed archive SHA-256 differs')
        with gzip.GzipFile(fileobj=snapshot, mode='rb') as zipped:
            copy_bounded(zipped, unpacked, MAX_ARCHIVE)
        manifest_entry = entry(unpacked, 'manifest.json', 0o644, MAX_MANIFEST)
        manifest_bytes = unpacked.read(manifest_entry.size)
        manifest = manifest_from(manifest_bytes)
        padding(unpacked, manifest_entry.size)
        if install_for is not None:
            require(manifest['platform'] == install_for, 'archive platform differs from this Linux target')
        for name in BINARIES:
            ref = manifest['binaries'][name]
            item = entry(unpacked, name, 0o755, MAX_BINARY)
            target = (staging / name).open('xb') if staging is not None else nullcontext()
            with target as binary:
                require(item.size == ref['bytes']
                        and elf_digest(unpacked, item.size, MACHINES[manifest['platform']], binary) == ref['sha256'],
                        'archive executable bytes differ: ' + name)
                if binary is not None:
                    binary.flush()
                    os.fchmod(binary.fileno(), 0o755)
                    os.fsync(binary.fileno())
            padding(unpacked, item.size)
        terminator = 2 * tarfile.BLOCKSIZE
        trailer = terminator + (-(unpacked.tell() + terminator) % tarfile.RECORDSIZE)
        require(unpacked.read(trailer) == bytes(trailer) and not unpacked.read(1), 'archive terminator or trailing members differ')
        if staging is not None:
            with (staging / 'manifest.json').open('xb') as metadata:
                metadata.write(manifest_bytes)
                metadata.flush()
                os.fchmod(metadata.fileno(), 0o644)
                os.fsync(metadata.fileno())
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--sha256', required=True, help='Expected digest from a separately trusted source')
    args = parser.parse_args()
    try:
        manifest = verify(args.archive, args.sha256)
    except (OSError, ValueError, RecursionError, EOFError, tarfile.TarError, zlib.error) as error:
        raise SystemExit(f'Linux candidate verification failed: {error}') from None
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
