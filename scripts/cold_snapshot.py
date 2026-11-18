#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Pair a verified PostgreSQL 16 physical backup with stopped native cratectl state."""

import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from bounded_client import run_owned_client
from verify_linux_candidate import SHA256, require, unique_members


PROFILE = 'cratectl-cold-physical-snapshot-v1'
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
DIR = READ | os.O_DIRECTORY
MAX_FILE = 1 << 30
MAX_BYTES = 16 << 30
MAX_ENTRIES = 10000
MAX_MANIFEST = 4 << 20
NAME = re.compile(r'[A-Za-z0-9._-]{1,128}')
TENANT = re.compile(r'[a-z][a-z0-9-]{0,62}')
REQUIRED = {'database/PG_VERSION', 'database/backup_manifest', 'installation/runtime.json',
            'installation/ca.crt', 'installation/server.crt', 'installation/server.key',
            'installation/client.json', 'installation/workers.json', 'installation/admin.token',
            'installation/worker.token', 'pagination.key', 'journal-checkpoint.json'}
ROOTS = {'database', 'installation'}
SNAPSHOT = 'snapshot.json'


def private_directory(fd):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            'snapshot directories must be owned by the caller and private')


def safe_parts(name):
    require(type(name) is str and 0 < len(name) <= 1024, 'invalid snapshot entry name')
    parts = name.split('/')
    require(len(parts) <= 12 and all(NAME.fullmatch(part) and part not in ('.', '..') for part in parts),
            'unsupported snapshot path')
    return parts


def transfer(fd, name, *, output=None, cap=MAX_FILE):
    with os.fdopen(os.open(name, READ, dir_fd=fd), 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and not before.st_mode & 0o077
                and 0 <= before.st_size <= cap, 'snapshot file is not an owned bounded private regular file')
        checksum = hashlib.sha256()
        length = 0
        while block := source.read(min(128 << 10, cap - length + 1)):
            length += len(block)
            require(length <= cap, 'snapshot file exceeds its size bound')
            checksum.update(block)
            if output is not None:
                output.write(block)
        after = os.fstat(source.fileno())
        require(length == before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns,
                'snapshot file changed while being copied')
    return {'bytes': length, 'sha256': checksum.hexdigest()}


def read_small(path, cap, directory=None):
    with os.fdopen(os.open(path, READ, dir_fd=directory), 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077
                and 0 < info.st_size <= cap, 'owned private snapshot metadata required')
        raw = source.read(cap + 1)
    require(len(raw) == info.st_size, 'snapshot metadata changed or exceeds its size bound')
    return raw


def encode(manifest):
    return (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode('ascii')


def write_stream(fd, name, path, cap):
    with path.open('xb') as output:
        value = transfer(fd, name, output=output, cap=cap)
        output.flush()
        os.fsync(output.fileno())
    return value


def sync_dir(path):
    fd = os.open(path, DIR)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Inventory:
    def __init__(self):
        self.directories = []
        self.files = {}
        self.bytes = 0
        self.cas_files = 0

    def record(self, path, reference):
        self.bytes += reference['bytes']
        require(self.bytes <= MAX_BYTES, 'snapshot exceeds its aggregate byte bound')
        parts = safe_parts(path)
        if len(parts) >= 4 and parts[:2] == ['installation', 'objects'] and parts[3] == 'sha256':
            require(len(parts) == 6 and TENANT.fullmatch(parts[2]) and SHA256.fullmatch(parts[5])
                    and parts[4] == parts[5][:2] and reference['sha256'] == parts[5],
                    'content-addressed bytes differ from their path')
            self.cas_files += 1
        self.files[path] = reference
        self.limit()

    def limit(self):
        require(len(self.files) + len(self.directories) <= MAX_ENTRIES, 'snapshot exceeds its entry bound')

    def tree(self, fd, prefix, destination):
        original = os.fstat(fd)
        if prefix:
            private_directory(fd)
            self.directories.append(prefix)
            self.limit()
            if destination is not None:
                destination.mkdir(mode=0o700)
        with os.scandir(fd) as entries:
            for entry in entries:
                name = entry.name
                if not prefix and name == SNAPSHOT:
                    continue
                relative = prefix + '/' + name if prefix else name
                safe_parts(relative)
                target = destination / name if destination is not None else None
                if entry.is_dir(follow_symlinks=False):
                    nested = os.open(name, DIR, dir_fd=fd)
                    try:
                        self.tree(nested, relative, target)
                    finally:
                        os.close(nested)
                else:
                    cap = min(MAX_FILE, MAX_BYTES - self.bytes)
                    ref = transfer(fd, name, cap=cap) if target is None else write_stream(fd, name, target, cap)
                    self.record(relative, ref)
        require(original.st_mtime_ns == os.fstat(fd).st_mtime_ns, 'snapshot directory changed during enumeration')
        if destination is not None:
            sync_dir(destination)

    def manifest(self):
        require(REQUIRED <= set(self.files), 'snapshot is missing required database, credential or checkpoint files')
        require(ROOTS <= set(self.directories) and all(
            path.split('/')[0] in ROOTS for path in self.directories), 'snapshot directory inventory differs')
        require(all(path in ('pagination.key', 'journal-checkpoint.json') or path.split('/')[0] in ROOTS
                    for path in self.files), 'snapshot file inventory differs')
        return {'schema': 1, 'profile': PROFILE, 'directories': sorted(self.directories), 'files': self.files,
                'bytes': self.bytes, 'verified_cas_files': self.cas_files}


def check_supported_inputs(root):
    require(read_small(root / 'database/PG_VERSION', 8).strip() == b'16', 'a PostgreSQL 16 physical backup is required')
    key = read_small(root / 'pagination.key', 128)
    encoded = key.strip()
    require(re.fullmatch(rb'[A-Za-z0-9_-]{43}', encoded) is not None
            and len(base64.urlsafe_b64decode(encoded + b'=')) == 32, 'a valid cratectl pagination key file is required')
    observed = root / 'installation/pagination.key'
    if observed.exists():
        require(read_small(observed, 128).strip() == encoded, 'installation and separately retained pagination keys differ')
    journal = json.loads(read_small(root / 'journal-checkpoint.json', 1 << 20), object_pairs_hook=unique_members)
    require(type(journal) is list and len(journal) <= 4096, 'invalid journal checkpoint inventory')
    tenants = set()
    for entry in journal:
        require(type(entry) is dict and set(entry) == {'tenant', 'event_count', 'last_sequence', 'last_hash'}
                and type(entry['tenant']) is str and TENANT.fullmatch(entry['tenant'])
                and type(entry['event_count']) is int and type(entry['last_sequence']) is int
                and 0 < entry['event_count'] <= entry['last_sequence'] < 1 << 63
                and type(entry['last_hash']) is str and SHA256.fullmatch(entry['last_hash'])
                and entry['tenant'] not in tenants, 'invalid journal checkpoint identity')
        tenants.add(entry['tenant'])
    with tempfile.TemporaryDirectory(prefix='cratectl-cold-verify-') as work:
        code, output = run_owned_client(['pg_verifybackup', '--exit-on-error', root.absolute() / 'database'],
                                        work, os.environ, timeout=300, output_limit=128 << 10)
    require(code == 0 and 'backup successfully verified' in output, 'stock pg_verifybackup failed')


def capture(database, installation, pagination, journal, output):
    with tempfile.TemporaryDirectory(prefix='cratectl-cold-snapshot-', dir=output.parent) as work:
        staging = Path(work) / 'snapshot'
        staging.mkdir(mode=0o700)
        inventory = Inventory()
        for prefix, source in [('database', database), ('installation', installation)]:
            fd = os.open(source, DIR)
            try:
                inventory.tree(fd, prefix, staging / prefix)
            finally:
                os.close(fd)
        for name, source, cap in [('pagination.key', pagination, 128), ('journal-checkpoint.json', journal, 1 << 20)]:
            inventory.record(name, write_stream(None, source, staging / name, cap))
        prepared = inventory.manifest()
        check_supported_inputs(staging)
        encoded = encode(prepared)
        require(len(encoded) <= MAX_MANIFEST, 'snapshot manifest exceeds its size bound')
        with (staging / SNAPSHOT).open('xb') as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        sync_dir(staging)
        require(not output.exists() and not output.is_symlink(), 'snapshot output already exists')
        staging.rename(output)
        sync_dir(output.parent)
        return hashlib.sha256(encoded).hexdigest()


def verify(root, expected):
    require(type(expected) is str and SHA256.fullmatch(expected), 'independently trusted snapshot SHA-256 required')
    fd = os.open(root, DIR)
    try:
        private_directory(fd)
        raw = read_small(SNAPSHOT, MAX_MANIFEST, directory=fd)
        require(hashlib.sha256(raw).hexdigest() == expected, 'snapshot manifest SHA-256 differs')
        inventory = Inventory()
        inventory.tree(fd, '', None)
        observed = inventory.manifest()
        require(encode(observed) == raw, 'captured snapshot file or directory inventory differs')
        check_supported_inputs(root)
        require(os.path.samestat(os.stat(root, follow_symlinks=False), os.fstat(fd)), 'snapshot directory changed during verification')
        return observed
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    pair = actions.add_parser('capture')
    for name in ('database', 'installation', 'pagination-key', 'journal-checkpoint', 'directory'):
        pair.add_argument('--' + name, type=Path, required=True)
    check = actions.add_parser('verify')
    check.add_argument('directory', type=Path)
    check.add_argument('--sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == 'verify':
            observed = verify(args.directory, args.sha256)
            print(json.dumps({'files': len(observed['files']), 'bytes': observed['bytes'],
                              'verified_cas_files': observed['verified_cas_files']}))
        else:
            fd = os.open(args.directory.parent, DIR)
            try:
                private_directory(fd)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                print(capture(args.database, args.installation, args.pagination_key,
                              args.journal_checkpoint, args.directory))
            finally:
                os.close(fd)
    except (OSError, ValueError, RuntimeError, RecursionError, TypeError, KeyError) as error:
        raise SystemExit(f'Cold snapshot failed: {error}') from None


if __name__ == '__main__':
    main()
