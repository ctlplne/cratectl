#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Install an authenticated cratectl binary archive on a matching Linux target."""

import argparse
import fcntl
import os
from pathlib import Path
import platform
import stat
import tarfile
import tempfile
import zlib

from verify_linux_candidate import require, verify


def install(archive, expected, directory):
    architectures = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}
    architecture = architectures.get(platform.machine())
    require(platform.system() == 'Linux' and architecture is not None,
            'the installer requires an x64 or ARM64 Linux target')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(directory, flags)
    try:
        info = os.fstat(parent)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                'the installation directory must be owned by the caller with mode 0700')
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Anchor staging and publication to the opened directory, including
        # when a parent path is moved or a symlink above it is retargeted.
        with tempfile.TemporaryDirectory(prefix='.cratectl-install-', dir=f'/proc/self/fd/{parent}') as folder:
            staging = Path(folder)
            manifest = verify(archive, expected, install_for='linux/' + architecture, staging=staging)
            name = 'cratectl-' + manifest['candidate'] + '-' + architecture
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('this candidate installation already exists')
            stage = os.open(staging, flags)
            try:
                os.fsync(stage)
            finally:
                os.close(stage)
            os.rename(staging.name, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        return directory / name
    finally:
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--sha256', required=True, help='Expected digest from a separately trusted source')
    parser.add_argument('--directory', type=Path, required=True, help='Existing, private installation directory')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        installed = install(args.archive, args.sha256, args.directory)
    except (OSError, ValueError, RecursionError, EOFError, tarfile.TarError, zlib.error) as error:
        raise SystemExit(f'Linux candidate installation failed: {error}') from None
    print(installed)


if __name__ == '__main__':
    main()
