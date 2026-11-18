#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Install checksum-pinned Terraform and OpenTofu binaries in a private CI directory."""
import argparse
import os
from pathlib import Path
import platform
import shutil
import stat
import tempfile
import zipfile

from fetch_archive import fetch
from terraform_provider_evidence import ARCHIVE_PINS, CLIENTS


ROOT = Path(__file__).resolve().parents[2]
MAX_BINARY = 160 << 20
HOST = {'amd64': 'x86_64', 'arm64': 'aarch64'}


def install(architecture):
    if platform.system() != 'Linux' or platform.machine() != HOST[architecture]:
        raise ValueError('native Linux infrastructure client architecture required')
    os.umask(0o077)
    cache = ROOT / '.cache'
    cache.mkdir(mode=0o700, exist_ok=True)
    if cache.is_symlink():
        raise ValueError('provider tool cache must be a real directory')
    folder = Path(tempfile.mkdtemp(prefix='cratectl-iac-native-', dir=cache))
    for name, version in CLIENTS.items():
        archive_name = f'{name}_{version}_linux_{architecture}.zip'
        base = (f'https://releases.hashicorp.com/terraform/{version}/' if name == 'terraform'
                else f'https://github.com/opentofu/opentofu/releases/download/v{version}/')
        fetch(ROOT, archive_name, base + archive_name, ARCHIVE_PINS[architecture][name], 64 << 20, os.environ)
        with zipfile.ZipFile(cache / archive_name) as archive:
            entries = archive.infolist()
            allowed = {'terraform': {'terraform', 'LICENSE.txt'}, 'tofu': {'tofu', 'LICENSE', 'README.md', 'CHANGELOG.md'}}[name]
            if len(entries) != len(allowed) or {entry.filename for entry in entries} != allowed:
                raise ValueError('unexpected stock infrastructure client archive inventory')
            member = archive.getinfo(name)
            mode = stat.S_IFMT(member.external_attr >> 16)
            if mode not in (0, stat.S_IFREG) or member.flag_bits & 1 or not 0 < member.file_size <= MAX_BINARY:
                raise ValueError('invalid stock infrastructure client executable')
            path = folder / name
            with archive.open(member) as source, path.open('xb') as target:
                shutil.copyfileobj(source, target, 128 << 10)
                if target.tell() != member.file_size:
                    raise ValueError('stock infrastructure client executable is incomplete')
                target.flush()
                os.fsync(target.fileno())
            path.chmod(0o700)
    return folder


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('architecture', choices=tuple(HOST))
    print(install(parser.parse_args().architecture))
