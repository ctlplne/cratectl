#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Install the reviewed stock Cargo SDK without running bundled install scripts."""
import argparse
import os
from pathlib import Path
import platform
import shutil
import tarfile
import tempfile

if __package__:
    from .fetch_archive import fetch
else:
    from fetch_archive import fetch

ROOT = Path(__file__).resolve().parents[2]
VERSION = '1.100.0'
SOURCE = 'https://static.rust-lang.org/dist/2026-11-12/'
TARGETS = {
    'amd64': ('Linux', 'x86_64', 'x86_64-unknown-linux-gnu'),
    'arm64': ('Linux', 'aarch64', 'aarch64-unknown-linux-gnu'),
    'darwin-arm64': ('Darwin', 'arm64', 'aarch64-apple-darwin'),
}
PINS = {
    'amd64': {
        'cargo': '7e29ce07d7c6e92d1826870575ba27d57fff6cb3e754aa57d99099cb88fab35d',
        'rustc': 'f1d0b1dec81dab6f523cd098507763487b0d4bd7fd2c87582f154128719be03b',
        'rust-std': '4591b6486594ded52ecd6135db95bf9355bbd3ca7a380888b141528bbcf9a5d4',
    },
    'arm64': {
        'cargo': 'd07ee80eb6ba3c5845c554ac88086e1ff5d63f83d99c3c09cb32504cbedd6844',
        'rustc': 'fcbfa5b8a0cb28f0c4edfb6dda6910ee910993db31f05258613f5cd5b851263a',
        'rust-std': 'c73f62fbe5d837f9807ed9e0076575dd8d3475c79af2b30e3570d328e6713f8f',
    },
    'darwin-arm64': {
        'cargo': '7e18265d2d2cda8dec6cac4d0faa3bbafe927b401e5185350abc7d669f9adafb',
        'rustc': '3fcd7f1709f62dda58bf4db2dcfd630a451e750aadaaa551a21cc4a627a37b4c',
        'rust-std': '9345645b6f56eea28bf8cc2c0f628a61d507a688f91c1bec5ae6bfad216a16c7',
    },
}
LIMITS = {'cargo': 24 << 20, 'rustc': 128 << 20, 'rust-std': 64 << 20}


def install(arch):
    system, machine, target = TARGETS[arch]
    if (platform.system(), platform.machine()) != (system, machine):
        raise ValueError('the pinned Cargo SDK requires a native host')
    os.umask(0o077)
    cache = ROOT / '.cache'
    cache.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='cratectl-rust-stage-', dir=cache) as temporary:
        stage = Path(temporary)
        sdk = stage / 'sdk'
        for component, digest in PINS[arch].items():
            base = f'{component}-{VERSION}-{target}'
            archive = base + '.tar.xz'
            fetch(ROOT, archive, SOURCE + archive, digest, LIMITS[component], os.environ)
            part = 'rust-std-' + target if component == 'rust-std' else component
            with tarfile.open(ROOT / '.cache' / archive, mode='r:xz') as bundle:
                total = 0
                for number, entry in enumerate(bundle, 1):
                    total += entry.size
                    if number > 4096 or total > 768 << 20:
                        raise ValueError('stock Rust component exceeds its unpacked inventory budget')
                    members = entry.name.split('/')
                    if len(members) < 3 or members[:2] != [base, part] or members[2] not in ('bin', 'lib'):
                        continue
                    if not entry.isfile() and not entry.isdir():
                        raise ValueError('stock SDK paths must be regular files or directories')
                    bundle.extract(entry, stage, set_attrs=True, filter='data')
            directory = stage / base / part
            for name in ('bin', 'lib'):
                if (directory / name).is_dir():
                    shutil.copytree(directory / name, sdk / name, dirs_exist_ok=True)
        if not all((sdk / 'bin' / name).is_file() for name in ('cargo', 'rustc')):
            raise ValueError('stock Cargo SDK binary inventory is missing')
        output = Path(tempfile.mkdtemp(prefix='cratectl-stock-cargo-' + VERSION + '-' + arch + '-', dir=cache))
        sdk.rename(output / 'sdk')
    return output / 'sdk/bin'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('architecture', choices=tuple(TARGETS))
    print(install(parser.parse_args().architecture))
