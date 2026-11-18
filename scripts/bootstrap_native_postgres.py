# SPDX-License-Identifier: BUSL-1.1
"""Build a reviewed official PostgreSQL patch release inside this project."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from ci.fetch_archive import fetch


ROOT = Path(__file__).resolve().parents[1]
PINS = {
    '16.15': 'c1575341fa7bd40f5274ea465b34390f4dc64cdd0770af327005caaeb9f6b7ed',
    '16.16': '9d5cd8633043b75740d5d59749c6b7365e6aeb53c47098b1a5e80bb18f87881a',
}


def build(version):
    os.umask(0o077)
    cache = ROOT / '.cache'
    name = 'postgresql-' + version
    archive = name + '.tar.bz2'
    url = f'https://ftp.postgresql.org/pub/source/v{version}/{archive}'
    fetch(ROOT, archive, url, PINS[version], 48 << 20, os.environ)
    source = cache / name
    prefix = cache / (name + '-install')
    log_name = 'postgresql-native-build' if version == '16.15' else 'postgresql-native-build-' + version
    options = ['--without-readline', '--without-icu', '--without-zlib']
    lock_path = cache / (name + '-build.lock')
    with lock_path.open('ab') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if not source.exists():
            with tempfile.TemporaryDirectory(prefix='cratectl-postgres-tree-', dir=cache) as stage:
                tree = Path(stage)
                with tarfile.open(cache / archive, 'r:bz2') as bundle:
                    bundle.extractall(tree, filter='data')
                if {entry.name for entry in tree.iterdir()} != {name}:
                    raise ValueError('unexpected PostgreSQL source root')
                shutil.move(tree / name, source)
        if source.is_symlink() or prefix.is_symlink():
            raise ValueError('PostgreSQL source and prefix must be real project directories')
        with (cache / (log_name + '.log')).open('w') as log:
            for command in (['./configure', '--prefix=' + str(prefix), *options], ['make', '-j4'], ['make', 'install']):
                subprocess.run(command, cwd=source, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1800)
        observed = subprocess.check_output([prefix / 'bin/postgres', '--version'], text=True, timeout=10).strip()
        if observed != f'postgres (PostgreSQL) {version}':
            raise ValueError('compiled PostgreSQL version does not match its approved source')
        (cache / (log_name + '.json')).write_text(json.dumps({
            'version': observed, 'source': url, 'sha256': PINS[version], 'prefix': str(prefix),
            'configure': options, 'purpose': 'Owned loopback integration build.',
        }, indent=2) + '\n')
    print(observed + ' installed in the project cache. No global service started.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', choices=tuple(PINS), default='16.15')
    build(parser.parse_args().version)
