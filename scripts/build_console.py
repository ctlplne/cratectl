#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Build or verify the embedded console using the installed, pinned tools."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / 'web'
DIST = ROOT / 'internal/consoleui/dist'
SOURCES = ('web/package.json', 'web/package-lock.json', 'web/tsconfig.json',
           'web/build.mjs', 'web/index.html', 'scripts/build_console.py')
ASSET = re.compile(r'[^/]+-[A-Za-z0-9_-]{8}\.(?:css|js)')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hashes(directory):
    return {path.relative_to(directory).as_posix(): digest(path)
            for path in sorted(directory.rglob('*')) if path.is_file()}


def notices():
    sections = ['cratectl operator console\nOriginal application: BUSL-1.1; see the repository licensing records.\n'
                'Bundled runtime components retain their licenses below.\n']
    for name in ('react', 'react-dom', 'scheduler'):
        package = WEB / 'node_modules' / name
        metadata = json.loads((package / 'package.json').read_text(encoding='utf-8'))
        sections.append('\n--- ' + name + ' ' + metadata['version'] + ' ---\n'
                        + (package / 'LICENSE').read_text(encoding='utf-8'))
    return '\n'.join(sections)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    cache = ROOT / '.cache'
    cache.mkdir(exist_ok=True)
    environment = {key: value for key, value in os.environ.items()
                   if key not in ('CRATECTL_OWNER_DSN', 'CRATECTL_DSN')}

    with tempfile.TemporaryDirectory(prefix='cratectl-console-build-', dir=cache) as folder:
        staging = Path(folder)
        tsc = WEB / 'node_modules/typescript/bin/tsc'
        subprocess.run(['node', tsc, '--noEmit'], cwd=WEB, env=environment, timeout=120, check=True)
        subprocess.run(['node', WEB / 'build.mjs', staging], cwd=WEB, env=environment, timeout=120, check=True)
        (staging / 'third-party-notices.txt').write_text(notices(), encoding='utf-8', newline='\n')
        sources = [ROOT / name for name in SOURCES]
        sources += sorted(path for path in (WEB / 'src').rglob('*') if path.is_file())
        manifest = {'sources': [{'path': path.relative_to(ROOT).as_posix(), 'sha256': digest(path)} for path in sources],
                    'asset_sha256': hashes(staging),
                    'build': 'TypeScript check, esbuild production bundle and bundled React/ReactDOM/scheduler notices. No source maps or external assets.'}
        path = WEB / 'build-manifest.json'
        if args.check:
            if manifest != json.loads(path.read_text(encoding='utf-8')) or hashes(DIST) != manifest['asset_sha256']:
                raise SystemExit('Embedded console differs from its source. Run make console and inspect the generated diff.')
            print('PASS: embedded console reproduces byte-for-byte from pinned source')
            return

        # Finish building before changing tracked assets. Publish the hashed
        # files before the HTML that references them, then retire old bundles.
        assets = DIST / 'assets'
        assets.mkdir(parents=True, exist_ok=True)
        for name in manifest['asset_sha256']:
            os.replace(staging / name, DIST / name)
        for old in assets.iterdir():
            if old.is_file() and ASSET.fullmatch(old.name) and 'assets/' + old.name not in manifest['asset_sha256']:
                old.unlink()
        encoded = staging / 'build-manifest.json'
        encoded.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8', newline='\n')
        os.replace(encoded, path)
        print('Embedded console and source/asset digest manifest written')


if __name__ == '__main__':
    main()
