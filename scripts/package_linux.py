#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Assemble reproducible local Linux binary candidates from an exact Git source."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BINARIES = ('cratectl', 'cratectld')
SOURCE_INPUTS = ('go.mod', 'go.sum', 'web/build-manifest.json', 'web/package-lock.json',
                 'internal/consoleui/dist/third-party-notices.txt', 'docs/licensing.md')
MAX_BINARY = 96 << 20


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(128 << 10), b''):
            result.update(block)
    return result.hexdigest()


def append(archive, name, content, size, mode):
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = mode
    archive.addfile(info, content)


def publish(path, candidate):
    # A second process can win publication, so accept only byte-identical
    # existing output. Never replace a previous candidate's evidence.
    try:
        os.link(candidate, path, follow_symlinks=False)
    except FileExistsError:
        if path.is_symlink() or not path.is_file() or path.stat().st_size != candidate.stat().st_size or digest(path) != digest(candidate):
            raise ValueError('Existing candidate artifact differs: ' + path.name) from None
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def archive_candidate(output, binaries, manifest):
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode('ascii')
    with tempfile.NamedTemporaryFile(dir=output.parent, prefix='.cratectl-', delete=False) as compressed:
        staged = Path(compressed.name)
        try:
            with gzip.GzipFile(fileobj=compressed, mode='wb', filename='', mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
                    append(archive, 'manifest.json', io.BytesIO(encoded), len(encoded), 0o644)
                    for name in BINARIES:
                        entry = manifest['binaries'][name]
                        with (binaries / name).open('rb') as source:
                            append(archive, name, source, entry['bytes'], 0o755)
            compressed.flush()
            os.fsync(compressed.fileno())
            publish(output, staged)
        finally:
            staged.unlink(missing_ok=True)


def build(architecture, candidate, version, parent, go):
    name = 'cratectl-linux-' + architecture + '.tar.gz'
    with tempfile.TemporaryDirectory(prefix='cratectl-' + architecture + '-', dir=parent) as directory:
        binaries = Path(directory)
        env = dict(os.environ, GOOS='linux', GOARCH=architecture, CGO_ENABLED='0', GOTOOLCHAIN='local',
                   GOENV='off', GOWORK='off', GOPROXY='off', GONOPROXY='', GOPRIVATE='', GOFLAGS='-mod=readonly')
        subprocess.run(['make', 'build', 'BINDIR=' + directory], cwd=ROOT, env=env, check=True, timeout=300)
        artifacts = {}
        for command in BINARIES:
            path = binaries / command
            observed = subprocess.check_output([go, 'version', '-m', path], text=True, timeout=15).splitlines()
            settings = dict(line.strip().removeprefix('build\t').split('=', 1) for line in observed
                            if line.strip().startswith('build\t') and '=' in line)
            expected = {'GOOS': 'linux', 'GOARCH': architecture, 'CGO_ENABLED': '0',
                        'vcs.revision': candidate, 'vcs.modified': 'false'}
            count = path.stat().st_size
            if (not observed or observed[0].rsplit(maxsplit=1)[-1] != 'go' + version
                    or '\tpath\tctlplne.dev/cratectl/cmd/' + command not in observed
                    or any(settings.get(key) != value for key, value in expected.items()) or not 0 < count <= MAX_BINARY):
                raise ValueError('Exact candidate binary identity required: ' + command)
            artifacts[command] = {'bytes': count, 'sha256': digest(path)}
        manifest = {'schema': 1, 'profile': 'cratectl-linux-binary-candidate-v1', 'candidate': candidate,
                    'go_version': version, 'platform': 'linux/' + architecture, 'binaries': artifacts,
                    'source_sha256': {path: digest(ROOT / path) for path in SOURCE_INPUTS},
                    'distribution_approved': False}
        archive_candidate(parent / name, binaries, manifest)
    return name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', choices=('amd64', 'arm64', 'both'), default='both')
    args = parser.parse_args()
    os.umask(0o077)
    candidate = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, cwd=ROOT, timeout=10).strip()
    if not re.fullmatch('[a-f0-9]{40}', candidate) or subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, timeout=10):
        parser.error('a clean Git commit is required')
    version, = re.findall(r'^go ([0-9]+\.[0-9]+\.[0-9]+)$', (ROOT / 'go.mod').read_text(), re.M)
    installed_sdk = ROOT / '.cache/go/bin/go'
    go = str(installed_sdk) if installed_sdk.is_file() else 'go'
    sdk = subprocess.check_output([go, 'version'], text=True, cwd=ROOT, timeout=10,
                                  env={**os.environ, 'GOTOOLCHAIN': 'local', 'GOENV': 'off'})
    if sdk.split()[2] != 'go' + version:
        parser.error('the repository-pinned Go SDK is required')
    parent = ROOT / '.cache/cratectl-linux-candidates' / candidate
    parent.mkdir(parents=True, exist_ok=True)
    targets = ('amd64', 'arm64') if args.architecture == 'both' else (args.architecture,)
    for architecture in targets:
        name = build(architecture, candidate, version, parent, go)
        print(digest(parent / name), parent / name)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f'Linux candidate assembly failed: {error}') from None
