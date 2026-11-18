#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Prepare reviewed Linux media or verify an externally signed copy offline."""

import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from bounded_client import run_owned_client
from compose_evaluation import POSTGRES
from linux_candidate_sbom import archive_checksums
from package_linux import ROOT, digest
from verify_linux_candidate import MAX_ARCHIVE, SHA256, require, unique_members, verify


PROFILE = 'cratectl-linux-offline-media-v1'
ARCH = ('amd64', 'arm64')
IMAGE_FILES = {'postgres': 'postgres-image.tar', 'registry': 'registry-image.tar'}
RELEASE_FILES = {
    'licensing.md': 'docs/licensing.md',
    'console-third-party-notices.txt': 'internal/consoleui/dist/third-party-notices.txt',
    'offline-media.md': 'docs/operator/offline-media.md',
    'native-install.md': 'docs/operator/native-install.md',
    'helm.md': 'docs/operator/helm.md',
    'linux-candidate.md': 'docs/operator/linux-candidate.md',
    'compose.yaml': 'deploy/compose/compose.yaml',
    'init-database.sql': 'deploy/compose/init-database.sql',
    'install_linux_candidate.py': 'scripts/install_linux_candidate.py',
    'verify_linux_candidate.py': 'scripts/verify_linux_candidate.py',
    'package_linux.py': 'scripts/package_linux.py',
}
CHART = 'cratectl-0.1.0.tgz'
MANIFEST = 'release-manifest.json'
SIGNATURE = 'release-manifest.sig'
METADATA_BYTES = 64 << 10
MAX_IMAGE = 768 << 20
ED25519_SPKI = bytes.fromhex('302a300506032b6570032100')
OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def members(architecture):
    archive = 'cratectl-linux-' + architecture
    return {**dict.fromkeys(RELEASE_FILES, 1 << 20), CHART: 4 << 20,
            archive + '.tar.gz': MAX_ARCHIVE, archive + '.spdx.json': 2 << 20, archive + '.cdx.json': 2 << 20,
            **dict.fromkeys(IMAGE_FILES.values(), MAX_IMAGE)}


def aliases(candidate, architecture):
    label = candidate + '-' + architecture
    return {'postgres': 'cratectl-offline-postgres:' + label, 'registry': 'cratectl-offline-registry:' + label}


def command(*args, cwd=ROOT, timeout=45):
    env = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOENV': 'off', 'GOWORK': 'off'}
    code, output = run_owned_client(args, cwd, env, timeout=timeout, output_limit=1 << 20, capture_limit=4096)
    require(code == 0, 'owned media command failed: ' + ' '.join(str(item) for item in args[:2]) + '\n' + output)
    return output.strip()


def closed_json(raw):
    return json.loads(raw.decode('ascii'), object_pairs_hook=unique_members)


def bounded_member(directory, name, maximum, *, raw=False):
    label = Path(name).name
    with os.fdopen(os.open(name, OPEN, dir_fd=directory), 'rb') as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, 'invalid size or type for ' + label)
        if raw:
            data = handle.read(maximum + 1)
            require(len(data) == info.st_size, 'media member changed during read: ' + label)
            return data
        checksum = hashlib.sha256()
        size = 0
        while block := handle.read(min(128 << 10, maximum - size + 1)):
            size += len(block)
            require(size <= maximum, 'media member exceeds size limit: ' + label)
            checksum.update(block)
        require(size == info.st_size, 'media member changed during read: ' + label)
        return {'bytes': size, 'sha256': checksum.hexdigest()}


def contract(raw, expected_platform):
    report = closed_json(raw)
    require(type(report) is dict and set(report) == {'schema', 'profile', 'candidate', 'platform', 'images', 'members'}
            and type(report['schema']) is int and report['schema'] == 1 and report['profile'] == PROFILE
            and type(report['candidate']) is str and re.fullmatch('[a-f0-9]{40}', report['candidate'])
            and expected_platform in ARCH and report['platform'] == 'linux/' + expected_platform,
            'closed media identity and target platform are required')
    names = aliases(report['candidate'], expected_platform)
    images = report['images']
    require(type(images) is dict and set(images) == set(IMAGE_FILES), 'media image inventory differs')
    for name, alias in names.items():
        entry = images[name]
        fields = {'tag', 'id', 'source'} if name == 'postgres' else {'tag', 'id'}
        require(type(entry) is dict and set(entry) == fields and entry['tag'] == alias
                and type(entry['id']) is str and re.fullmatch('sha256:[a-f0-9]{64}', entry['id']),
                'invalid reviewed image identity: ' + name)
    require(images['postgres']['source'] == POSTGRES, 'media PostgreSQL pin differs')
    files = report['members']
    expected = members(expected_platform)
    require(type(files) is dict and set(files) == set(expected), 'closed media membership is required')
    for name, maximum in expected.items():
        entry = files[name]
        require(type(entry) is dict and set(entry) == {'bytes', 'sha256'}
                and type(entry['bytes']) is int and 0 < entry['bytes'] <= maximum
                and type(entry['sha256']) is str and SHA256.fullmatch(entry['sha256']), 'invalid media identity: ' + name)
    return report


def check_key(path, expected):
    require(SHA256.fullmatch(expected) is not None, 'independent public-key SHA-256 required')
    encoded = bounded_member(None, path, 256, raw=True)
    require(hashlib.sha256(encoded).hexdigest() == expected, 'approved public key digest differs')
    match = re.fullmatch(rb'-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=]+)\r?\n-----END PUBLIC KEY-----\r?\n', encoded)
    require(match is not None, 'a PEM Ed25519 public key is required')
    der = base64.b64decode(match[1], validate=True)
    require(len(der) == len(ED25519_SPKI) + 32 and der.startswith(ED25519_SPKI), 'a PEM Ed25519 public key is required')
    return encoded


def verify_media(directory, architecture, trusted_key, key_digest):
    key = check_key(trusted_key, key_digest)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        raw = bounded_member(fd, MANIFEST, METADATA_BYTES, raw=True)
        signature = bounded_member(fd, SIGNATURE, 64, raw=True)
        require(len(signature) == 64, 'detached Ed25519 signature requires 64 bytes')
        with tempfile.TemporaryDirectory(prefix='cratectl-offline-verification-') as scratch:
            work = Path(scratch)
            (work / 'trust.pem').write_bytes(key)
            (work / MANIFEST).write_bytes(raw)
            (work / SIGNATURE).write_bytes(signature)
            command('openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', 'trust.pem',
                    '-in', MANIFEST, '-sigfile', SIGNATURE, cwd=work)
        report = contract(raw, architecture)
        filenames = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                filenames.add(entry.name)
                require(len(filenames) <= len(report['members']) + 2, 'unexpected signed media members')
        require(filenames == {*report['members'], MANIFEST, SIGNATURE}, 'signed media directory inventory differs')
        for name, maximum in members(architecture).items():
            require(bounded_member(fd, name, maximum) == report['members'][name], 'signed media bytes differ: ' + name)
        return report
    finally:
        os.close(fd)


def image_id(reference, platform):
    output = command('docker', 'image', 'inspect', '--platform=' + platform,
                     '--format', '{{.Id}} {{.Os}}/{{.Architecture}}', reference)
    result = re.fullmatch(r'(sha256:[a-f0-9]{64}) ' + re.escape(platform), output)
    require(result is not None, 'image does not have the reviewed Linux platform')
    return result[1]


def verify_sbom_subjects(media, archive, metadata, archive_digest):
    fd = os.open(media, os.O_RDONLY | os.O_DIRECTORY)
    try:
        spdx = closed_json(bounded_member(fd, archive + '.spdx.json', 2 << 20, raw=True))
        cdx = closed_json(bounded_member(fd, archive + '.cdx.json', 2 << 20, raw=True))
    finally:
        os.close(fd)
    expected = {'archive': archive_digest, **{name: row['sha256'] for name, row in metadata['binaries'].items()}}
    packages = unique_members([(part['SPDXID'].removeprefix('SPDXRef-'), part) for part in spdx['packages']])
    components = unique_members([(part['bom-ref'], part)
                                 for part in [cdx['metadata']['component'], *cdx['components']]])
    require(spdx['spdxVersion'] == 'SPDX-2.3' and cdx['bomFormat'] == 'CycloneDX' and cdx['specVersion'] == '1.6'
            and packages['archive']['versionInfo'] == components['archive']['version'] == metadata['candidate']
            and all(packages[name]['checksums'] == [{'algorithm': 'SHA256', 'checksumValue': checksum}]
                    and components[name]['hashes'] == [{'alg': 'SHA-256', 'content': checksum}]
                    for name, checksum in expected.items()), 'SBOM subjects differ from the verified archive')


def assemble(architecture, candidate, output):
    platform = 'linux/' + architecture
    archive = 'cratectl-linux-' + architecture
    packages = ROOT / '.cache/cratectl-linux-candidates' / candidate
    expected_digest = archive_checksums(packages / 'SHA256SUMS')[archive + '.tar.gz']
    tags = aliases(candidate, architecture)
    parent = output.parent
    require(not output.exists() and not output.is_symlink(), 'existing offline media is immutable')
    postgres_id = image_id(POSTGRES, platform)
    with tempfile.TemporaryDirectory(prefix='cratectl-offline-assembly-', dir=parent) as scratch:
        scratch = Path(scratch)
        media, context = scratch / 'media', scratch / 'build'
        media.mkdir(mode=0o700)
        context.mkdir(mode=0o700)
        for suffix in ('.tar.gz', '.spdx.json', '.cdx.json'):
            shutil.copyfile(packages / (archive + suffix), media / (archive + suffix))
        metadata = verify(media / (archive + '.tar.gz'), expected_digest, staging=context)
        require(metadata['candidate'] == candidate and metadata['platform'] == platform
                and all(digest(ROOT / name) == checksum for name, checksum in metadata['source_sha256'].items()),
                'offline media archive differs from the current source or platform')
        verify_sbom_subjects(media, archive, metadata, expected_digest)
        for name in ('Dockerfile', '.dockerignore'):
            shutil.copyfile(ROOT / 'deploy/compose' / name, context / name)
        for name, source in RELEASE_FILES.items():
            shutil.copyfile(ROOT / source, media / name)
        command('helm', 'package', ROOT / 'deploy/helm/cratectl', '--destination', media)
        # The configuration ID from platform inspection is a useful binding.
        # The daemon indexes multi-platform images by the registry reference.
        command('docker', 'image', 'tag', POSTGRES, tags['postgres'])
        command('docker', 'build', '--platform=' + platform, '--network=none', '--build-arg', 'POSTGRES_IMAGE=' + POSTGRES,
                '-t', tags['registry'], context, timeout=300)
        images = {'postgres': {'tag': tags['postgres'], 'id': postgres_id, 'source': POSTGRES},
                  'registry': {'tag': tags['registry'], 'id': image_id(tags['registry'], platform)}}
        for name, filename in IMAGE_FILES.items():
            require(image_id(tags[name], platform) == images[name]['id'], 'staged image tag differs')
            command('docker', 'image', 'save', '--platform=' + platform, '--output', media / filename, tags[name], timeout=300)
        fd = os.open(media, os.O_RDONLY | os.O_DIRECTORY)
        try:
            files = {name: bounded_member(fd, name, maximum) for name, maximum in members(architecture).items()}
        finally:
            os.close(fd)
        require({entry.name for entry in media.iterdir()} == set(files), 'unexpected staged media assets')
        manifest = {'schema': 1, 'profile': PROFILE, 'candidate': candidate, 'platform': platform,
                    'images': images, 'members': files}
        raw = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode('ascii')
        contract(raw, architecture)
        (media / MANIFEST).write_bytes(raw)
        for entry in media.iterdir():
            with entry.open('rb') as handle:
                os.fsync(handle.fileno())
        for path in (media, parent):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                if path == parent:
                    media.rename(output)
                os.fsync(fd)
            finally:
                os.close(fd)
    return output


def prepare(architecture):
    candidate = command('git', 'rev-parse', 'HEAD')
    require(re.fullmatch('[a-f0-9]{40}', candidate) and not command('git', 'status', '--porcelain'),
            'a clean Git candidate is required')
    require(command('docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}').startswith('unix://')
            and os.environ.get('DOCKER_HOST', 'unix://').startswith('unix://'), 'a local Docker Unix socket is required')
    parent = ROOT / '.cache/cratectl-offline-media'
    parent.mkdir(parents=True, exist_ok=True)
    output = parent / (candidate + '-' + architecture)
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(parent / (output.name + '.lock'), flags, 0o600)
    with os.fdopen(fd, 'rb') as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0,
                'offline media assembly lock must be a private regular file')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return assemble(architecture, candidate, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    build = commands.add_parser('prepare')
    build.add_argument('--architecture', required=True, choices=ARCH)
    review = commands.add_parser('verify')
    review.add_argument('directory', type=Path)
    review.add_argument('--architecture', required=True, choices=ARCH)
    review.add_argument('--trusted-key', type=Path, required=True)
    review.add_argument('--trusted-key-sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == 'prepare':
            print(prepare(args.architecture))
        else:
            result = verify_media(args.directory, args.architecture, args.trusted_key, args.trusted_key_sha256)
            print(json.dumps(result, indent=2, sort_keys=True))
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, EOFError) as error:
        raise SystemExit(f'Linux offline media failed: {error}') from None


if __name__ == '__main__':
    main()
