#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Fetch only approved, bounded, hash-pinned public CI tool archives."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bounded_client import ClientLimitError, run_owned_client


def validate(name, url, digest, maximum):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{1,100}', name):
        raise ValueError('Tool archive must have one bounded filename')
    if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError('Tool archive requires its reviewed SHA256 pin')
    if type(maximum) is not int or not 1024 <= maximum <= 64 << 20 or maximum % 1024:
        raise ValueError('Tool archive budget must be whole KiB within 64MiB')
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in url) or '?' in url or '#' in url:
        raise ValueError('Tool archive URL is outside the reviewed sources')
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None or parsed.port is not None or parsed.path.rsplit('/', 1)[-1] != name:
        raise ValueError('Tool archive URL must be exact credential-free HTTPS')
    oras = parsed.hostname == 'github.com' and re.fullmatch(r'/oras-project/oras/releases/download/v([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4})/oras_\1_linux_(amd64|arm64)\.tar\.gz', parsed.path)
    helm = parsed.hostname == 'get.helm.sh' and re.fullmatch(r'/helm-v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,4}-linux-(amd64|arm64)\.tar\.gz', parsed.path)
    gitleaks = parsed.hostname == 'github.com' and parsed.path == '/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz'
    if not (oras or helm or gitleaks) or (oras or gitleaks) and maximum > 32 << 20:
        raise ValueError('Tool archive source or byte budget is not approved')


def checked_digest(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError('Tool archive must be a bounded regular file')
        digest = hashlib.sha256(); total = 0
        while True:
            chunk = source.read(min(65536, maximum - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError('Tool archive exceeds its byte budget')
            digest.update(chunk)
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise ValueError('Tool archive changed during verification')
        os.fsync(source.fileno())
        return digest.hexdigest()


def fetch(root, name, url, digest, maximum, environment):
    validate(name, url, digest, maximum)
    cache = Path(root) / '.cache'
    if cache.is_symlink():
        raise ValueError('CI archive cache cannot be a linked directory')
    cache.mkdir(mode=0o700, exist_ok=True)
    destination = cache / name
    if destination.exists() or destination.is_symlink():
        if checked_digest(destination, maximum) != digest:
            raise ValueError('Cached tool archive does not match its reviewed pin')
        return 'cache-hit'
    descriptor, temporary = tempfile.mkstemp(prefix='cratectl-download-', suffix='.part', dir=cache)
    os.close(descriptor)
    partial = Path(temporary)
    try:
        child_environment = {k:v for k,v in environment.items() if k not in {'BASH_ENV','ENV','SHELLOPTS','BASHOPTS','POSIXLY_CORRECT'}}
        # Bash's default ulimit unit is KiB. The child kernel limit independently
        # bounds file growth even when a server omits Content-Length.
        argv = ['bash', '--noprofile', '--norc', '-c', 'set -e\nulimit -c 0\nulimit -f "$1"\nshift\nexec "$@"',
                'cratectl-download', str(maximum // 1024), 'curl', '--disable',
                '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2',
                '--fail', '--location', '--max-redirs', '5', '--silent', '--show-error',
                '--connect-timeout', '15', '--max-time', '180', '--max-filesize', str(maximum),
                '--output', str(partial), url]
        try:
            code, output = run_owned_client(argv, root, child_environment, timeout=195,
                                            output_limit=65536, capture_limit=4096)
        except ClientLimitError as error:
            raise ValueError('Tool archive download exceeded its deadline/output budget') from error
        if code:
            status = re.search(r'returned error: ([45][0-9]{2})(?:\D|$)', output)
            detail = ', HTTP ' + status[1] if status else ''
            raise ValueError('Bounded tool archive transfer failed (exit ' + str(code) + detail + ')')
        if checked_digest(partial, maximum) != digest:
            raise ValueError('Downloaded tool archive does not match its reviewed pin')
        try:
            os.link(partial, destination, follow_symlinks=False)
        except FileExistsError:
            if checked_digest(destination, maximum) != digest:
                raise ValueError('Concurrent cache publication has a different tool pin')
        if checked_digest(destination, maximum) != digest:
            raise ValueError('Published archive failed verification')
        directory = os.open(cache, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return 'downloaded'
    finally:
        partial.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--url', required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--max-bytes', required=True, type=int)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.environ.get('RUNNER_OS') != 'Linux':
        raise ValueError('Archive installation requires an isolated GitHub-hosted Linux runner')
    result = fetch(Path.cwd(), args.archive, args.url, args.sha256, args.max_bytes, os.environ)
    print('Pinned tool archive verified (' + result + '): ' + args.archive)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit('Tool archive unavailable: ' + str(error)) from None
