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


APACHE_ARCHIVES = {
    'apache-ivy-2.6.0-bin.tar.gz': '/ant/ivy/2.6.0/apache-ivy-2.6.0-bin.tar.gz',
    'apache-ant-1.10.18-bin.tar.gz': '/ant/binaries/apache-ant-1.10.18-bin.tar.gz',
}


class ArchiveTransferError(ValueError):
    """Only a failed transfer may select another approved copy of the same bytes."""


def validate(name, url, digest, maximum, algorithm='sha256'):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{1,100}', name):
        raise ValueError('Tool archive must have one bounded filename')
    if algorithm not in ('sha256', 'sha512') or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{'+str({'sha256':64,'sha512':128}.get(algorithm,0))+'}', digest):
        raise ValueError('Tool archive requires its reviewed exact digest algorithm and pin')
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
    apache = (name in APACHE_ARCHIVES and ((parsed.hostname == 'downloads.apache.org' and parsed.path == APACHE_ARCHIVES[name]) or (parsed.hostname == 'archive.apache.org' and parsed.path == '/dist'+APACHE_ARCHIVES[name])))
    if not ((algorithm == 'sha256' and (oras or helm or gitleaks)) or (algorithm == 'sha512' and apache)) or (oras or gitleaks) and maximum > 32 << 20:
        raise ValueError('Tool archive source or byte budget is not approved')


def checked_digest(path, maximum, algorithm='sha256'):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError('Tool archive must be a bounded regular file')
        digest = hashlib.new(algorithm); total = 0
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


def fetch(root, name, url, digest, maximum, environment, algorithm='sha256'):
    validate(name, url, digest, maximum, algorithm)
    cache = Path(root) / '.cache'
    if cache.is_symlink():
        raise ValueError('CI archive cache cannot be a linked directory')
    cache.mkdir(mode=0o700, exist_ok=True)
    destination = cache / name
    if destination.exists() or destination.is_symlink():
        if checked_digest(destination, maximum, algorithm) != digest:
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
            failure = ArchiveTransferError if code in (5, 6, 7, 18, 22, 28, 35, 52, 55, 56) else ValueError
            raise failure('Bounded tool archive transfer failed (exit ' + str(code) + detail + ')')
        if checked_digest(partial, maximum, algorithm) != digest:
            raise ValueError('Downloaded tool archive does not match its reviewed pin')
        try:
            os.link(partial, destination, follow_symlinks=False)
        except FileExistsError:
            if checked_digest(destination, maximum, algorithm) != digest:
                raise ValueError('Concurrent cache publication has a different tool pin')
        if checked_digest(destination, maximum, algorithm) != digest:
            raise ValueError('Published archive failed verification')
        directory = os.open(cache, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return 'downloaded'
    finally:
        partial.unlink(missing_ok=True)


def fetch_apache(root, name, primary, fallback, digest, maximum, environment):
    # Reject wrong mirrors/versions/pins before any network or cache access.
    path = APACHE_ARCHIVES.get(name)
    if path is None or primary != 'https://downloads.apache.org'+path or fallback != 'https://archive.apache.org/dist'+path:
        raise ValueError('Apache fallback must be the reviewed original archive on the official archive host')
    validate(name, primary, digest, maximum, 'sha512')
    validate(name, fallback, digest, maximum, 'sha512')
    try:
        return fetch(root, name, primary, digest, maximum, environment, 'sha512')
    except ArchiveTransferError:
        # A completed mismatch, corrupt cache, unsafe path or local I/O error is
        # never retried or overwritten. This fixed public URL has no credentials.
        print('Approved Apache primary transfer failed: '+primary, flush=True)
        return fetch(root, name, fallback, digest, maximum, environment, 'sha512')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--url', required=True)
    pins = parser.add_mutually_exclusive_group(required=True)
    pins.add_argument('--sha256')
    pins.add_argument('--sha512')
    parser.add_argument('--fallback-url')
    parser.add_argument('--max-bytes', required=True, type=int)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.environ.get('RUNNER_OS') != 'Linux':
        raise ValueError('Archive installation requires an isolated GitHub-hosted Linux runner')
    if args.sha512 is not None:
        result = fetch_apache(Path.cwd(), args.archive, args.url, args.fallback_url, args.sha512, args.max_bytes, os.environ)
    else:
        if args.fallback_url is not None:
            raise ValueError('Fallback is restricted to the reviewed Apache SHA512 archives')
        result = fetch(Path.cwd(), args.archive, args.url, args.sha256, args.max_bytes, os.environ)
    print('Pinned tool archive verified (' + result + '): ' + args.archive)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit('Tool archive unavailable: ' + str(error)) from None
