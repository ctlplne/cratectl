#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Reserve only owned ports on disposable native GitHub Linux runners."""
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from bounded_client import run_owned_client

OWNED = {35432, 38443}
RESERVED = Path('/proc/sys/net/ipv4/ip_local_reserved_ports')
MAX_FIELD = 1 << 20


def require(ok, category):
    if not ok:
        raise ValueError(category)


def guard(environment, system, uid):
    require(system == 'Linux' and uid == 0
            and environment.get('GITHUB_ACTIONS') == 'true'
            and environment.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and environment.get('RUNNER_OS') == 'Linux'
            and re.fullmatch('[a-f0-9]{64}', environment.get('CRATECTL_CI_POSTGRES_CONTAINER_ID', '')),
            'owned_ports_requires_root_disposable_github_linux')


def ports(raw):
    require(isinstance(raw, str) and len(raw) <= MAX_FIELD, 'reserved_port_input_limit')
    value = raw.strip()
    result = set()
    if not value:
        return result
    for item in value.split(','):
        require(re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?', item), 'invalid_reserved_port_range')
        bounds = [int(n) for n in item.split('-')]
        low, high = bounds[0], bounds[-1]
        require(0 <= low <= high <= 65535, 'invalid_reserved_port_range')
        result.update(range(low, high + 1))
    return result


def render(values):
    result = []
    for number in sorted(values):
        require(type(number) is int and 0 <= number <= 65535, 'invalid_reserved_port')
        if result and number == result[-1][1] + 1:
            result[-1][1] = number
        else:
            result.append([number, number])
    return ','.join(str(low) if low == high else str(low) + '-' + str(high) for low, high in result)


def read_field(target):
    with target.open() as source:
        raw = source.read(MAX_FIELD + 1)
    require(len(raw) <= MAX_FIELD, 'reserved_port_input_limit')
    return raw


def reserve(read, write):
    before = ports(read())
    expected = before | OWNED
    write(render(expected) + '\n')
    after = ports(read())
    require(after == expected, 'reserved_port_readback_mismatch')
    return {'owned_ports': sorted(OWNED), 'inherited_count': len(before),
            'before_sha256': hashlib.sha256(render(before).encode()).hexdigest(),
            'after_sha256': hashlib.sha256(render(after).encode()).hexdigest()}


def namespace_case(mode, parent_inode):
    current = os.stat('/proc/self/ns/net').st_ino
    require(current != parent_inode and current != os.stat('/proc/1/ns/net').st_ino,
            'kernel_case_requires_fresh_child_namespace')
    ip = next((p for p in ('/usr/sbin/ip', '/sbin/ip') if Path(p).is_file()), None)
    require(ip is not None, 'kernel_case_ip_unavailable')
    subprocess.run([ip, 'link', 'set', 'dev', 'lo', 'up'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    # Only this fresh child namespace gets a declared one-port automatic range.
    Path('/proc/sys/net/ipv4/ip_local_port_range').write_text('38443 38443\n')
    RESERVED.write_text('35432\n')
    if mode == 'reserved':
        reserve(lambda: read_field(RESERVED), RESERVED.write_text)
    with socket.socket() as peer, socket.socket() as client, socket.socket() as fixed:
        peer.settimeout(2)
        client.settimeout(2)
        fixed.settimeout(2)
        peer.bind(('127.0.0.1', 35432))
        peer.listen(1)
        if mode == 'unreserved':
            client.connect(('127.0.0.1', 35432))
            require(client.getsockname()[1] == 38443, 'kernel_automatic_port_not_observed')
            try:
                fixed.bind(('127.0.0.1', 38443))
            except OSError as exc:
                require(exc.errno == errno.EADDRINUSE, 'kernel_unexpected_bind_error')
            else:
                require(False, 'kernel_unreserved_collision_missing')
        else:
            try:
                client.connect(('127.0.0.1', 35432))
            except OSError as exc:
                require(exc.errno == errno.EADDRNOTAVAIL, 'kernel_unexpected_allocation_error')
            else:
                require(False, 'kernel_reserved_automatic_allocation')
            fixed.bind(('127.0.0.1', 38443))
            fixed.listen(1)
    return {'mode': mode, 'automatic_uses_owned_port': mode == 'unreserved',
            'explicit_bind_succeeds': mode == 'reserved'}


def qualify():
    parent = os.stat('/proc/self/ns/net').st_ino
    parent_range = read_field(Path('/proc/sys/net/ipv4/ip_local_port_range'))
    parent_reserved = ports(read_field(RESERVED))
    environment = {key: os.environ[key] for key in
                   ('PATH', 'GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'CRATECTL_CI_POSTGRES_CONTAINER_ID')}
    observations = []
    for mode in ('unreserved', 'reserved'):
        code, output = run_owned_client(['unshare', '--net', '--', sys.executable, str(Path(__file__).resolve()),
                                        '--case', mode, str(parent)], ROOT, environment,
                                       timeout=20, output_limit=65536, capture_limit=65536)
        require(code == 0, 'owned_port_kernel_case_failed')
        observed = json.loads(output)
        expected = {'mode': mode, 'automatic_uses_owned_port': mode == 'unreserved',
                    'explicit_bind_succeeds': mode == 'reserved'}
        require(observed == expected, 'owned_port_kernel_case_mismatch')
        observations.append(observed)
    require(os.stat('/proc/self/ns/net').st_ino == parent, 'parent_namespace_changed')
    require(read_field(Path('/proc/sys/net/ipv4/ip_local_port_range')) == parent_range
            and ports(read_field(RESERVED)) == parent_reserved, 'parent_kernel_fields_changed')
    return observations


def main():
    try:
        guard(os.environ, platform.system(), os.geteuid())
        if len(sys.argv) == 4 and sys.argv[1] == '--case' and sys.argv[2] in ('unreserved', 'reserved') and re.fullmatch('[1-9][0-9]{0,19}', sys.argv[3]):
            result = namespace_case(sys.argv[2], int(sys.argv[3]))
        else:
            require(len(sys.argv) == 1, 'invalid_owned_port_arguments')
            observations = qualify()
            result = reserve(lambda: read_field(RESERVED), RESERVED.write_text)
            result.update(profile='cratectl-owned-ci-ports-v1', kernel_controls=observations,
                          machine=platform.machine(), source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        # No inherited sysctl values, arbitrary command output or environment.
        print('Owned native port isolation/qualification failed; no pass established.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
