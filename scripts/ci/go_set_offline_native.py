#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned common-set CLI/stock-Go journey; called by the real PG integration test.

No package is compiled or executed. Every offline command observes its own empty
kernel network namespace before executing under the original ordinary job UID.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from conformance_go_export_portable import (NETWORK_PROBE, network_prefix,
                                           run_capture, verify_network_probe)
from ci.owned_child_process import kill_owned_cli

PROBE_EXEC = '''
import os,resource,sys
# This owned graph has small inert files. Bound diagnostic/capture files even
# for the killed child whose stdout is held at a kernel pipe barrier.
resource.setrlimit(resource.RLIMIT_FSIZE,(8<<20,8<<20))
raw=__import__('subprocess').check_output([sys.executable,'-c',sys.argv[2]],timeout=10)
fd=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb')as f:f.write(raw)
args=sys.argv[3:]
if args[0]=='--owned-cli-pid-file':
 fd=os.open(args[1],os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write((str(os.getpid())+'\\n').encode())
 args=args[2:]
os.execvpe(args[0],args,os.environ)
'''


def checked(condition, message):
    if not condition:
        raise ValueError(message)


def main(path):
    private = Path(path).resolve()
    checked(sys.platform == 'linux' and os.getuid() != 0, 'Native ordinary-user Linux required')
    raw = (private / 'fixture.json').read_bytes()
    checked(len(raw) <= 128 << 10, 'Owned fixture bound')
    fixture = json.loads(raw)
    collection = private / 'collection'
    cli, go = fixture['cli'], fixture['go']
    env = {'PATH': os.environ['PATH'], 'HOME': str(private), 'GOENV': 'off', 'GOWORK': 'off',
           'GOTOOLCHAIN': 'local', 'GOAUTH': 'off', 'GOSUMDB': 'off', 'GONOSUMDB': '*',
           'GONOPROXY': 'none', 'GOVCS': '*:off', 'GOTELEMETRY': 'off',
           'GOMODCACHE': str(private / 'consumer' / 'modcache'),
           'GOPATH': str(private / 'consumer' / 'gopath'),
           'GOCACHE': str(private / 'consumer' / 'buildcache')}
    prefix, _ = network_prefix(env)
    host_ns = os.stat('/proc/self/ns/net').st_ino
    count = 0

    def isolated(arguments, *, ok=True, cwd=private):
        nonlocal count
        count += 1
        probe = private / ('network-probe-%02d.json' % count)
        command = [sys.executable, '-c', PROBE_EXEC, str(probe), NETWORK_PROBE, *map(str, arguments)]
        code, output = run_capture(command, cwd, env, private / ('command-%02d.log' % count),
                                   timeout=90, isolated=True)
        checked(probe.exists(), 'Actual command did not observe isolation')
        verify_network_probe(probe.read_bytes(), host_ns, os.getuid(), os.getgid())
        checked((code == 0) == ok, 'Actual native command returned unexpected status')
        checked(ok or not output, 'Refused native command emitted a success-shaped body')
        return output

    output = private / 'offline union'
    args = [cli, 'go-export-set-offline', '--collection-directory', str(collection),
            '--set-id', fixture['set_id'], '--output-directory', str(output),
            '--journal-tenant', fixture['tenant'], '--journal-event-sequence', str(fixture['created_sequence']),
            '--journal-through', str(fixture['through']['sequence']),
            '--journal-through-hash', fixture['through']['hash'],
            '--checkpoint-key-file', str(private / 'independent-public.pem'), '--chunk-bytes', '65536']
    # A4096-byte pipe deterministically blocks the final receipt write after the
    # complete bundle has been synced/published. Kill only that owned child, then
    # reverify/replay its original completion. No production fault seam is used.
    read_fd, write_fd = os.pipe()
    checked(fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096) == 4096, 'Owned pipe capacity changed')
    child = None
    probe = private / 'network-probe-ack.json'
    pid_file = private / 'ack-cli.pid'
    try:
        with (private / 'uncertain-ack.stderr').open('xb') as diagnostic:
            child = subprocess.Popen(prefix + [sys.executable, '-c', PROBE_EXEC, str(probe), NETWORK_PROBE,
                                               '--owned-cli-pid-file', str(pid_file), *args],
                                     cwd=private, env=env, stdout=write_fd, stderr=diagnostic)
            os.close(write_fd)
            write_fd = -1
            checked(bool(select.select([read_fd], [], [], 90)[0]), 'Owned acknowledgement barrier timed out')
            checked(len(os.read(read_fd, 1)) == 1, 'Actual CLI failed before its final acknowledgement')
            receipt_raw = (output / 'bundle' / 'receipt.json').read_bytes()
            checked(4097 < len(receipt_raw) <= 512 << 10 and child.poll() is None,
                    'Final receipt did not exceed the actual pipe capacity')
            probe_raw = probe.read_bytes()
            verify_network_probe(probe_raw, host_ns, os.getuid(), os.getgid())
            killed_pid = kill_owned_cli(child, pid_file, cli, json.loads(probe_raw)['namespace'])
            checked(child.wait(timeout=10) != 0, 'Interrupted child reported success')
        verify_network_probe(probe.read_bytes(), host_ns, os.getuid(), os.getgid())
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
    replay = isolated(args + ['--resume'])
    checked(replay == receipt_raw, 'Uncertain acknowledgement replay changed original receipt')
    receipt = json.loads(replay)
    checked(receipt['profile'] == 'cratectl.go.hosted.set-offline.v1'
            and receipt['set_id'] == fixture['set_id'] and len(receipt['roots']) == 8
            and receipt['bytes_verified'] is True and receipt['selected_roots_complete'] is True
            and receipt['native_proxy_prepared'] is True and receipt['dependency_closure'] is False
            and receipt['checksum_authority_verified'] is False and receipt['current_registry_admission'] is False,
            'Offline receipt supplied incomplete/unsupported claims')
    proxy = urllib.parse.urlsplit(receipt['goproxy'])
    checked(proxy.scheme == 'file' and not proxy.netloc and not proxy.query and not proxy.fragment
            and urllib.parse.unquote(proxy.path) == str(output / 'bundle' / 'proxy'), 'Unexpected native proxy')
    checked(not (output / 'staging').exists(), 'Published output retained a competing tree')
    env['GOPROXY'] = receipt['goproxy']
    consumer = private / 'consumer'
    consumer.mkdir(mode=0o700)
    with (consumer / 'go.mod').open('x') as mod:
        mod.write('module go.cratectl.invalid/owned-consumer\n\ngo 1.27.0\nrequire '
                  + fixture['root_module'] + ' v1.0.0\n')
    try:
        version = isolated([go, 'version'], cwd=consumer)
        checked(b'go1.27.3 ' in version, 'Pinned stock Go1.27.3 required')
        downloaded = isolated([go, 'mod', 'download', '-json', 'all'], cwd=consumer)
        values, decoder, text = [], json.JSONDecoder(), downloaded.decode()
        while text.strip():
            value, end = decoder.raw_decode(text.lstrip())
            values.append(value)
            text = text.lstrip()[end:]
        expected = {(r['module'], r['version']): r for r in receipt['roots']}
        checked(len(values) == len(expected) == 8,
                'Stock Go did not download the complete transitive graph (observed=%d, expected=%d)'
                % (len(values), len(expected)))
        for value in values:
            root = expected.pop((value['Path'], value['Version']))
            checked(not value.get('Error') and value['Sum'] == root['zip_h1'] and value['GoModSum'] == root['mod_h1'],
                    'Stock Go differs from the original native hashes')
            checked((Path(value['Dir']) / 'assets' / 'owned.txt').read_text() == 'owned inert graph asset',
                    'Stock Go extracted different inert bytes')
        checked(not expected, 'A selected dependency was omitted')
    finally:
        isolated([go, 'clean', '-modcache'], cwd=consumer)
    # A late retained source corruption must fail even with a good published
    # tree. Preserve the historical receipt and corrupt input without repair.
    corrupt = collection / 'root.007.info'
    changed = bytearray(corrupt.read_bytes())
    changed[len(changed) // 2] ^= 1
    corrupt.write_bytes(changed)
    isolated(args + ['--resume'], ok=False)
    checked((output / 'bundle' / 'receipt.json').read_bytes() == receipt_raw
            and corrupt.read_bytes() == changed, 'Failed replay changed original state')
    probes = {}
    for path in sorted(private.glob('network-probe-*.json')):
        body = path.read_bytes()
        verify_network_probe(body, host_ns, os.getuid(), os.getgid())
        probes[path.name] = hashlib.sha256(body).hexdigest()
    checked(len(probes) == 6, 'Offline native journey omitted an observed command network')
    journey = {'profile': 'cratectl.go.common-offline.native.v1', 'status': 'passed',
               'roots': 8, 'go_version': '1.27.3', 'killed_verified_cli': True,
               'killed_cli_pid': killed_pid, 'signal': 'SIGKILL',
               'receipt_sha256': hashlib.sha256(receipt_raw).hexdigest(),
               'download_sha256': hashlib.sha256(downloaded).hexdigest(),
               'network_probes': probes,
               'checks': ['complete_proxy', 'stock_go_exact_graph', 'verified_cli_sigkill',
                          'original_receipt_replay', 'every_empty_network', 'late_corruption_refused']}
    fd = os.open(private / 'offline-journey.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as report:
        report.write((json.dumps(journey, sort_keys=True) + '\n').encode())
    print('Common-set offline native graph, empty networks, uncertain acknowledgement and corruption controls passed')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Expected one owned private fixture directory')
    main(sys.argv[1])
