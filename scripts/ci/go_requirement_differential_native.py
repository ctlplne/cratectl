#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Signed original requirement graphs versus stock Go, after source shutdown.

Five fixed owned metadata cases; inert assets only. No package is built or run.
Every CLI/SDK command observes a fresh empty kernel network under the job UID.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from conformance_go_export_portable import (NETWORK_PROBE, run_capture,
                                           unique_object, verify_network_probe)
from ci.go_set_offline_native import PROBE_EXEC

CASES = ['specific', 'wildcard', 'exclusion', 'excluded-only', 'excluded-lower']


def checked(condition, message):
    if not condition:
        raise ValueError(message)


def values(raw):
    checked(isinstance(raw, bytes) and 0 < len(raw) <= 1 << 20, 'SDK JSON byte budget')
    result, decoder, text = [], json.JSONDecoder(object_pairs_hook=unique_object), raw.decode()
    while text.strip():
        checked(len(result) < 16, 'SDK module count budget')
        item, end = decoder.raw_decode(text.lstrip())
        checked(isinstance(item, dict) and not item.get('Error'), 'SDK module response contains an error')
        result.append(item)
        text = text.lstrip()[end:]
    return result


def check_listing(raw, expected):
    modules, actual, main_count = values(raw), [], 0
    for item in modules:
        if item.get('Main'):
            checked(item['Path'] == 'go.cratectl.invalid/owned-differential' and 'Replace' not in item,
                    'Unexpected SDK main module')
            main_count += 1
            continue
        logical = (item['Path'], item['Version'])
        physical = item.get('Replace', item)
        checked(isinstance(physical, dict) and not physical.get('Error'), 'SDK replacement failed')
        actual.append((*logical, physical['Path'], physical['Version']))
    want = [(r['module'], r['version'], r['source_module'], r['source_version']) for r in expected]
    checked(main_count == 1 and len(actual) == len(want) and set(actual) == set(want),
            'SDK logical/replacement selection differs from original proof')


def check_downloads(raw, roots):
    expected = {(r['module'], r['version']): r for r in roots}
    actual = values(raw)
    checked(len(expected) == len(roots) == len(actual), 'SDK selected download inventory differs')
    for item in actual:
        coordinate = (item['Path'], item['Version'])
        checked(coordinate in expected, 'SDK downloaded an unexpected or duplicate physical module')
        root = expected.pop(coordinate)
        checked(item.get('Sum') == root['zip_h1'] and item.get('GoModSum') == root['mod_h1'],
                'SDK native hashes differ from the signed original bytes')
        checked((Path(item['Dir']) / 'assets' / 'owned.txt').read_bytes() == b'owned inert differential asset',
                'SDK extracted different inert bytes')
    checked(not expected, 'SDK omitted a selected physical module')


def main(path):
    private = Path(path).resolve()
    checked(sys.platform == 'linux' and os.getuid() != 0, 'Native ordinary-user Linux required')
    with (private / 'differentials.json').open('rb') as handle:
        raw = handle.read((128 << 10) + 1)
    checked(0 < len(raw) <= 128 << 10, 'Owned differential fixture byte budget')
    fixture = json.loads(raw, object_pairs_hook=unique_object)
    checked([v['name'] for v in fixture['cases']] == CASES, 'Exact five owned differential cases required')
    cli, go = fixture['cli'], fixture['go']
    env = {'PATH': os.environ['PATH'], 'HOME': str(private), 'GOENV': 'off', 'GOWORK': 'off',
           'GOTOOLCHAIN': 'local', 'GOAUTH': 'off', 'GOSUMDB': 'off', 'GONOSUMDB': '*',
           'GONOPROXY': 'none', 'GOVCS': '*:off', 'GOTELEMETRY': 'off'}
    host_ns, count = os.stat('/proc/self/ns/net').st_ino, 0

    def isolated(arguments, *, cwd=private):
        nonlocal count
        count += 1
        probe = private / ('differential-network-%02d.json' % count)
        command = [sys.executable, '-c', PROBE_EXEC, str(probe), NETWORK_PROBE, *map(str, arguments)]
        code, output = run_capture(command, cwd, env, private / ('differential-command-%02d.log' % count),
                                   timeout=90, isolated=True)
        verify_network_probe(probe.read_bytes(), host_ns, os.getuid(), os.getgid())
        checked(code == 0, 'Actual native differential command failed')
        return output

    checked(b'go1.27.3 ' in isolated([go, 'version']), 'Pinned stock Go1.27.3 required')
    reports = []
    for case in fixture['cases']:
        name = case['name']
        collection, output = private / (name + '-collection'), private / (name + '-offline')
        original_main = (collection / 'main.mod').read_bytes()
        checked(hashlib.sha256(original_main).hexdigest() == case['main_sha256'], 'Original project changed')
        original_receipt = (collection / 'receipt.json').read_bytes()
        trust = ['--collection-directory', str(collection), '--set-id', case['set_id'],
                 '--journal-tenant', fixture['tenant'], '--journal-event-sequence', str(case['created_sequence']),
                 '--journal-through', str(fixture['through']['sequence']), '--journal-through-hash', fixture['through']['hash'],
                 '--checkpoint-key-file', str(private / 'independent-public.pem')]
        verified = json.loads(isolated([cli, 'go-requirement-export-verify', *trust]))
        checked(verified['examined_sources'] == case['examined_sources'] and verified['selected_roots'] == len(case['expected'])
                and all(verified[k] is True for k in ('bytes_verified', 'original_inputs_complete', 'requirements_replayed'))
                and all(verified[k] is False for k in ('dependency_closure', 'checksum_authority_verified', 'current_registry_admission')),
                'Differential verification overclaimed its metadata scope')
        offline = [cli, 'go-requirement-export-offline', *trust, '--output-directory', str(output), '--chunk-bytes', '65536']
        receipt_raw = isolated(offline)
        checked(isolated(offline + ['--resume']) == receipt_raw, 'Differential offline replay changed original completion')
        receipt = json.loads(receipt_raw)
        checked(receipt['profile'] == 'cratectl.go.hosted.requirement-offline.v1'
                and all(receipt[k] is True for k in ('bytes_verified', 'selected_roots_complete', 'native_proxy_prepared'))
                and all(receipt[k] is False for k in ('dependency_closure', 'checksum_authority_verified', 'current_registry_admission'))
                and receipt['requirement_evidence']['examined_sources'] == case['examined_sources'],
                'Differential native proxy overclaimed closure or current admission')
        physical = [(r['module'], r['version']) for r in receipt['roots']]
        expected = [(r['source_module'], r['source_version']) for r in case['expected']]
        checked(physical == expected, 'Physical roots lost logical selected order')
        proxy = urllib.parse.urlsplit(receipt['goproxy'])
        checked(proxy.scheme == 'file' and not proxy.netloc and not proxy.query and not proxy.fragment
                and urllib.parse.unquote(proxy.path) == str(output / 'bundle' / 'proxy'), 'Unexpected differential proxy')
        consumer = private / (name + '-consumer')
        consumer.mkdir(mode=0o700)
        (consumer / 'go.mod').write_bytes(original_main)
        env.update(GOPROXY=receipt['goproxy'], GOMODCACHE=str(consumer / 'modcache'),
                   GOPATH=str(consumer / 'gopath'), GOCACHE=str(consumer / 'buildcache'))
        try:
            listed = isolated([go, 'list', '-mod=mod', '-m', '-json', 'all'], cwd=consumer)
            check_listing(listed, case['expected'])
            downloaded = isolated([go, 'mod', 'download', '-json', 'all'], cwd=consumer)
            check_downloads(downloaded, receipt['roots'])
        finally:
            isolated([go, 'clean', '-modcache'], cwd=consumer)
        checked((collection / 'main.mod').read_bytes() == original_main
                and (collection / 'receipt.json').read_bytes() == original_receipt,
                'SDK execution changed the retained original collection')
        reports.append({'case': name, 'examined_sources': case['examined_sources'], 'selected_roots': len(physical),
                        'main_sha256': case['main_sha256'], 'receipt_sha256': hashlib.sha256(receipt_raw).hexdigest(),
                        'listing_sha256': hashlib.sha256(listed).hexdigest(), 'download_sha256': hashlib.sha256(downloaded).hexdigest()})
    probes = {p.name: verify_network_probe(p.read_bytes(), host_ns, os.getuid(), os.getgid())
              for p in sorted(private.glob('differential-network-*.json'))}
    checked(len(probes) == count == 31, 'Differential journey omitted an observed empty command network')
    report = {'profile': 'cratectl.go.requirement-differentials.native.v1', 'status': 'passed',
              'go_version': '1.27.3', 'cases': reports, 'network_probes': probes,
              'dependency_closure': False, 'checksum_authority_verified': False, 'current_registry_admission': False}
    fd = os.open(private / 'requirement-differentials-report.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write((json.dumps(report, sort_keys=True) + '\n').encode())
    print('Requirement native replacement and exclusion differentials passed (five cases,31 empty command networks)')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Expected one owned private differential fixture directory')
    main(sys.argv[1])
