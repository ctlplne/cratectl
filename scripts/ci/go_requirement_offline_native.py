#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Actual signed requirement CLI/stock SDK journey, invoked by PostgreSQL tests.

The registry listener has stopped. Every command observes an empty kernel network
namespace before exec. Downloads inspect inert assets; no package code runs.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from conformance_go_export_portable import NETWORK_PROBE, run_capture, verify_network_probe
from ci.go_set_offline_native import PROBE_EXEC


def checked(condition, message):
    if not condition:
        raise ValueError(message)


def main(path):
    private = Path(path).resolve()
    checked(sys.platform == 'linux' and os.getuid() != 0, 'Native ordinary-user Linux required')
    raw = (private / 'fixture.json').read_bytes()
    checked(len(raw) <= 128 << 10, 'Owned requirement fixture bound')
    fixture = json.loads(raw)
    collection = private / 'collection'
    cli, go = fixture['cli'], fixture['go']
    env = {'PATH': os.environ['PATH'], 'HOME': str(private), 'GOENV': 'off', 'GOWORK': 'off',
           'GOTOOLCHAIN': 'local', 'GOAUTH': 'off', 'GOSUMDB': 'off', 'GONOSUMDB': '*',
           'GONOPROXY': 'none', 'GOVCS': '*:off', 'GOTELEMETRY': 'off',
           'GOMODCACHE': str(private / 'consumer' / 'modcache'),
           'GOPATH': str(private / 'consumer' / 'gopath'),
           'GOCACHE': str(private / 'consumer' / 'buildcache')}
    host_ns, count = os.stat('/proc/self/ns/net').st_ino, 0

    def isolated(arguments, *, ok=True, cwd=private):
        nonlocal count
        count += 1
        probe = private / ('requirement-network-%02d.json' % count)
        command = [sys.executable, '-c', PROBE_EXEC, str(probe), NETWORK_PROBE, *map(str, arguments)]
        code, output = run_capture(command, cwd, env, private / ('requirement-command-%02d.log' % count),
                                   timeout=90, isolated=True)
        checked(probe.exists(), 'Requirement command did not observe isolation')
        verify_network_probe(probe.read_bytes(), host_ns, os.getuid(), os.getgid())
        checked((code == 0) == ok, 'Actual requirement command returned unexpected status')
        checked(ok or not output, 'Refused requirement command emitted a success-shaped body')
        return output

    trust = ['--collection-directory', str(collection), '--set-id', fixture['set_id'],
             '--journal-tenant', fixture['tenant'],
             '--journal-event-sequence', str(fixture['created_sequence']),
             '--journal-through', str(fixture['through']['sequence']),
             '--journal-through-hash', fixture['through']['hash'],
             '--checkpoint-key-file', str(private / 'independent-public.pem')]
    verify = [cli, 'go-requirement-export-verify', *trust]
    verified = json.loads(isolated(verify))
    checked(verified['profile'] == 'cratectl.go.requirement-verification.v1'
            and verified['examined_sources'] == 3 and verified['selected_roots'] == 2
            and all(verified[k] is True for k in ('bytes_verified', 'original_inputs_complete', 'requirements_replayed'))
            and all(verified[k] is False for k in ('dependency_closure', 'checksum_authority_verified', 'current_registry_admission')),
            'Requirement verification supplied incomplete/unsupported claims')
    # These are independently chosen trust anchors, never taken from a receipt.
    for flag, value in [('--checkpoint-key-file', str(private / 'unrelated-public.pem')),
                        ('--journal-through-hash', 'f' * 64),
                        ('--journal-event-sequence', '1')]:
        changed = list(verify)
        changed[changed.index(flag) + 1] = value
        isolated(changed, ok=False)
    output = private / 'requirement offline'
    offline = [cli, 'go-requirement-export-offline', *trust, '--output-directory', str(output),
               '--chunk-bytes', '65536']
    tiny = list(offline)
    tiny[tiny.index('--output-directory') + 1] = str(private / 'refused tiny output')
    isolated(tiny + ['--max-bytes', '1'], ok=False)
    checked(not (private / 'refused tiny output').exists(), 'Refused budget created output state')
    receipt_raw = isolated(offline)
    checked(isolated(offline + ['--resume']) == receipt_raw, 'Original offline completion changed on replay')
    receipt = json.loads(receipt_raw)
    evidence = receipt['requirement_evidence']
    checked(receipt['profile'] == 'cratectl.go.hosted.requirement-offline.v1'
            and len(receipt['roots']) == 2 and receipt['bytes_verified'] is True
            and receipt['selected_roots_complete'] is True and receipt['native_proxy_prepared'] is True
            and evidence['examined_sources'] == 3
            and all(evidence[k] is True for k in ('original_inputs_complete', 'requirements_replayed', 'metadata_inputs_available'))
            and all(receipt[k] is False for k in ('dependency_closure', 'checksum_authority_verified', 'current_registry_admission')),
            'Requirement offline completion overclaimed its scope')
    proxy = urllib.parse.urlsplit(receipt['goproxy'])
    checked(proxy.scheme == 'file' and not proxy.netloc and not proxy.query and not proxy.fragment
            and urllib.parse.unquote(proxy.path) == str(output / 'bundle' / 'proxy'), 'Unexpected requirement proxy')
    native = output / 'bundle' / 'proxy'
    escaped = fixture['module'].replace('/Owned/', '/!owned/')
    lower = native / escaped / '@v' / 'v1.0.0.mod'
    checked(lower.read_bytes() == (collection / fixture['lower_input']).read_bytes(), 'Lower examined mod omitted')
    checked(not lower.with_suffix('.zip').exists() and not lower.with_suffix('.info').exists(),
            'Unselected version advertised an unavailable payload')
    checked((lower.parent / 'list').read_bytes() == b'v1.1.0\n'
            and json.loads((lower.parent.parent / '@latest').read_bytes())['Version'] == 'v1.1.0',
            'Examined lower metadata changed selected discovery')
    consumer = private / 'consumer'
    consumer.mkdir(mode=0o700)
    (consumer / 'go.mod').write_bytes((collection / 'main.mod').read_bytes())
    env['GOPROXY'] = receipt['goproxy']
    try:
        checked(b'go1.27.3 ' in isolated([go, 'version'], cwd=consumer), 'Pinned stock Go1.27.3 required')
        listed = isolated([go, 'list', '-mod=mod', '-m', '-json', 'all'], cwd=consumer)
        downloaded = isolated([go, 'mod', 'download', '-json', 'all'], cwd=consumer)

        def values(raw):
            result, decoder, text = [], json.JSONDecoder(), raw.decode()
            while text.strip():
                item, end = decoder.raw_decode(text.lstrip())
                result.append(item)
                text = text.lstrip()[end:]
            return result

        expected = {(r['module'], r['version']): r for r in receipt['roots']}
        checked({(v['Path'], v['Version']) for v in values(listed) if not v.get('Main')} == set(expected)
                == {(fixture['module'], 'v1.1.0'), (fixture['selector'], 'v1.0.0')},
                'Stock SDK disagrees with independently replayed competing versions')
        actual = values(downloaded)
        checked(len(actual) == 2, 'Stock SDK did not download exactly the selected versions')
        for value in actual:
            root = expected.pop((value['Path'], value['Version']))
            checked(not value.get('Error') and value['Sum'] == root['zip_h1'] and value['GoModSum'] == root['mod_h1'],
                    'Stock SDK differs from original native hashes')
            checked((Path(value['Dir']) / 'assets' / 'owned.txt').read_bytes() == b'owned inert requirement asset',
                    'Stock SDK extracted different inert bytes')
        checked(not expected, 'Stock SDK omitted a selected root')
        checked((Path(env['GOMODCACHE']) / 'cache' / 'download' / escaped / '@v' / 'v1.0.0.mod').read_bytes()
                == lower.read_bytes(), 'Native SDK did not actually read the unselected original metadata')
    finally:
        isolated([go, 'clean', '-modcache'], cwd=consumer)
    # A historical collection remains verifiable after source denial; it grants
    # no current admission. Changed retained originals must still refuse replay.
    corrupt = collection / fixture['lower_input']
    original = corrupt.read_bytes()
    changed = bytearray(original)
    changed[len(changed) // 2] ^= 1
    corrupt.write_bytes(changed)
    isolated(verify, ok=False)
    isolated(offline + ['--resume'], ok=False)
    checked(corrupt.read_bytes() == changed and (output / 'bundle' / 'receipt.json').read_bytes() == receipt_raw,
            'Refusal repaired corrupt originals or changed published completion')
    corrupt.write_bytes(original)
    unknown = collection / 'unexpected.mod'
    unknown.write_bytes(b'owned unknown input')
    isolated(verify, ok=False)
    checked(unknown.read_bytes() == b'owned unknown input', 'Unknown input was removed')
    unknown.unlink()
    checked(json.loads(isolated(verify)) == verified, 'Restored originals changed historical verification')
    probes = {}
    for path in sorted(private.glob('requirement-network-*.json')):
        body = path.read_bytes()
        verify_network_probe(body, host_ns, os.getuid(), os.getgid())
        probes[path.name] = hashlib.sha256(body).hexdigest()
    checked(len(probes) == count == 15, 'Requirement journey omitted an observed empty network')
    report = {'profile': 'cratectl.go.requirement-offline.native.v1', 'status': 'passed',
              'examined_sources': 3, 'selected_roots': 2, 'go_version': '1.27.3',
              'receipt_sha256': hashlib.sha256(receipt_raw).hexdigest(),
              'download_sha256': hashlib.sha256(downloaded).hexdigest(), 'network_probes': probes,
              'checks': ['production_creation_signature', 'all_original_inputs', 'independent_mvs_replay',
                         'native_competing_versions', 'actual_unselected_mod_read', 'selected_discovery_only',
                         'current_source_denial_preserves_history', 'independent_key_head_event_refusals',
                         'budget_before_output', 'immutable_completion_replay', 'corrupt_original_refusal',
                         'unknown_input_refusal', 'every_empty_command_network']}
    fd = os.open(private / 'requirement-offline-journey.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write((json.dumps(report, sort_keys=True) + '\n').encode())
    print('Requirement offline native competing versions, original metadata, independent trust and empty networks passed')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Expected one owned private requirement fixture directory')
    main(sys.argv[1])
