#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Transfer a complete owned common collection between independent native jobs.

Keep the original single-version journey separate. No fixture package is compiled
or executed; this exercises native downloads, original proof and explicit refusals.
"""
import argparse
import base64
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from ci.campaign_transport import strict_json
from ci.go_common_export_portability_evidence import (FILES, HASHES, STAGES,
                                                     safe_go_common_export_portability_contract)
from ci.go_set_offline_native import NETWORK_PROBE, PROBE_EXEC
from conformance_go_export_portable import (build_identity, digest, network_prefix,
                                           run_capture, verify_network_probe, write_private)
from go_common_export_fixture import MODULE_PREFIX, decode_common_fixture, read_common_capsule
from qualification_contract import candidate_artifact_names, candidate_binary_directory


def require(condition, message):
    if not condition:
        raise ValueError(message)


def original_arguments(cli, value, collection, output, independent_key):
    return [str(cli), 'go-export-set-offline', '--collection-directory', str(collection),
            '--set-id', value['set_id'], '--output-directory', str(output),
            '--journal-tenant', value['tenant'], '--journal-event-sequence', str(value['created_sequence']),
            '--journal-through', str(value['through']['sequence']), '--journal-through-hash', value['through']['hash'],
            '--checkpoint-key-file', str(independent_key), '--chunk-bytes', '65536']


def bind_common_transport(value, raw, files, own, environment):
    # A copied key and receipt cannot replace the separately supplied job output.
    require(isinstance(own, str) and re.fullmatch('[a-f0-9]{64}', own) is not None
            and own != value['source_runner_sha256'], 'Common consumer reused its producer runner')
    for key, observed in [('CRATECTL_COMMON_FIXTURE_SHA256', digest(raw)),
                          ('CRATECTL_COMMON_PUBLIC_KEY_SHA256', digest(files['signer-public.pem'])),
                          ('CRATECTL_COMMON_SOURCE_RUNNER_SHA256', value['source_runner_sha256'])]:
        require(environment.get(key) == observed, 'Common input differs from its independently supplied source output')


def retained_originals(private, value, files):
    bundle = private / 'offline union' / 'bundle'
    manifest = strict_json(files['manifest.json'])
    require(len(manifest['entries']) == 8, 'Common native manifest omitted selected roots')
    for name in ['manifest.json', 'journal.jsonl', 'checkpoint.json', 'checkpoint.sig',
                 'signer-public.pem', 'bindings.json', 'receipt.json']:
        require((bundle / 'proof' / name).read_bytes() == files[name], 'Original common proof changed at destination')
    for n, entry in enumerate(manifest['entries']):
        module = MODULE_PREFIX + '/node%d' % n
        require(entry['module'] == module and entry['version'] == 'v1.0.0' and entry['repository'] == 'graph',
                'Owned selected common root differs from its fixed coordinate')
        prefix = module.replace('/Owned/', '/!owned/') + '/@v/v1.0.0'
        for k, kind in enumerate(['zip', 'mod', 'info']):
            path = prefix + '.' + kind
            artifact = entry['artifacts'][k]
            raw = files['root.%03d.%s' % (n, kind)]
            require(artifact['path'] == path and artifact['digest'] == digest(raw)
                    and artifact['size'] == len(raw), 'Owned root does not bind its exact original bytes')
            require((bundle / 'proxy' / path).read_bytes() == raw, 'Native proxy changed an original selected representation')


def consume(private, cli, go, value, files, command, stage, contract):
    collection = private / 'collection'
    collection.mkdir(mode=0o700)
    for name, raw in files.items():
        write_private(collection / name, raw)
    independent = private / 'independent-public.pem'
    write_private(independent, files['signer-public.pem'])
    settings = {'cli': str(cli), 'go': str(go), 'set_id': value['set_id'], 'tenant': value['tenant'],
                'created_sequence': value['created_sequence'], 'through': value['through'],
                'root_module': value['root_module']}
    write_private(private / 'fixture.json', (json.dumps(settings) + '\n').encode())
    helper = Path(__file__).resolve().parent / 'ci/go_set_offline_native.py'
    command([sys.executable, helper, private], timeout=300)
    report_path = private / 'offline-journey.json'
    require(report_path.stat().st_size <= 64 << 10, 'Native journey report exceeds its bound')
    report_raw = report_path.read_bytes()
    report = strict_json(report_raw)
    require(report['profile'] == 'cratectl.go.common-offline.native.v1' and report['status'] == 'passed'
            and report['roots'] == 8 and report['go_version'] == '1.27.3'
            and report['killed_verified_cli'] is True and report['signal'] == 'SIGKILL'
            and type(report['killed_cli_pid']) is int and report['killed_cli_pid'] > 1
            and report['checks'] == ['complete_proxy', 'stock_go_exact_graph', 'verified_cli_sigkill',
                                     'original_receipt_replay', 'every_empty_network', 'late_corruption_refused'],
            'Native common journey omitted a required control')
    native_probes = {}
    host_namespace = os.stat('/proc/self/ns/net').st_ino
    for name, expected in report['network_probes'].items():
        require(re.fullmatch(r'network-probe-(?:ack|0[1-5])\.json', name) is not None,
                'Native journey probe name is outside its fixed inventory')
        body = (private / name).read_bytes()
        require(digest(body) == expected, 'Native journey probe differs from its observed original')
        verify_network_probe(body, host_namespace, os.getuid(), os.getgid())
        native_probes[name] = expected
    require(len(native_probes) == 6, 'Native common journey omitted a command namespace')
    contract.update(network_isolated=True, namespace_commands=6, native_journey_sha256=digest(report_raw))
    stage('network_isolation_observed')
    receipt = private / 'offline union' / 'bundle' / 'receipt.json'
    require(digest(receipt.read_bytes()) == report['receipt_sha256'], 'Published common completion changed after SDK verification')
    stage('complete_common_proxy_and_sdk')
    stage('uncertain_ack_exact_replay')
    retained_originals(private, value, files)
    stage('originals_and_proof_retained')

    # Each refusal uses fresh exact originals, preserving the positive bundle and
    # original collection receipt. The inner positive helper intentionally changed
    # its retained last source member; never repair or reuse it for these cases.
    wrong_fixture = strict_json((Path(__file__).resolve().parents[1] / 'internal/crypto/testdata/journal-checkpoint-public.json').read_bytes())
    wrong_key = base64.b64decode(wrong_fixture['PublicKey'], validate=True)
    require(wrong_key != files['signer-public.pem'], 'Independent wrong-key control reused the original key')
    wrong_key_path = private / 'different-independent-public.pem'
    write_private(wrong_key_path, wrong_key)
    cases = [('changed_manifest_refused', 'manifest.json'), ('changed_late_zip_refused', 'root.007.zip'),
             ('truncated_journal_refused', 'journal.jsonl'), ('changed_signature_refused', 'checkpoint.sig'),
             ('wrong_independent_key_refused', None), ('wrong_set_refused', None),
             ('copied_unsupported_receipt_refused', 'receipt.json'), ('unknown_member_refused', None)]
    outer_probes = {}
    for n, (name, member) in enumerate(cases):
        inputs, output = private / ('case-%02d-inputs' % n), private / ('case-%02d-output' % n)
        inputs.mkdir(mode=0o700)
        for filename, raw in files.items():
            if filename == member:
                if name == 'truncated_journal_refused':
                    raw = raw[:-1]
                elif name == 'copied_unsupported_receipt_refused':
                    copied = strict_json(raw)
                    copied['current_registry_admission'] = True
                    raw = (json.dumps(copied, separators=(',', ':')) + '\n').encode()
                else:
                    changed = bytearray(raw)
                    changed[len(changed) // 2] ^= 1
                    raw = bytes(changed)
            write_private(inputs / filename, raw)
        args = original_arguments(cli, value, inputs, output, independent)
        if name == 'wrong_independent_key_refused':
            args += ['--checkpoint-key-file', str(wrong_key_path)]
        if name == 'wrong_set_refused':
            args += ['--set-id', '0' * 64 if value['set_id'] != '0' * 64 else '1' * 64]
        if name == 'unknown_member_refused':
            write_private(inputs / 'unreviewed-member', b'owned input must be preserved')
        probe = private / ('outer-probe-%02d.json' % n)
        command([sys.executable, '-c', PROBE_EXEC, probe, NETWORK_PROBE, *args], expected=False, isolated=True)
        body = probe.read_bytes()
        verify_network_probe(body, host_namespace, os.getuid(), os.getgid())
        outer_probes[probe.name] = digest(body)
        require(not (output / 'bundle').exists(), 'Refused common input published a complete servable bundle')
        stage(name)
    contract['namespace_commands'] = len(native_probes) + len(outer_probes)
    contract['network_probe_sha256'] = digest(json.dumps({**native_probes, **outer_probes}, sort_keys=True).encode())


def main(role):
    os.umask(0o077)
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('GITHUB_REPOSITORY') == 'ctlplne/cratectl' and os.environ.get('RUNNER_OS') == 'Linux'
            and role in STAGES and os.environ.get('GITHUB_JOB') == ('produce' if role == 'producer' else 'consume')
            and os.environ.get('RUNNER_ARCH') == ('X64' if role == 'producer' else 'ARM64')
            and 0 < len(os.environ.get('RUNNER_NAME', '')) <= 256, 'Actual owned native common producer/consumer context required')
    candidate, run_id = os.environ.get('GITHUB_SHA', ''), os.environ.get('GITHUB_RUN_ID', '')
    require(re.fullmatch('[a-f0-9]{40}', candidate) is not None and re.fullmatch('[1-9][0-9]{0,19}', run_id) is not None,
            'Exact native common candidate/run required')
    run = uuid.uuid4().hex[:10]
    private = root / '.private/go-common-export-portability' / run
    private.mkdir(parents=True, mode=0o700)
    paths = candidate_artifact_names()
    binaries = candidate_binary_directory()
    identities = {name: build_identity(root, name) for name in paths}
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain', '--', 'cmd', 'internal', 'scripts', 'api', 'web', 'go.mod', 'go.sum', 'Makefile'], text=True).strip())
    contract = dict.fromkeys(HASHES)
    contract.update(profile='hosted-common-export-cross-runner-v1', role=role, completed=[], go_version=None,
                    source_run_id=run_id, source_arch='amd64', destination_arch='arm64' if role == 'consumer' else None,
                    files_sha256={}, network_isolated=False, network_tools_sha256={}, namespace_commands=0,
                    explicit_roots=8, automatic_closure=False, destination_admission=False)
    bindings = {'fixture_source_sha256': 'internal/server/go_module_export_collect_integration_test.go',
                'capsule_source_sha256': 'internal/server/go_module_export_common_portable_integration_test.go',
                'graph_fixture_source_sha256': 'internal/server/go_common_graph_fixture_test.go',
                'native_helper_sha256': 'scripts/ci/go_set_offline_native.py',
                'process_helper_sha256': 'scripts/ci/owned_child_process.py',
                'decoder_sha256': 'scripts/go_common_export_fixture.py'}
    for key, path in bindings.items():
        contract[key] = digest((root / path).read_bytes())
    contract['script_sha256'] = digest(Path(__file__).read_bytes())
    checks, commands = [], []
    result = {'run': run, 'candidate': candidate, 'status': 'failed', 'checks': checks, 'commands': commands,
              'source_dirty': dirty, 'build_source_matches_candidate': not dirty and all(v.get('vcs.revision') == candidate and v.get('vcs.modified') == 'false' for v in identities.values()),
              'artifact_digests': {name: digest((root / name).read_bytes()) for name in paths}, 'build_identity': identities,
              'go_common_export_portability_contract': contract,
              'limits': ['Owned eight-root private graph; artifact/bootstrap transport is online. No package code executes.',
                         'Actual distinct GitHub x86 producer/ARM consumer; empty command networks and original UID; not an offline installer or HA/scale proof.',
                         'Fingerprint job outputs are a separate workflow trust-channel stand-in, not a production issuer/signing service.',
                         'Explicit selection supplies no automatic closure, public checksum authority or current destination admission. Full GOAL4.1 remains active.']}
    env = {'PATH': os.environ['PATH'], 'GOENV': 'off', 'GOWORK': 'off', 'GOTOOLCHAIN': 'local', 'GOTELEMETRY': 'off'}
    for key in ['LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH']:
        if key in os.environ:
            env[key] = os.environ[key]

    def command(arguments, expected=True, command_env=None, timeout=90, cwd=private, combined=False, isolated=False):
        log = private / ('command-' + uuid.uuid4().hex + '.log')
        item = {'private_log': str(log.relative_to(root)), 'expected_failure': not expected, 'exit': None}
        commands.append(item)
        code, output = run_capture(arguments, cwd, command_env or env, log, timeout=timeout, combined=combined, isolated=isolated)
        item['exit'] = code
        require(code == (0 if expected else 1), 'Native common command returned an unexpected status')
        require(expected or not output, 'Refused common command emitted a success-shaped body')
        return output

    def stage(name):
        require(name == STAGES[role][len(contract['completed'])], 'Native common stage order changed')
        contract['completed'].append(name)
        checks.append(name)
        print('PASS: ' + name, flush=True)

    try:
        require(result['build_source_matches_candidate'] and all(v.get('GOOS') == 'linux' and v.get('GOARCH') == ('amd64' if role == 'producer' else 'arm64') for v in identities.values()),
                'Clean exact native common CLI/server binaries required')
        go = Path(shutil.which('go')).resolve()
        version = command([go, 'version']).decode().strip()
        require(version.startswith('go version go1.27.3 linux/' + ('amd64' if role == 'producer' else 'arm64')), 'Pinned native Go1.27.3 required')
        contract.update(go_version='1.27.3', go_binary_sha256=digest(go.read_bytes()))
        stage('native_identity')
        if role == 'producer':
            fixture_dir = root / '.cache/go-common-export-portable-upload'
            native_env = {**os.environ, 'CRATECTL_GO_COMMON_EXPORT_PORTABLE_OUT': str(fixture_dir)}
            command([go, 'test', '-count=1', '-tags=integration', '-run', '^TestGoModuleCommonSetOfflineNativeGraphAndUncertainAcknowledgement$', './internal/server'],
                    command_env=native_env, cwd=root, timeout=540, combined=True)
            stage('native_postgresql_common_fixture')
            raw = read_common_capsule(fixture_dir / 'fixture.json')
        else:
            raw = read_common_capsule(root / '.cache/go-common-export-portable-download/fixture.json')
        value, files = decode_common_fixture(raw, candidate, run_id)
        contract.update(fixture_sha256=digest(raw), public_key_sha256=digest(files['signer-public.pem']),
                        source_runner_sha256=value['source_runner_sha256'], files_sha256={name: digest(body) for name, body in files.items()})
        own = digest(os.environ['RUNNER_NAME'].encode())
        if role == 'producer':
            require(own == value['source_runner_sha256'], 'Actual common source runner differs from its retained fixture')
            stage('original_common_files_bound')
        else:
            contract['destination_runner_sha256'] = own
            bind_common_transport(value, raw, files, own, os.environ)
        stage('transport_bound')
        if role == 'producer':
            with open(os.environ['GITHUB_OUTPUT'], 'a') as target:
                for key in ['fixture_sha256', 'public_key_sha256', 'source_runner_sha256']:
                    target.write('common_' + key + '=' + contract[key] + '\n')
        else:
            _, tools = network_prefix(env)
            contract['network_tools_sha256'] = {name: digest(Path(path).read_bytes()) for name, path in tools.items()}
            consume(private, binaries / 'cratectl', go, value, files, command, stage, contract)
        require(not subprocess.check_output(['git', 'status', '--porcelain', '--', 'cmd', 'internal', 'scripts', 'api', 'web', 'go.mod', 'go.sum', 'Makefile'], text=True).strip(),
                'Native common journey changed its candidate source')
        result['status'] = 'passed'
    except BaseException as error:
        result['failure'] = type(error).__name__ + ': ' + str(error)[:4096]
        raise
    finally:
        safe_go_common_export_portability_contract(contract, result['status'])
        destination = root / 'evidence' / datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / ('go-common-export-portability-' + run + '.json')
        with target.open('x') as output:
            json.dump(result, output, indent=2)
            output.write('\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=['producer', 'consumer'])
    main(parser.parse_args().role)
