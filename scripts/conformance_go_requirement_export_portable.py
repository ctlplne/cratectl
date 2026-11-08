#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Transfer exact owned requirement originals between separate native Actions jobs.

Every historical input and its independent trust channel remains distinct from
current destination admission, package/platform closure and public authority.
"""
import argparse
import base64
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import uuid

from ci.campaign_transport import strict_json
from ci.go_requirement_export_portability_evidence import (FILES, HASHES, STAGES,
                                                          safe_go_requirement_export_portability_contract)
from ci.go_set_offline_native import NETWORK_PROBE, PROBE_EXEC
from conformance_go_export_portable import (build_identity, digest, network_prefix,
                                           run_capture, verify_network_probe, write_private)
from go_requirement_export_fixture import (MODULE, SELECTOR, decode_requirement_fixture,
                                           read_requirement_capsule)
from qualification_contract import candidate_artifact_names, candidate_binary_directory


def require(condition, message):
    if not condition:
        raise ValueError(message)


def prepare_source_fixture(go, root, fixture_dir, command):
    native_env = {**os.environ, 'CRATECTL_GO_REQUIREMENT_EXPORT_PORTABLE_OUT': str(fixture_dir)}
    return command([go, 'test', '-count=1', '-tags=integration', '-run',
                    '^TestGoModuleRequirementCollectionNativeSignedCompetingVersionsAndOffline$', './internal/server'],
                   command_env=native_env, cwd=root, timeout=300, combined=True)


def original_arguments(cli, value, collection, output, independent_key):
    return [str(cli), 'go-requirement-export-offline', '--collection-directory', str(collection),
            '--set-id', value['set_id'], '--output-directory', str(output),
            '--journal-tenant', value['tenant'], '--journal-event-sequence', str(value['created_sequence']),
            '--journal-through', str(value['through']['sequence']), '--journal-through-hash', value['through']['hash'],
            '--checkpoint-key-file', str(independent_key), '--chunk-bytes', '65536']


def bind_requirement_transport(value, raw, files, own, environment):
    require(isinstance(own, str) and re.fullmatch('[a-f0-9]{64}', own) is not None
            and own != value['source_runner_sha256'], 'Requirement consumer reused its producer runner')
    for key, observed in [('CRATECTL_REQUIREMENT_FIXTURE_SHA256', digest(raw)),
                          ('CRATECTL_REQUIREMENT_PUBLIC_KEY_SHA256', digest(files['signer-public.pem'])),
                          ('CRATECTL_REQUIREMENT_SOURCE_RUNNER_SHA256', value['source_runner_sha256'])]:
        require(environment.get(key) == observed, 'Requirement input differs from its separate workflow output')


def retained_originals(private, value, files):
    bundle = private / 'requirement offline' / 'bundle'
    parent = strict_json(files['manifest.json'])
    require(parent['profile'] == 'cratectl.go.hosted.requirement-export.v1'
            and len(parent['sources']) == 3 and len(parent['selection']['entries']) == 2,
            'Requirement native parent lost an examined input or selected root')
    for name in FILES:
        if name.startswith('root.'):
            continue
        require((bundle / 'proof' / name).read_bytes() == files[name], 'Original requirement proof/input changed at destination')
    for n, entry in enumerate(parent['selection']['entries']):
        module, version = (MODULE, 'v1.1.0') if n == 0 else (SELECTOR, 'v1.0.0')
        require(entry['module'] == module and entry['version'] == version and entry['repository'] == 'requirements',
                'Owned requirement root differs from its fixed coordinate')
        prefix = module.replace('/Owned/', '/!owned/') + '/@v/' + version
        for k, kind in enumerate(['zip', 'mod', 'info']):
            path = prefix + '.' + kind
            artifact, raw = entry['artifacts'][k], files['root.%03d.%s' % (n, kind)]
            require(artifact['path'] == path and artifact['digest'] == digest(raw) and artifact['size'] == len(raw),
                    'Selected requirement artifact does not bind original bytes')
            require((bundle / 'proxy' / path).read_bytes() == raw, 'Requirement proxy changed selected original bytes')
    for n, source in enumerate(parent['sources']):
        path = source['module'].replace('/Owned/', '/!owned/') + '/@v/' + source['version'] + '.mod'
        require((bundle / 'proxy' / path).read_bytes() == files['input.%04d.mod' % n],
                'Examined original metadata omitted from native proxy')


def consume(private, cli, go, value, files, command, stage, contract):
    collection = private / 'collection'
    collection.mkdir(mode=0o700)
    for name, raw in files.items():
        write_private(collection / name, raw)
    independent = private / 'independent-public.pem'
    write_private(independent, files['signer-public.pem'])
    wrong_fixture = strict_json((Path(__file__).resolve().parents[1] / 'internal/crypto/testdata/journal-checkpoint-public.json').read_bytes())
    wrong_key = base64.b64decode(wrong_fixture['PublicKey'], validate=True)
    require(wrong_key != files['signer-public.pem'], 'Wrong-key control reused the original requirement key')
    wrong_key_path = private / 'unrelated-public.pem'
    write_private(wrong_key_path, wrong_key)
    settings = {'cli': str(cli), 'go': str(go), 'set_id': value['set_id'], 'tenant': value['tenant'],
                'created_sequence': value['created_sequence'], 'through': value['through'],
                'module': value['module'], 'selector': value['selector'], 'lower_input': value['lower_input']}
    write_private(private / 'fixture.json', (json.dumps(settings) + '\n').encode())
    helper = Path(__file__).resolve().parent / 'ci/go_requirement_offline_native.py'
    command([sys.executable, helper, private], timeout=300)
    report_path = private / 'requirement-offline-journey.json'
    require(report_path.stat().st_size <= 64 << 10, 'Requirement native report exceeds its bound')
    report_raw = report_path.read_bytes()
    report = strict_json(report_raw)
    checks = ['production_creation_signature', 'all_original_inputs', 'independent_mvs_replay',
              'native_competing_versions', 'actual_unselected_mod_read', 'selected_discovery_only',
              'historical_verification_without_registry', 'independent_key_head_event_refusals',
              'budget_before_output', 'immutable_completion_replay', 'corrupt_original_refusal',
              'unknown_input_refusal', 'every_empty_command_network', 'actual_acknowledgement_sigpipe',
              'acknowledgement_original_completion_replay']
    require(set(report) == {'profile', 'status', 'examined_sources', 'selected_roots', 'go_version', 'receipt_sha256',
                           'acknowledgement_signal', 'acknowledgement_exit', 'acknowledgement_receipt_sha256', 'download_sha256', 'network_probes', 'checks'}
            and report['profile'] == 'cratectl.go.requirement-offline.native.v2' and report['status'] == 'passed'
            and report['examined_sources'] == 3 and report['selected_roots'] == 2 and report['go_version'] == '1.27.3'
            and report['acknowledgement_signal'] == 'SIGPIPE' and report['acknowledgement_exit'] in (-signal.SIGPIPE,128+signal.SIGPIPE)
            and report['checks'] == checks,
            'Requirement native journey omitted a mandatory control')
    native_probes = {}
    host_namespace = os.stat('/proc/self/ns/net').st_ino
    for name, expected in report['network_probes'].items():
        require(re.fullmatch(r'requirement-network-(?:0[1-9]|1[0-7])\.json', name) is not None,
                'Requirement native probe is outside its fixed inventory')
        body = (private / name).read_bytes()
        require(digest(body) == expected, 'Requirement network probe changed')
        verify_network_probe(body, host_namespace, os.getuid(), os.getgid())
        native_probes[name] = expected
    require(len(native_probes) == 17, 'Requirement journey omitted a native command network')
    contract.update(network_isolated=True, namespace_commands=17, native_journey_sha256=digest(report_raw))
    stage('network_isolation_observed')
    receipt = private / 'requirement offline' / 'bundle' / 'receipt.json'
    require(digest(receipt.read_bytes()) == report['receipt_sha256'], 'Requirement completion changed after SDK verification')
    stage('complete_requirement_proxy_and_sdk')
    acknowledgement = private / 'requirement lost acknowledgement' / 'bundle' / 'receipt.json'
    require(digest(acknowledgement.read_bytes()) == report['acknowledgement_receipt_sha256'],
            'Lost acknowledgement completion changed after exact replay')
    stage('acknowledgement_loss_exact_replay')
    retained_originals(private, value, files)
    stage('original_inputs_and_proof_retained')
    cases = [('changed_parent_refused', 'manifest.json'), ('changed_lower_mod_refused', value['lower_input']),
             ('truncated_journal_refused', 'journal.jsonl'), ('changed_signature_refused', 'checkpoint.sig'),
             ('wrong_independent_key_refused', None), ('wrong_set_refused', None),
             ('copied_unsupported_receipt_refused', 'receipt.json'), ('unknown_member_refused', None)]
    outer_probes = {}
    for n, (name, member) in enumerate(cases):
        inputs, output = private / ('case-%02d-inputs' % n), private / ('case-%02d-output' % n)
        inputs.mkdir(mode=0o700)
        originals = {}
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
            originals[filename] = raw
        args = original_arguments(cli, value, inputs, output, independent)
        if name == 'wrong_independent_key_refused':
            args[args.index('--checkpoint-key-file') + 1] = str(wrong_key_path)
        if name == 'wrong_set_refused':
            args[args.index('--set-id') + 1] = '0' * 64 if value['set_id'] != '0' * 64 else '1' * 64
        if name == 'unknown_member_refused':
            originals['unreviewed-member'] = b'owned input must be preserved'
            write_private(inputs / 'unreviewed-member', originals['unreviewed-member'])
        probe = private / ('outer-probe-%02d.json' % n)
        command([sys.executable, '-c', PROBE_EXEC, probe, NETWORK_PROBE, *args], expected=False, isolated=True)
        body = probe.read_bytes()
        verify_network_probe(body, host_namespace, os.getuid(), os.getgid())
        outer_probes[probe.name] = digest(body)
        require(not output.exists(), 'Refused requirement input created output state')
        require(all((inputs / filename).read_bytes() == raw for filename, raw in originals.items()),
                'Refusal repaired or removed a retained requirement input')
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
            and 0 < len(os.environ.get('RUNNER_NAME', '')) <= 256, 'Actual owned native requirement producer/consumer context required')
    candidate, run_id = os.environ.get('GITHUB_SHA', ''), os.environ.get('GITHUB_RUN_ID', '')
    require(re.fullmatch('[a-f0-9]{40}', candidate) is not None and re.fullmatch('[1-9][0-9]{0,19}', run_id) is not None,
            'Exact native requirement candidate/run required')
    run = uuid.uuid4().hex[:10]
    private = root / '.private/go-requirement-export-portability' / run
    private.mkdir(parents=True, mode=0o700)
    paths = candidate_artifact_names()
    binaries = candidate_binary_directory()
    identities = {name: build_identity(root, name) for name in paths}
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain', '--', 'cmd', 'internal', 'scripts', 'api', 'web', 'go.mod', 'go.sum', 'Makefile'], text=True).strip())
    contract = dict.fromkeys(HASHES)
    contract.update(profile='hosted-requirement-export-cross-runner-v1', role=role, completed=[], go_version=None,
                    source_run_id=run_id, source_arch='amd64', destination_arch='arm64' if role == 'consumer' else None,
                    files_sha256={}, network_isolated=False, network_tools_sha256={}, namespace_commands=0,
                    examined_sources=3, selected_roots=2, automatic_closure=False, checksum_authority=False, destination_admission=False)
    bindings = {'fixture_source_sha256': 'internal/server/go_module_export_collect_integration_test.go',
                'capsule_source_sha256': 'internal/server/go_module_export_requirement_portable_integration_test.go',
                'graph_fixture_source_sha256': 'internal/server/go_module_fixture_test.go',
                'native_helper_sha256': 'scripts/ci/go_requirement_offline_native.py',
                'probe_helper_sha256': 'scripts/ci/go_set_offline_native.py',
                'reader_source_sha256': 'scripts/go_common_export_fixture.py',
                'process_helper_sha256': 'scripts/ci/owned_child_process.py',
                'decoder_sha256': 'scripts/go_requirement_export_fixture.py'}
    for key, path in bindings.items():
        contract[key] = digest((root / path).read_bytes())
    contract['script_sha256'] = digest(Path(__file__).read_bytes())
    checks, commands = [], []
    result = {'run': run, 'candidate': candidate, 'status': 'failed', 'checks': checks, 'commands': commands,
              'source_dirty': dirty, 'build_source_matches_candidate': not dirty and all(v.get('vcs.revision') == candidate and v.get('vcs.modified') == 'false' for v in identities.values()),
              'artifact_digests': {name: digest((root / name).read_bytes()) for name in paths}, 'build_identity': identities,
              'go_requirement_export_portability_contract': contract,
              'limits': ['Owned three-examined-input/two-selected-root graph; artifact/bootstrap transport is online. No package code executes.',
                         'Actual distinct GitHub x86 producer/ARM consumer; empty command networks and original UID; not an offline installer or HA/scale proof.',
                         'Fingerprint job outputs are a separate workflow trust-channel stand-in, not a production issuer/signing service.',
                         'Replayed metadata selection supplies no package/platform closure, public checksum authority or current destination admission. Full GOAL4.1 remains active.']}
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
        require(code == (0 if expected else 1), 'Native requirement command returned an unexpected status')
        require(expected or not output, 'Refused requirement command emitted a success-shaped body')
        return output

    def stage(name):
        require(name == STAGES[role][len(contract['completed'])], 'Native requirement stage order changed')
        contract['completed'].append(name)
        checks.append(name)
        print('PASS: ' + name, flush=True)

    try:
        require(result['build_source_matches_candidate'] and all(v.get('GOOS') == 'linux' and v.get('GOARCH') == ('amd64' if role == 'producer' else 'arm64') for v in identities.values()),
                'Clean exact native requirement CLI/server binaries required')
        go = Path(shutil.which('go')).resolve()
        version = command([go, 'version']).decode().strip()
        require(version.startswith('go version go1.27.3 linux/' + ('amd64' if role == 'producer' else 'arm64')), 'Pinned native Go1.27.3 required')
        contract.update(go_version='1.27.3', go_binary_sha256=digest(go.read_bytes()))
        stage('native_identity')
        if role == 'producer':
            fixture_dir = root / '.cache/go-requirement-export-portable-upload'
            prepare_source_fixture(go, root, fixture_dir, command)
            stage('native_postgresql_requirement_fixture')
            raw = read_requirement_capsule(fixture_dir / 'fixture.json')
        else:
            raw = read_requirement_capsule(root / '.cache/go-requirement-export-portable-download/fixture.json')
        value, files = decode_requirement_fixture(raw, candidate, run_id)
        contract.update(fixture_sha256=digest(raw), public_key_sha256=digest(files['signer-public.pem']),
                        source_runner_sha256=value['source_runner_sha256'], files_sha256={name: digest(body) for name, body in files.items()})
        own = digest(os.environ['RUNNER_NAME'].encode())
        if role == 'producer':
            require(own == value['source_runner_sha256'], 'Actual requirement source runner differs from its retained fixture')
            stage('original_requirement_files_bound')
        else:
            contract['destination_runner_sha256'] = own
            bind_requirement_transport(value, raw, files, own, os.environ)
        stage('transport_bound')
        if role == 'producer':
            with open(os.environ['GITHUB_OUTPUT'], 'a') as target:
                for key in ['fixture_sha256', 'public_key_sha256', 'source_runner_sha256']:
                    target.write('requirement_' + key + '=' + contract[key] + '\n')
        else:
            _, tools = network_prefix(env)
            contract['network_tools_sha256'] = {name: digest(Path(path).read_bytes()) for name, path in tools.items()}
            consume(private, binaries / 'cratectl', go, value, files, command, stage, contract)
        require(not subprocess.check_output(['git', 'status', '--porcelain', '--', 'cmd', 'internal', 'scripts', 'api', 'web', 'go.mod', 'go.sum', 'Makefile'], text=True).strip(),
                'Native requirement journey changed its candidate source')
        result['status'] = 'passed'
    except BaseException as error:
        result['failure'] = type(error).__name__ + ': ' + str(error)[:4096]
        raise
    finally:
        safe_go_requirement_export_portability_contract(contract, result['status'])
        destination = root / 'evidence' / datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / ('go-requirement-export-portability-' + run + '.json')
        with target.open('x') as output:
            json.dump(result, output, indent=2)
            output.write('\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=['producer', 'consumer'])
    main(parser.parse_args().role)
