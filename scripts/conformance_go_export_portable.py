#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Transfer one owned signed Go export between distinct native GitHub jobs.

The fixture is synthetic test input, never a customer export or a release.
Package contents are downloaded/extracted by Go, never compiled or executed.
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid
import urllib.parse
import zipfile

from bounded_client import run_owned_client
from qualification_contract import candidate_artifact_names, candidate_binary_directory
from ci.go_export_portability_evidence import FILES, STAGES, safe_go_export_portability_contract

LIMITS = {'original.zip': 4 << 20, 'original.mod': 1 << 20, 'original.info': 64 << 10,
          'manifest.json': 32 << 10, 'journal.jsonl': 1 << 20, 'checkpoint.json': 16 << 10,
          'signer-public.pem': 4096, 'checkpoint.sig': 64}
CAPSULE_LIMIT = 8 << 20
FIXTURE_FIELDS = {'profile', 'candidate', 'source_run_id', 'source_job', 'source_runner_sha256',
                  'source_os', 'source_arch', 'tenant', 'repository', 'module', 'version',
                  'export_id', 'created_sequence', 'through', 'zip_h1', 'mod_h1', 'files'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('Duplicate fixture JSON property')
        out[key] = value
    return out


def decode_fixture(raw, candidate, run_id):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= CAPSULE_LIMIT:
        raise ValueError('Fixture capsule exceeds its byte bound')
    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or set(value) != FIXTURE_FIELDS:
        raise ValueError('Fixture contains an unreviewed field')
    if (value['profile'] != 'cratectl.go.export.portable.fixture.v1'
            or value['candidate'] != candidate or not re.fullmatch('[a-f0-9]{40}', candidate)
            or value['source_run_id'] != run_id or not re.fullmatch('[1-9][0-9]{0,19}', run_id)
            or value['source_job'] != 'produce' or value['source_os'] != 'linux'
            or value['source_arch'] != 'amd64' or value['tenant'] != 'schema-team'
            or value['repository'] != 'exported' or value['module'] != 'go.cratectl.invalid/Owned/intake'
            or value['version'] != 'v1.0.0'):
        raise ValueError('Fixture is outside the declared owned source/run/coordinate')
    for key in ['source_runner_sha256', 'export_id']:
        if not isinstance(value[key], str) or not re.fullmatch('[a-f0-9]{64}', value[key]):
            raise ValueError('Fixture identity is not a bounded digest')
    for key in ['zip_h1', 'mod_h1']:
        if not isinstance(value[key], str) or not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', value[key]):
            raise ValueError('Fixture requires an exact observed native Go sum')
    through = value['through']
    if (type(value['created_sequence']) is not int or not 1 <= value['created_sequence'] < 1 << 63
            or not isinstance(through, dict) or set(through) != {'tenant', 'sequence', 'hash'}
            or through['tenant'] != value['tenant'] or type(through['sequence']) is not int
            or not value['created_sequence'] <= through['sequence'] < 1 << 63
            or not isinstance(through['hash'], str) or not re.fullmatch('[a-f0-9]{64}', through['hash'])):
        raise ValueError('Fixture requires its complete bounded original journal anchor')
    files = value['files']
    if not isinstance(files, dict) or set(files) != FILES:
        raise ValueError('Fixture file inventory must exclude credentials, private keys and caches')
    decoded = {}
    for name, encoded in files.items():
        if not isinstance(encoded, str) or len(encoded) > ((LIMITS[name] + 2) // 3) * 4:
            raise ValueError('Fixture member exceeds its encoded byte bound')
        body = base64.b64decode(encoded, validate=True)
        if not 0 < len(body) <= LIMITS[name]:
            raise ValueError('Fixture member exceeds its decoded byte bound')
        decoded[name] = body
    if (len(decoded['checkpoint.sig']) != 64
            or not decoded['signer-public.pem'].startswith(b'-----BEGIN PUBLIC KEY-----\n')
            or any(b'PRIVATE KEY-----' in body for body in decoded.values())):
        raise ValueError('Fixture must retain only the declared public verification material')
    return value, decoded


def read_capsule(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= CAPSULE_LIMIT:
            raise ValueError('Fixture must be a bounded regular file')
        raw = source.read(CAPSULE_LIMIT + 1)
    if len(raw) > CAPSULE_LIMIT:
        raise ValueError('Fixture grew beyond its byte bound')
    return raw


def write_private(path, body):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as target:
        target.write(body)
        target.flush()
        os.fsync(target.fileno())


# Keep stdout (a possible success receipt) separate from bounded private stderr.
# Only the producer's Go compilation uses combined capture: compilation writes
# test binaries larger than the fixture commands' regular-file limit.
CAPTURE_CHILD = '''
try:
 import os,resource,sys
 resource.setrlimit(resource.RLIMIT_FSIZE,(8<<20,8<<20))
 fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 os.dup2(fd,1)
 os.close(fd)
 os.execvpe(sys.argv[2],sys.argv[2:],os.environ)
except BaseException:
 os._exit(125)
'''


def network_prefix(environment):
    if os.getuid() == 0:
        raise ValueError('The isolated consumer must return to an ordinary job user')
    tools = {}
    for name in ['sudo', 'unshare', 'setpriv']:
        found = shutil.which(name)
        if not found:
            raise ValueError('The actual native consumer must supply namespace isolation utilities')
        tools[name] = str(Path(found).resolve())
    # Root creates only a fresh child network namespace, then immediately drops
    # back to this job's original UID/GID. The host network remains unchanged.
    return [tools['sudo'], '-n', tools['unshare'], '--net', '--', tools['setpriv'],
            '--reuid', str(os.getuid()), '--regid', str(os.getgid()), '--clear-groups',
            '--', '/usr/bin/env', '-i', *[key + '=' + value for key, value in sorted(environment.items())]], tools


NETWORK_PROBE = '''
import json,os,socket
print(json.dumps({'namespace':os.stat('/proc/self/ns/net').st_ino,'uid':os.getuid(),'gid':os.getgid(),'interfaces':[v[1]for v in socket.if_nameindex()],'ipv4_routes':open('/proc/net/route').read(16384).splitlines()[1:],'ipv6_routes':open('/proc/net/ipv6_route').read(16384).splitlines()},sort_keys=True,separators=(',',':')))
'''


def verify_network_probe(raw, host_namespace, uid, gid):
    if not isinstance(raw, bytes) or len(raw) > 32 << 10:
        raise ValueError('Namespace observation exceeds its byte bound')
    value = json.loads(raw, object_pairs_hook=unique_object)
    if (not isinstance(value, dict) or set(value) != {'namespace', 'uid', 'gid', 'interfaces', 'ipv4_routes', 'ipv6_routes'}
            or type(value['namespace']) is not int or value['namespace'] <= 0 or value['namespace'] == host_namespace
            or type(value['uid']) is not int or type(value['gid']) is not int
            or value['uid'] != uid or value['gid'] != gid or value['interfaces'] != ['lo']
            or value['ipv4_routes'] != [] or not isinstance(value['ipv6_routes'], list)
            or any(not isinstance(line, str) or not line.split() or line.split()[-1] != 'lo' for line in value['ipv6_routes'])):
        raise ValueError('Consumer is not in a distinct empty network namespace under its original identity')
    return digest(raw)


def run_capture(argv, cwd, environment, log, *, combined=False, timeout=60, isolated=False):
    argv = [str(v) for v in argv]
    stdout = Path(str(log) + '.stdout')
    wrapped = argv if combined else [sys.executable, '-c', CAPTURE_CHILD, str(stdout), *argv]
    if isolated:
        if combined:
            raise ValueError('Only the declared file-only consumer commands use isolated capture')
        prefix, _ = network_prefix(environment)
        wrapped = prefix + wrapped
    with os.fdopen(os.open(log, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600), 'wb') as sink:
        code, output = run_owned_client(wrapped, cwd, environment, timeout=timeout,
                                       output_limit=8 << 20, capture_limit=8 << 20, output_sink=sink)
    if combined:
        return code, output.encode()
    # Setup/exec failures are not an expected rejection by the actual CLI.
    if code == 125 or not stdout.exists():
        raise ValueError('Native stdout capture or process execution failed')
    fd = os.open(stdout, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 << 20:
            raise ValueError('Native stdout exceeds its regular-file bound')
        body = source.read((8 << 20) + 1)
    if len(body) > 8 << 20:
        raise ValueError('Native stdout grew beyond its byte bound')
    return code, body


def build_identity(root, path):
    text = subprocess.check_output(['go', 'version', '-m', path], cwd=root, text=True, timeout=10)
    fields = {}
    for line in text.splitlines():
        parts = line.strip().split('\t')
        if len(parts) == 2 and parts[0] == 'build' and '=' in parts[1]:
            key, value = parts[1].split('=', 1)
            fields[key] = value
    return fields


def private_file_proxy(value, output):
    if (not isinstance(value, str) or not 0 < len(value) <= 8192
            or ',' in value or '|' in value or any(ord(c) < 32 for c in value)):
        raise ValueError('Consumer must configure exactly one private file proxy')
    proxy = urllib.parse.urlsplit(value)
    directory = Path(urllib.parse.unquote(proxy.path)).resolve()
    if (proxy.scheme != 'file' or proxy.netloc or proxy.query or proxy.fragment
            or not directory.is_relative_to(output.resolve()) or not directory.is_dir()):
        raise ValueError('Consumer proxy must stay in the newly verified private output')
    return value


def main(role):
    os.umask(0o077)
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('RUNNER_OS') != 'Linux' or role not in STAGES
            or not 0 < len(os.environ.get('RUNNER_NAME', '')) <= 256
            or os.environ.get('GITHUB_JOB') != ('produce' if role == 'producer' else 'consume')
            or os.environ.get('RUNNER_ARCH') != ('X64' if role == 'producer' else 'ARM64')):
        raise ValueError('This journey requires the two declared actual GitHub-hosted jobs')
    candidate, run_id = os.environ.get('GITHUB_SHA', ''), os.environ.get('GITHUB_RUN_ID', '')
    if not re.fullmatch('[a-f0-9]{40}', candidate) or not re.fullmatch('[1-9][0-9]{0,19}', run_id):
        raise ValueError('Native portability requires exact source and workflow identities')
    run = uuid.uuid4().hex[:10]
    private = root / '.private/go-export-portability' / run
    private.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    bin_dir = candidate_binary_directory()
    paths = candidate_artifact_names()
    identities = {name: build_identity(root, name) for name in paths}
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain', '--', 'cmd', 'internal', 'scripts', 'api', 'web', 'go.mod', 'go.sum', 'Makefile'], text=True).strip())
    contract = {'profile': 'hosted-export-cross-runner-v1', 'role': role, 'completed': [],
                'go_version': None, 'source_run_id': run_id, 'source_arch': 'amd64',
                'destination_arch': 'arm64' if role == 'consumer' else None,
                'fixture_sha256': None, 'public_key_sha256': None,
                'source_runner_sha256': None, 'destination_runner_sha256': None,
                'go_binary_sha256': None,
                'fixture_source_sha256': digest((root / 'internal/store/go_module_offline_integration_test.go').read_bytes()),
                'script_sha256': digest(Path(__file__).read_bytes()), 'files_sha256': {}}
    contract.update(network_isolated=False, network_probe_sha256=None, network_tools_sha256={})
    checks, commands = [], []
    result = {'run': run, 'candidate': candidate, 'status': 'failed', 'checks': checks,
              'commands': commands, 'source_dirty': dirty,
              'artifact_digests': {name: digest((root / name).read_bytes()) for name in paths},
              'build_identity': identities, 'build_source_matches_candidate': not dirty and all(v.get('vcs.revision') == candidate and v.get('vcs.modified') == 'false' for v in identities.values()),
              'go_export_portability_contract': contract,
              'limits': ['Synthetic single-version source only; historical policy is not destination admission, SumDB trust, dependency/permission/provenance closure or import.',
                         'Distinct native GitHub VM jobs and architectures; bootstrap/artifact transport is online. Consumer verification/SDK commands use fresh empty kernel network namespaces under the original job UID; no complete offline-install or multi-host HA claim.',
                         'The public-key digest arrives through the producer job output, separately from the fixture artifact. This is an owned workflow trust-channel stand-in, not a production external signer/provider service.',
                         'No fixture package code runs. All broad readiness/450capabilities/41families/laterGOAL4.1scope remains incomplete.']}
    env = {'PATH': os.environ['PATH'], 'GOENV': 'off', 'GOWORK': 'off', 'GOTOOLCHAIN': 'local', 'GOTELEMETRY': 'off'}
    for key in ['LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH']:
        if key in os.environ:
            env[key] = os.environ[key]
    isolated = False

    def command(argv, expected=True, command_env=None, timeout=60, cwd=None, combined=False):
        log = private / ('command-' + uuid.uuid4().hex + '.log')
        item = {'private_log': str(log.relative_to(root)), 'expected_failure': not expected, 'exit': None}
        commands.append(item)
        try:
            code, output = run_capture(argv, cwd or private, command_env or env, log, timeout=timeout, combined=combined, isolated=isolated)
            item['exit'] = code
            if code != (0 if expected else 1):
                item['assertion_failed'] = True
                raise ValueError('Native portable command outcome differs from its required result')
            result['last_observation'] = item
            return output
        except BaseException:
            item['assertion_failed'] = True
            raise

    def stage(name):
        if name != STAGES[role][len(contract['completed'])]:
            raise ValueError('Portability stage order changed')
        contract['completed'].append(name)
        checks.append(name)
        print('PASS: ' + name, flush=True)

    try:
        if (not result['build_source_matches_candidate'] or any(v.get('GOOS') != 'linux' or v.get('GOARCH') != ('amd64' if role == 'producer' else 'arm64') for v in identities.values())):
            raise ValueError('Portability requires clean matching native CLI/server artifacts')
        go = Path(shutil.which('go')).resolve()
        version = command([go, 'version']).decode().strip()
        if not version.startswith('go version go1.27.3 linux/' + ('amd64' if role == 'producer' else 'arm64')):
            raise ValueError('Exact native Go1.27.3 required')
        contract['go_version'], contract['go_binary_sha256'] = '1.27.3', digest(go.read_bytes())
        stage('native_identity')
        if role == 'producer':
            fixture_dir = root / '.cache/go-export-portable-upload'
            native_env = {**os.environ, 'CRATECTL_GO_EXPORT_PORTABLE_OUT': str(fixture_dir)}
            command([go, 'test', '-count=1', '-tags=integration', '-run', '^TestGoModuleExportSignedManifestNativeOfflineSDK$', './internal/store'], command_env=native_env, timeout=300, cwd=root, combined=True)
            stage('native_postgresql_fixture')
            raw = read_capsule(fixture_dir / 'fixture.json')
        else:
            raw = read_capsule(root / '.cache/go-export-portable-download/fixture.json')
        value, files = decode_fixture(raw, candidate, run_id)
        contract['fixture_sha256'] = digest(raw)
        contract['public_key_sha256'] = digest(files['signer-public.pem'])
        contract['source_runner_sha256'] = value['source_runner_sha256']
        contract['files_sha256'] = {name: digest(body) for name, body in files.items()}
        own_runner = digest(os.environ.get('RUNNER_NAME', '').encode())
        if role == 'producer':
            if own_runner != value['source_runner_sha256']:
                raise ValueError('Source runner observation differs from fixture')
        else:
            contract['destination_runner_sha256'] = own_runner
            for key, observed in [('CRATECTL_PORTABLE_FIXTURE_SHA256', digest(raw)), ('CRATECTL_PORTABLE_PUBLIC_KEY_SHA256', contract['public_key_sha256']), ('CRATECTL_PORTABLE_SOURCE_RUNNER_SHA256', value['source_runner_sha256'])]:
                if os.environ.get(key) != observed:
                    raise ValueError('Fixture differs from separately supplied source job output')
            if own_runner == value['source_runner_sha256']:
                raise ValueError('Consumer reused the producer runner')
        stage('transport_bound')
        if role == 'producer':
            with open(os.environ['GITHUB_OUTPUT'], 'a') as target:
                for key in ['fixture_sha256', 'public_key_sha256', 'source_runner_sha256']:
                    target.write(key + '=' + contract[key] + '\n')
        else:
            _, tools = network_prefix(env)
            contract['network_tools_sha256'] = {name: digest(Path(path).read_bytes()) for name, path in tools.items()}
            isolated = True
            observation = command([sys.executable, '-c', NETWORK_PROBE])
            contract['network_probe_sha256'] = verify_network_probe(observation, os.stat('/proc/self/ns/net').st_ino, os.getuid(), os.getgid())
            contract['network_isolated'] = True
            stage('network_isolation_observed')
            consume(private, bin_dir / 'cratectl', go, value, files, command, stage, env)
        if subprocess.check_output(['git', 'status', '--porcelain', '--', 'cmd', 'internal', 'scripts', 'api', 'web', 'go.mod', 'go.sum', 'Makefile'], text=True).strip():
            result['source_dirty'] = True
            result['build_source_matches_candidate'] = False
            raise ValueError('Native journey changed its clean candidate source')
        result['status'] = 'passed'
    except BaseException as error:
        result['failure'] = type(error).__name__ + ': ' + str(error)[:4096]
        raise
    finally:
        safe_go_export_portability_contract(contract, result['status'])
        target = root / 'evidence' / datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        target.mkdir(parents=True, exist_ok=True)
        (target / ('go-export-portability-' + run + '.json')).write_text(json.dumps(result, indent=2) + '\n')


def consume(private, cli, go, value, files, command, stage, env):
    write_private(private / 'go.mod', b'module go.cratectl.invalid/portable-consumer\n\ngo 1.27.3\n')
    inputs = private / 'inputs'
    inputs.mkdir(mode=0o700)
    for name, body in files.items():
        write_private(inputs / name, body)
    output = private / 'offline export'
    args = [cli, 'go-module-offline', '--repository', value['repository'], '--module', value['module'], '--version', value['version'],
            '--zip-file', inputs / 'original.zip', '--mod-file', inputs / 'original.mod', '--info-file', inputs / 'original.info',
            '--manifest-file', inputs / 'manifest.json', '--export-id', value['export_id'], '--output-directory', output,
            '--journal-file', inputs / 'journal.jsonl', '--journal-tenant', value['tenant'], '--journal-event-sequence', str(value['created_sequence']),
            '--journal-through', str(value['through']['sequence']), '--journal-through-hash', value['through']['hash'],
            '--checkpoint-file', inputs / 'checkpoint.json', '--checkpoint-signature-file', inputs / 'checkpoint.sig', '--checkpoint-key-file', inputs / 'signer-public.pem']
    receipt = json.loads(command(args))
    history = receipt['journal_attribution']['journal']
    if (receipt['profile'] != 'cratectl.go.hosted.offline.v1'
            or receipt['current_registry_admission'] is not False or receipt['checksum_authority_verified'] is not False
            or receipt['export_snapshot']['id'] != value['export_id']
            or receipt['export_snapshot']['manifest_sha256'] != digest(files['manifest.json'])
            or receipt['journal_attribution']['event_sequence'] != value['created_sequence']
            or receipt['journal_attribution']['checkpoint_signature']['signature_verified'] is not True
            or history['matches_supplied_checkpoint'] is not True or history['export_sha256'] != digest(files['journal.jsonl'])
            or history['tenant'] != value['tenant'] or history['head_sequence'] != value['through']['sequence'] or history['head_hash'] != value['through']['hash']
            or receipt['zip_h1'] != value['zip_h1'] or receipt['mod_h1'] != value['mod_h1']
            or (output / 'export-manifest.json').read_bytes() != files['manifest.json']):
        raise ValueError('Independent native CLI did not bind exact signed export history')
    stage('signed_export_verified')
    private_file_proxy(receipt['goproxy'], output)
    sdk_env = {**env, 'GOAUTH': 'off', 'GOVCS': '*:off', 'GOPROXY': receipt['goproxy'], 'GOSUMDB': 'off', 'GONOSUMDB': '*', 'GONOPROXY': 'none', 'GOPRIVATE': '', 'GOFLAGS': '', 'GOCACHE': str(private / 'go-build'), 'GOMODCACHE': str(private / 'go-mod'), 'GOPATH': str(private / 'go-path')}
    failed = False
    try:
        downloaded = json.loads(command([go, 'mod', 'download', '-json', value['module'] + '@' + value['version']], command_env=sdk_env))
        extracted = Path(downloaded['Dir']).resolve()
        if not extracted.is_relative_to((private / 'go-mod').resolve()):
            raise ValueError('SDK extraction must stay in the fresh private cache')
        with (extracted / 'assets/owned.txt').open('rb') as asset:
            inert = asset.read(1024)
        if (downloaded.get('Error')
                or downloaded.get('Path') != value['module'] or downloaded.get('Version') != value['version']
                or downloaded['Sum'] != value['zip_h1'] or downloaded['GoModSum'] != value['mod_h1']
                or inert != b'original bytes'):
            raise ValueError('Independent stock Go did not extract original inert bytes and sums')
        stage('stock_go_exact_bytes')
        if command(args, expected=False):
            raise ValueError('Existing output emitted a false receipt')
        if (output / 'export-manifest.json').read_bytes() != files['manifest.json']:
            raise ValueError('Existing output changed after rejected overwrite')
        stage('existing_output_rejected')
        changed_zip = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(files['original.zip'])) as original, zipfile.ZipFile(changed_zip, 'w', zipfile.ZIP_DEFLATED) as changed:
            prefix = value['module'] + '@' + value['version'] + '/'
            if len(original.infolist()) != 2 or set(original.namelist()) != {prefix + 'go.mod', prefix + 'assets/owned.txt'} or any(info.file_size > 1 << 20 for info in original.infolist()):
                raise ValueError('Only the declared small inert ZIP fixture may be changed')
            for name in original.namelist():
                changed.writestr(name, b'altered inert bytes' if name.endswith('/assets/owned.txt') else original.read(name))
        manifest = files['manifest.json'].replace(b'"require_review":true', b'"require_review":false', 1)
        if manifest == files['manifest.json']:
            raise ValueError('Owned source manifest lacks the required review control')
        prefix = files['journal.jsonl'].rstrip(b'\n').rsplit(b'\n', 1)[0] + b'\n'
        wrong_private, wrong_public = private / 'wrong-private.pem', private / 'wrong-public.pem'
        command(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', wrong_private])
        wrong_private.chmod(0o600)
        command(['openssl', 'pkey', '-in', wrong_private, '-pubout', '-out', wrong_public])
        cases = [('changed_manifest_rejected', '--manifest-file', manifest),
                 ('changed_zip_rejected', '--zip-file', changed_zip.getvalue()),
                 ('truncated_journal_rejected', '--journal-file', prefix),
                 ('changed_statement_rejected', '--checkpoint-file', files['checkpoint.json'] + b' '),
                 ('changed_signature_rejected', '--checkpoint-signature-file', bytes([files['checkpoint.sig'][0] ^ 1]) + files['checkpoint.sig'][1:]),
                 ('wrong_key_rejected', '--checkpoint-key-file', wrong_public.read_bytes()),
                 ('wrong_export_rejected', '--export-id', '0' * 64)]
        for label, flag, replacement in cases:
            dest, body = private / label, private / (label + '.input')
            negative = list(args)
            negative[negative.index('--output-directory') + 1] = dest
            if isinstance(replacement, bytes):
                write_private(body, replacement)
                replacement = body
            negative[negative.index(flag) + 1] = replacement
            if command(negative, expected=False) or dest.exists():
                raise ValueError('Changed native input produced success or a destination proxy')
            stage(label)
    except BaseException:
        failed = True
        raise
    finally:
        try:
            command([go, 'clean', '-modcache'], command_env=sdk_env)
        except BaseException:
            if not failed:
                raise  # Preserve the first failure; both private logs remain.


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=['producer', 'consumer'])
    main(parser.parse_args().role)
