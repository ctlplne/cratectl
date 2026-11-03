#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Docker, Podman and Helm use a real isolated registry/PostgreSQL fixture.

Images contain only owned text files. No RUN instruction, image entrypoint,
package script, chart hook or application is executed. Containers are created
only to copy installed filesystem bytes, then removed by their owned names.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from oci_client_contract import new_podman_runroot, read_owned_file, validate_podman_runroot
from ci.native_client_diagnostics import safe_client_diagnostics
from qualification_contract import CURRENT_SCHEMA, candidate_binary_directory, validate_historical_build

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-clean-build', action='store_true')
parser.add_argument('--binary-directory', type=Path)
args = parser.parse_args()
ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
os.umask(0o077)
BIN = candidate_binary_directory(args.binary_directory)
SERVER, CLI = BIN / 'cratectld', BIN / 'cratectl'
HELM = ROOT / '.cache/bin/helm'
PSQL = ROOT / '.cache/postgresql-16.15-install/bin/psql'
RUN = uuid.uuid4().hex[:10]
PRIVATE = ROOT / '.private/oci-client-conformance' / RUN
PRIVATE.mkdir(parents=True, mode=0o700)
BASE, REGISTRY = 'http://127.0.0.1:38443', '127.0.0.1:38443'
ARCH = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
OTHER_ARCH = 'arm64' if ARCH == 'amd64' else 'amd64'
REPOS = {kind: 'cratectl-client-' + RUN + '-' + kind for kind in ['hosted', 'origin', 'proxy', 'fallback', 'host-group', 'proxy-group']}
checks, commands, tokens, auth, created, images = [], [], {}, {}, [], set()
env, runtime = dict(os.environ), {}
process, server_log = None, None
PODMAN_RUNROOT = None
LOCK = threading.RLock()
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ACCEPT = ', '.join(['application/vnd.oci.image.index.v1+json', 'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json', 'application/vnd.docker.distribution.manifest.v2+json'])
candidate = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
scope = ['cmd', 'internal', 'scripts', 'web', 'api', 'go.mod', 'go.sum', 'Makefile']
result = {'candidate': candidate, 'run': RUN, 'status': 'running', 'phase': 'preflight', 'checks': checks, 'commands': commands,
          'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain', '--', *scope]).strip()),
          'artifact_digests': {}, 'build_identity': {}, 'client_versions': {}, 'client_binary_sha256': {}, 'client_packages': {}, 'subjects': [],
          'topology': 'Native Linux Docker daemon, separate private Podman VFS store, Helm4, real restricted PostgreSQL on35432 and registry on38443; upstream is a separate tenant on the same real registry process.',
          'limits': ['Named stock-client hosted/proxy/group, layered/multi-architecture metadata, dependency, authorization/policy, tenant and restart journeys only; no full OCI or release readiness.',
                     'No image, application, package script or chart hook is started. Foreign-platform images use scratch and COPY only; no foreign CPU execution or emulator qualification.',
                     'One host, filesystem CAS and explicit loopback HTTP development profile; not production TLS, independent vendor upstream, independent-host HA, retention/GC, scale or all client failure modes.',
                     'Docker and buildx come from the recorded GitHub runner image. Helm archive and Podman CLI4.9.3 are pinned; the installed Ubuntu security revision/architecture and client binary hashes are retained. Other client versions, build tools, signatures and attachments remain required.']}


def private(name, body):
    path = PRIVATE / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body if isinstance(body, bytes) else json.dumps(body).encode())
    path.chmod(0o600)
    return path


def checkpoint():
    with LOCK:
        private('progress.json', result)


def phase(name):
    result['phase'] = name
    checkpoint()


def check(label, condition):
    if not condition:
        raise AssertionError(label)
    with LOCK:
        checks.append(label)
        checkpoint()
    print('PASS: ' + label, flush=True)


def command(argv, label, *, stdin=None, extra=None, owner=False, ok=True, timeout=180):
    command_env = dict(env)
    if not owner:
        for key in ['CRATECTL_OWNER_DSN', 'CRATECTL_DSN', 'GITHUB_TOKEN', 'GH_TOKEN', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']:
            command_env.pop(key, None)
    command_env.update(extra or {})
    path = private('command-' + uuid.uuid4().hex + '.log', b'')
    entry = {'label': label, 'binary': Path(str(argv[0])).name, 'expected_success': ok, 'private_log': str(path.relative_to(ROOT))}
    with LOCK:
        commands.append(entry)
    started = time.monotonic()
    try:
        with path.open('ab') as output:
            completed = subprocess.run([str(v) for v in argv], input=stdin, env=command_env, cwd=PRIVATE,
                                       stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
        with LOCK:
            entry['exit'] = completed.returncode
        if path.stat().st_size > 8 << 20:
            raise AssertionError('native client command exceeded its observation budget: ' + label)
        raw = read_owned_file(PRIVATE, path, 8 << 20)
        if ok is not None and (completed.returncode == 0) != ok:
            # Keep raw output private. Only fixed categories may reach CI logs.
            lower = raw.lower()
            category = next((kind for marker, kind in [(b'http response to https', 'tls_profile'), (b'unauthorized:', 'authorization'), (b'authentication required', 'authorization'), (b'requested access to the resource is denied', 'authorization'), (b'connection refused', 'connection'), (b'unknown flag:', 'client_flag'), (b'manifest unknown', 'manifest_missing'), (b'blob unknown', 'blob_missing'), (b'no matching manifest', 'platform_selection')] if marker in lower), 'unclassified')
            with LOCK:
                result['command_failure_kind'] = category
                result['command_diagnostics'] = safe_client_diagnostics(raw)
            print('Native client error markers: ' + ','.join(result['command_diagnostics']), flush=True)
            raise AssertionError('native client command failed: ' + label + '; category=' + category)
        return raw
    finally:
        with LOCK:
            entry['seconds'] = round(time.monotonic() - started, 3)
        checkpoint()


def http(path, method='GET', value=None, role='admin', headers=None):
    fields = {'Authorization': 'Bearer ' + tokens[role], **(headers or {})}
    if isinstance(value, dict):
        value = json.dumps(value).encode()
        fields['Content-Type'] = 'application/json'
    if method in ['POST', 'PUT', 'DELETE']:
        fields['Idempotency-Key'] = uuid.uuid4().hex
    request = urllib.request.Request(BASE + path, data=value, method=method, headers=fields)
    try:
        response = HTTP.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read((8 << 20) + 1)
        if len(raw) > 8 << 20:
            raise AssertionError('owned HTTP observation exceeded its byte budget')
        return response.status, raw, response.headers


def value(path, role='admin'):
    status, body, _ = http(path, role=role)
    if status != 200:
        raise AssertionError('owned management observation returned status ' + str(status))
    return json.loads(body)


def stop():
    global process, server_log
    if process is not None:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        process = None
    if server_log is not None:
        server_log.close()
        server_log = None


def start():
    global process, server_log
    server_log = (PRIVATE / 'registry.log').open('ab')
    process = subprocess.Popen([str(SERVER), 'serve', '--listen', '127.0.0.1:38443', '--public-url', BASE,
                                '--dev-loopback-http', '--objects', str(PRIVATE / 'objects'),
                                '--allow-private-upstreams', '127.0.0.1/32', '--upstream-credentials', str(PRIVATE / 'upstreams.json')],
                               env=runtime, stdout=server_log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError('owned registry exited; inspect private registry log')
        try:
            with HTTP.open(BASE + '/health/ready', timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(.05)
    raise AssertionError('owned registry readiness observation expired')


def docker(role, arguments, label, **options):
    # Docker's manifest client collapses several transport errors into a
    # generic lookup failure. Debug detail stays in encrypted private logs.
    debug = ['--debug'] if arguments and arguments[0] == 'manifest' else []
    return command(['docker', *debug, '--host', 'unix:///var/run/docker.sock', '--config', auth[role]['docker'], *arguments], label, **options)


def podman(role, arguments, label, **options):
    if PODMAN_RUNROOT is None:
        raise AssertionError('owned Podman runtime directory is not initialized')
    return command(['sudo', '-n', 'podman', '--root', PRIVATE / 'podman-root', '--runroot', PODMAN_RUNROOT[0],
                    '--storage-driver', 'vfs', '--events-backend', 'file', *arguments], label,
                   extra={'REGISTRY_AUTH_FILE': str(auth[role]['podman'])}, **options)


def helm(role, arguments, label, **options):
    return command([HELM, *arguments, '--registry-config', auth[role]['helm']], label,
                   extra={'HELM_CACHE_HOME': str(auth[role]['home'] / 'cache'), 'HELM_CONFIG_HOME': str(auth[role]['home'] / 'config'),
                          'HELM_DATA_HOME': str(auth[role]['home'] / 'data'), 'HELM_PLUGINS': str(PRIVATE / 'empty-plugins')}, **options)


def repo(kind, role='admin', **settings):
    check('create ' + kind + ' repository for ' + role,
          http('/api/v1/repositories', 'POST', {'name': REPOS[kind], 'format': 'oci', **settings}, role)[0] == 201)


def grant(kind, actor, read=True, write=False):
    check('set ' + actor + ' grant on ' + kind,
          http('/api/v1/repositories/' + REPOS[kind] + '/grants', 'PUT', {'actor': actor, 'read': read, 'write': write})[0] == 200)


def ref(kind, tag, image='payload'):
    return REGISTRY + '/' + REPOS[kind] + '/' + image + ('@' if tag.startswith('sha256:') else ':') + tag


def graph(kind, tag, role='admin', image='payload'):
    path = '/v2/' + REPOS[kind] + '/' + image + '/'
    status, raw, headers = http(path + 'manifests/' + tag, role=role, headers={'Accept': ACCEPT})
    check(kind + ' ' + image + ' ' + tag + ' root has exact immutable bytes', status == 200 and headers.get('Docker-Content-Digest') == 'sha256:' + hashlib.sha256(raw).hexdigest())
    root_digest, root = headers['Docker-Content-Digest'], json.loads(raw)
    manifest, native_digest = root, root_digest
    if 'manifests' in root:
        candidates = [d for d in root['manifests'] if d.get('platform', {}).get('os') == 'linux' and d.get('platform', {}).get('architecture') == ARCH]
        check('multi-architecture index has exactly one native selection', len(candidates) == 1)
        descriptor = candidates[0]
        status, raw, _ = http(path + 'manifests/' + descriptor['digest'], role=role, headers={'Accept': ACCEPT})
        check('selected native manifest matches declared index bytes', status == 200 and len(raw) == descriptor['size'] and 'sha256:' + hashlib.sha256(raw).hexdigest() == descriptor['digest'])
        manifest = json.loads(raw)
        native_digest = descriptor['digest']
    descriptors = [manifest['config'], *manifest['layers']]
    check('native graph has bounded config and payload descriptors', 1 < len(descriptors) <= 16)
    for descriptor in descriptors:
        status, body, _ = http(path + 'blobs/' + descriptor['digest'], role=role)
        check('native graph member bytes match declared digest and length', status == 200 and len(body) == descriptor['size'] and 'sha256:' + hashlib.sha256(body).hexdigest() == descriptor['digest'])
    result['subjects'].append({'repository': kind, 'image': image, 'reference': tag, 'digest': root_digest, 'native_manifest_digest': native_digest,
                               'members': [{'digest': d['digest'], 'size': d['size']} for d in descriptors]})
    return {'digest': root_digest, 'manifest': manifest, 'index': root}


def decision(kind, target, outcome, image='payload'):
    path = image + '/' + target['kind'] + '/' + target['digest']
    check(kind + ' exact digest decision ' + outcome,
          http('/api/v1/repositories/' + REPOS[kind] + '/decisions', 'PUT', {'path': path, 'digest': target['digest'].removeprefix('sha256:'), 'decision': outcome})[0] == 200)


def lifecycle(kind, digest, action, image='payload'):
    path = image + '/manifests/' + digest
    endpoint = '/api/v1/repositories/' + REPOS[kind] + '/artifacts/lifecycle'
    current = value(endpoint + '?' + urllib.parse.urlencode({'path': path}))
    body = {'path': path, 'digest': digest.removeprefix('sha256:'), 'action': action,
            'expected_revision': current['revision'], 'reason': 'Owned native client retained lifecycle proof'}
    check('native client lifecycle preview ' + action, http(endpoint, 'PUT', {**body, 'dry_run': True})[0] == 200)
    check('preview preserves current native lifecycle revision', value(endpoint + '?' + urllib.parse.urlencode({'path': path}))['revision'] == current['revision'])
    check('native client lifecycle apply ' + action, http(endpoint, 'PUT', {**body, 'dry_run': False})[0] == 200)


def build_image(tag, body, architecture=ARCH, kind='hosted', role='writer'):
    folder = PRIVATE / ('build-' + uuid.uuid4().hex[:8])
    folder.mkdir()
    (folder / 'dependency.txt').write_bytes(DEPENDENCY)
    (folder / 'app.txt').write_bytes(body)
    (folder / 'Dockerfile').write_text('FROM scratch\nCOPY dependency.txt /cratectl-dependency.txt\nCOPY app.txt /cratectl-app.txt\nLABEL dev.cratectl.conformance.run="' + RUN + '"\n')
    target = ref(kind, tag)
    docker(role, ['build', '--network=none', '--provenance=false', '--platform', 'linux/' + architecture, '--tag', target, folder], 'build owned scratch COPY fixture ' + tag)
    images.add(target)
    docker(role, ['image', 'push', '--platform', 'linux/' + architecture, target], 'Docker publishes ' + kind + ' ' + tag)
    return target


def image_bytes(client, kind, tag, expected, role='reader', ok=True, expected_status=403):
    target = ref(kind, tag)
    if not ok:
        check('independent image denial control has the required HTTP status', http('/v2/' + REPOS[kind] + '/payload/manifests/' + tag, role=role, headers={'Accept': ACCEPT})[0] == expected_status)
    if client == 'docker':
        docker(role, ['image', 'pull', target], 'Docker pull ' + kind + ' ' + tag, ok=ok)
        if not ok:
            return
        with LOCK:
            images.add(target)
    else:
        podman(role, ['pull', '--tls-verify=false', '--authfile', auth[role]['podman'], target], 'Podman pull ' + kind + ' ' + tag, ok=ok)
        if not ok:
            return
    call = docker if client == 'docker' else podman
    image = json.loads(call(role, ['image', 'inspect', '--format', '{{json .}}', target], 'observe selected native image identity'))
    check(client + ' selects this native architecture and owned image', image['Os'] == 'linux' and image['Architecture'] == ARCH and image['Config']['Labels']['dev.cratectl.conformance.run'] == RUN)
    name = 'cratectl-oci-' + RUN + '-' + uuid.uuid4().hex[:8]
    if client == 'docker':
        docker(role, ['container', 'create', '--name', name, '--label', 'ctlplne.project=cratectl', '--network=none', '--pull=never', '--entrypoint', '/cratectl-never-executed', target], 'create stopped Docker observation')
    else:
        podman(role, ['create', '--name', name, '--label', 'ctlplne.project=cratectl', '--network=none', '--cgroups=disabled', '--pull=never', '--entrypoint', '/cratectl-never-executed', target], 'create stopped Podman observation')
    with LOCK:
        created.append((client, role, name))
    state = json.loads(call(role, ['inspect', '--format', '{{json .State}}', name], 'inspect never-started ' + client + ' state'))
    check(client + ' package observation never starts its image', state['Running'] is False and state['Status'] in ['created', 'configured'])
    for filename, body in [('cratectl-app.txt', expected), ('cratectl-dependency.txt', DEPENDENCY)]:
        destination = PRIVATE / ('copy-' + uuid.uuid4().hex)
        call(role, ['cp', name + ':/' + filename, destination], client + ' copies installed fixture bytes')
        check(client + ' ' + kind + ' ' + tag + ' exact installed ' + filename, read_owned_file(PRIVATE, destination, 1 << 20) == body)
    call(role, ['rm', name], 'remove owned stopped ' + client + ' container')
    with LOCK:
        created.remove((client, role, name))


def chart_package(name, version, body, repository=None, dependency_version=None, role='admin'):
    folder = PRIVATE / ('chart-' + uuid.uuid4().hex[:8]) / name
    folder.mkdir(parents=True)
    chart = {'apiVersion': 'v2', 'name': name, 'version': version, 'description': 'Owned opaque cratectl client fixture'}
    if repository:
        chart['dependencies'] = [{'name': 'cratectl-dependency', 'version': dependency_version, 'repository': 'oci://' + REGISTRY + '/' + REPOS[repository]}]
    (folder / 'Chart.yaml').write_text(json.dumps(chart))
    (folder / 'values.yaml').write_text(json.dumps({'fixture': body}))
    if repository:
        helm(role, ['dependency', 'build', folder, '--plain-http'], 'Helm resolves declared chart dependency')
        dependency = folder / 'charts' / ('cratectl-dependency-' + dependency_version + '.tgz')
        check('Helm dependency build retrieves exact packaged dependency', read_owned_file(PRIVATE, dependency, 4 << 20) == CHARTS[dependency_version])
    helm(role, ['package', folder, '--destination', folder.parent], 'Helm packages owned chart ' + name + ' ' + version)
    package = folder.parent / (name + '-' + version + '.tgz')
    return package, read_owned_file(PRIVATE, package, 4 << 20)


def chart_bytes(kind, name, version, expected, role='reader', ok=True, expected_status=403):
    destination = PRIVATE / ('helm-pull-' + uuid.uuid4().hex[:8])
    destination.mkdir()
    if not ok:
        check('independent chart denial control has the required HTTP status', http('/v2/' + REPOS[kind] + '/' + name + '/manifests/' + version, role=role, headers={'Accept': ACCEPT})[0] == expected_status)
    helm(role, ['pull', 'oci://' + REGISTRY + '/' + REPOS[kind] + '/' + name, '--version', version, '--plain-http', '--destination', destination], 'Helm pull ' + kind + ' ' + name, ok=ok)
    if ok:
        check('Helm ' + kind + ' retains exact chart package bytes', read_owned_file(PRIVATE, destination / (name + '-' + version + '.tgz'), 4 << 20) == expected)


DEPENDENCY = b'owned shared dependency layer\n' * 1024
APP1 = ('owned native linux/' + str(ARCH) + ' application version1\n').encode() * 512
APP2 = ('owned native linux/' + str(ARCH) + ' application version2\n').encode() * 512
FALLBACK = b'owned fallback must never replace denied primary\n'
OTHER = b'owned independent tenant with the same coordinate\n'
CHARTS = {}
result['fixture_sha256'] = {name: hashlib.sha256(body).hexdigest() for name, body in [('application_v1', APP1), ('application_v2', APP2), ('dependency', DEPENDENCY), ('fallback', FALLBACK), ('other_tenant', OTHER), ('foreign_platform', b'owned alternate platform metadata fixture\n')]}
try:
    phase('preflight')
    check('native Linux amd64 or arm64 client host', platform.system() == 'Linux' and ARCH in ['amd64', 'arm64'])
    PODMAN_RUNROOT = new_podman_runroot(RUN)
    check('owned Podman runtime path fits the native 50-byte limit', len(os.fsencode(PODMAN_RUNROOT[0])) <= 50)
    with socket.socket() as probe:
        check('owned registry port38443 is free', probe.connect_ex(('127.0.0.1', 38443)) != 0)
    check('selected native binaries stay inside this workspace', all(p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(ROOT) for p in [SERVER, CLI]))
    for binary in [SERVER, CLI]:
        metadata = subprocess.check_output([ROOT / '.cache/go/bin/go', 'version', '-m', binary], text=True)
        key = str(binary.relative_to(ROOT))
        result['build_identity'][key] = validate_historical_build(metadata, candidate, 'linux', ARCH)
        with binary.open('rb') as source:
            result['artifact_digests'][key] = hashlib.file_digest(source, 'sha256').hexdigest()
    result['build_source_matches_candidate'] = True
    if args.require_clean_build:
        check('selected source and binaries are one clean exact native candidate', not result['source_dirty'])
    result['host'] = {'os': platform.system(), 'architecture': ARCH, 'runner_image': os.environ.get('ImageVersion', '')}
    for name, file in [('docker', Path(shutil.which('docker') or '/missing/docker')), ('podman', Path(shutil.which('podman') or '/missing/podman')), ('helm', HELM)]:
        with file.open('rb') as binary:
            result['client_binary_sha256'][name] = hashlib.file_digest(binary, 'sha256').hexdigest()
    docker_version = json.loads(command(['docker', '--host', 'unix:///var/run/docker.sock', 'version', '--format', '{{json .}}'], 'observe native Docker client and engine'))
    check('Docker engine is native Linux on this host', docker_version['Server']['Os'] == 'linux' and docker_version['Server']['Arch'] == ARCH)
    result['client_versions'].update(docker=docker_version['Client']['Version'], docker_engine=docker_version['Server']['Version'])
    result['client_versions']['podman'] = command(['podman', '--version'], 'observe Podman version').decode().strip().removeprefix('podman version ')
    check('Podman CLI has the reviewed upstream version', result['client_versions']['podman'] == '4.9.3')
    package = command(['dpkg-query', '--show', '--showformat=${Version}|${Architecture}', 'podman'], 'observe installed Podman package identity').decode().strip().split('|')
    check('installed Podman package has this native architecture', len(package) == 2 and package[1] == ARCH)
    result['client_packages']['podman'] = {'version': package[0], 'architecture': package[1]}
    result['client_versions']['helm'] = command([HELM, 'version', '--short'], 'observe Helm version').decode().strip().removeprefix('v')
    buildx = command(['docker', 'buildx', 'version'], 'observe buildx version').decode().split()
    result['client_versions']['buildx'] = next(v.removeprefix('v') for v in buildx if re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?', v))
    phase('database')
    owner = urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN'])
    check('owned PostgreSQL is loopback35432', owner.hostname == '127.0.0.1' and owner.port == 35432)
    database = 'cratectl_oci_clients_' + RUN
    pgenv = dict(env, PGHOST=owner.hostname, PGPORT=str(owner.port), PGUSER=urllib.parse.unquote(owner.username), PGPASSWORD=urllib.parse.unquote(owner.password), PGDATABASE=owner.path[1:])
    command([PSQL, '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', 'CREATE DATABASE ' + database], 'create isolated OCI client database', owner=True, extra=pgenv)
    for key in ['CRATECTL_OWNER_DSN', 'CRATECTL_DSN']:
        address = urllib.parse.urlsplit(env[key])
        env[key] = urllib.parse.urlunsplit((address.scheme, address.netloc, '/' + database, address.query, address.fragment))
    private('database.json', {'owner': env['CRATECTL_OWNER_DSN'], 'runtime': env['CRATECTL_DSN']})
    command([SERVER, 'migrate'], 'migrate isolated OCI client fixture', owner=True)
    plan = json.loads(command([SERVER, 'migrate', '--plan'], 'observe isolated schema receipts', owner=True))
    check('isolated schema has every current safe receipt', plan['binary_version'] == CURRENT_SCHEMA and len(plan['applied']) == CURRENT_SCHEMA and plan['safety_valid'] and not plan['pending'])
    address = urllib.parse.urlsplit(env['CRATECTL_DSN'])
    check('runtime connection stays on the owned endpoint with a distinct role', address.hostname == owner.hostname and address.port == owner.port and address.username != owner.username)
    runtime_pg = dict(PGHOST=address.hostname, PGPORT=str(address.port), PGUSER=urllib.parse.unquote(address.username), PGPASSWORD=urllib.parse.unquote(address.password), PGDATABASE=database)
    privilege = command([PSQL, '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', "SELECT (rolsuper OR rolbypassrls OR current_user=(SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()))::int FROM pg_roles WHERE rolname=current_user"], 'observe actual runtime role boundary', extra=runtime_pg)
    check('runtime connection is nonsuperuser nonowner without BYPASSRLS', privilege.strip() == b'0')
    rls = command([PSQL, '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', "SELECT count(*),bool_and(c.relrowsecurity AND c.relforcerowsecurity AND c.relowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user)) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='cratectl' AND c.relkind IN ('r','p') AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant' AND NOT a.attisdropped)"], 'observe forced tenant table RLS', extra=runtime_pg).decode().strip().split('|')
    check('every observed durable tenant table has forced RLS', len(rls) == 2 and int(rls[0]) > 0 and rls[1] == 't')
    tenant = 'oci-clients-' + RUN
    for role, permission, target in [('admin', 'admin', tenant), ('writer', 'writer', tenant), ('reader', 'reader', tenant), ('revocable', 'reader', tenant), ('origin', 'admin', tenant + '-origin')]:
        token_file = PRIVATE / (role + '.token')
        command([SERVER, 'provision', '--tenant', target, '--actor', role, '--role', permission, '--token-file', token_file], 'provision ' + role, owner=True)
        tokens[role] = read_owned_file(PRIVATE, token_file, 4096).decode().strip()
        home = PRIVATE / ('auth-' + role)
        (home / 'docker').mkdir(parents=True)
        private('auth-' + role + '/docker/config.json', {})
        auth[role] = {'home': home, 'docker': home / 'docker', 'podman': home / 'podman.json', 'helm': home / 'helm.json'}
    private('upstreams.json', {tenant + '/origin': {'value': tokens['origin'], 'allowed_url': BASE + '/v2/' + REPOS['origin'] + '/'}})
    runtime = dict(env)
    runtime.pop('CRATECTL_OWNER_DSN', None)
    phase('registry')
    start()
    repo('hosted');repo('fallback');repo('origin', role='origin')
    repo('proxy', mode='proxy', settings={'upstream': {'url': BASE + '/v2/' + REPOS['origin'] + '/', 'networks': ['127.0.0.1/32'], 'credential_ref': 'origin'}, 'cache': {'fresh_seconds': 300, 'negative_seconds': 2, 'stale_seconds': 0, 'allow_no_store': True}})
    for group, member in [('host-group', 'hosted'), ('proxy-group', 'proxy')]:
        repo(group, mode='group', settings={'members': [REPOS[member], REPOS['fallback']]})
    for kind in REPOS:
        if kind != 'origin':
            for role in ['reader', 'revocable']:
                grant(kind, role)
    grant('hosted', 'writer', write=True)
    phase('authentication')
    for role in auth:
        docker(role, ['login', '--username', 'token', '--password-stdin', REGISTRY], 'Docker login ' + role, stdin=(tokens[role] + '\n').encode())
        podman(role, ['login', '--tls-verify=false', '--authfile', auth[role]['podman'], '--username', 'token', '--password-stdin', REGISTRY], 'Podman login ' + role, stdin=(tokens[role] + '\n').encode())
        helm(role, ['registry', 'login', '--plain-http', '--username', 'token', '--password-stdin', REGISTRY], 'Helm login ' + role, stdin=(tokens[role] + '\n').encode())
    phase('image_publication')
    native = build_image('v1', APP1)
    build_image('v2', APP2)
    foreign = build_image('foreign', b'owned alternate platform metadata fixture\n', OTHER_ARCH)
    build_image('v1', FALLBACK, kind='fallback', role='admin')
    multi = ref('hosted', 'multi')
    docker('writer', ['manifest', 'create', '--insecure', multi, native, foreign], 'Docker creates native multi-architecture index')
    docker('writer', ['manifest', 'push', '--insecure', multi], 'Docker publishes complete multi-architecture index')
    images.add(multi)
    hosted = graph('hosted', 'multi')
    check('index contains both declared platforms', {d['platform']['architecture'] for d in hosted['index']['manifests']} == {'amd64', 'arm64'})
    for tag in ['v1', 'foreign']:
        source, target = ref('hosted', tag), ref('origin', tag)
        docker('origin', ['image', 'tag', source, target], 'tag owned origin platform fixture')
        images.add(target)
        docker('origin', ['image', 'push', '--platform', 'linux/' + (ARCH if tag == 'v1' else OTHER_ARCH), target], 'Docker publishes separate upstream tenant')
    origin_multi = ref('origin', 'multi')
    docker('origin', ['manifest', 'create', '--insecure', origin_multi, ref('origin', 'v1'), ref('origin', 'foreign')], 'Docker creates upstream multi-architecture index')
    docker('origin', ['manifest', 'push', '--insecure', origin_multi], 'Docker publishes upstream multi-architecture index')
    origin = graph('origin', 'multi', role='origin')
    phase('native_consumption')
    for kind in ['hosted', 'host-group']:
        for client in ['docker', 'podman']:
            image_bytes(client, kind, 'multi', APP1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(image_bytes, client, 'proxy-group', 'multi', APP1) for client in ['docker', 'podman']]
        for future in futures:
            future.result()
    check('proxy retains exact upstream index bytes', graph('proxy', 'multi')['digest'] == origin['digest'])
    image_bytes('podman', 'hosted', 'v2', APP2)
    podman('writer', ['tag', ref('hosted', 'v2'), ref('hosted', 'podman')], 'Podman tags its installed version2 fixture')
    podman('writer', ['push', '--tls-verify=false', '--authfile', auth['writer']['podman'], ref('hosted', 'podman')], 'Podman publishes through the native upload protocol')
    image_bytes('docker', 'host-group', 'podman', APP2)
    podman_graph = graph('hosted', 'podman')
    docker('writer', ['image', 'push', ref('hosted', 'v2')], 'Docker repeats exact native publication')
    docker('reader', ['image', 'push', ref('hosted', 'v2')], 'Docker reader cannot publish', ok=False)
    podman('reader', ['tag', ref('hosted', 'v2'), ref('hosted', 'reader-denied')], 'tag owned reader-denial fixture')
    podman('reader', ['push', '--tls-verify=false', '--authfile', auth['reader']['podman'], ref('hosted', 'reader-denied')], 'Podman reader cannot publish', ok=False)
    check('reader publication denial creates no manifest reference', http('/v2/' + REPOS['hosted'] + '/payload/manifests/reader-denied', headers={'Accept': ACCEPT})[0] == 404)
    phase('helm_dependencies')
    for version in ['1.0.0', '1.1.0']:
        package, data = chart_package('cratectl-dependency', version, 'owned dependency ' + version)
        CHARTS[version] = data
        result['fixture_sha256']['chart_dependency_' + version.replace('.', '_')] = hashlib.sha256(data).hexdigest()
        for kind, role in [('hosted', 'admin'), ('origin', 'origin')]:
            helm(role, ['push', package, 'oci://' + REGISTRY + '/' + REPOS[kind], '--plain-http'], 'Helm publishes dependency to ' + kind)
    parent, parent_bytes = chart_package('cratectl-application', '1.0.0', 'owned parent with dependency', 'host-group', '1.0.0')
    result['fixture_sha256']['chart_application_1_0_0'] = hashlib.sha256(parent_bytes).hexdigest()
    for kind, role in [('hosted', 'admin'), ('origin', 'origin')]:
        helm(role, ['push', parent, 'oci://' + REGISTRY + '/' + REPOS[kind], '--plain-http'], 'Helm publishes parent to ' + kind)
    for kind in ['hosted', 'proxy', 'host-group', 'proxy-group']:
        chart_bytes(kind, 'cratectl-application', '1.0.0', parent_bytes)
        chart_package('cratectl-consumer', '1.0.0', 'owned independent consumer', kind, '1.1.0', role='reader')
    denied_chart, _ = chart_package('cratectl-reader-denied', '1.0.0', 'owned reader publication denial')
    helm('reader', ['push', denied_chart, 'oci://' + REGISTRY + '/' + REPOS['hosted'], '--plain-http'], 'Helm reader cannot publish', ok=False)
    check('Helm reader denial creates no chart manifest', http('/v2/' + REPOS['hosted'] + '/cratectl-reader-denied/manifests/1.0.0', headers={'Accept': ACCEPT})[0] == 404)
    chart_root = graph('hosted', '1.0.0', image='cratectl-application')
    phase('tenant_collision')
    image_bytes('docker', 'hosted', 'v1', APP1, role='origin', ok=False, expected_status=404)
    repo('hosted', role='origin')
    build_image('v1', OTHER, role='origin')
    for client in ['docker', 'podman']:
        image_bytes(client, 'hosted', 'v1', OTHER, role='origin')
        image_bytes(client, 'hosted', 'v1', APP1)
    other_chart, other_chart_bytes = chart_package('cratectl-application', '1.0.0', 'owned independent tenant package')
    result['fixture_sha256']['chart_other_tenant_1_0_0'] = hashlib.sha256(other_chart_bytes).hexdigest()
    helm('origin', ['push', other_chart, 'oci://' + REGISTRY + '/' + REPOS['hosted'], '--plain-http'], 'Helm publishes same coordinate in independent tenant')
    chart_bytes('hosted', 'cratectl-application', '1.0.0', other_chart_bytes, role='origin')
    chart_bytes('hosted', 'cratectl-application', '1.0.0', parent_bytes)
    phase('policy_and_grants')
    root = graph('hosted', 'v1')
    target = {'kind': 'manifests', 'digest': root['digest']}
    decision('hosted', target, 'denied')
    for client in ['docker', 'podman']:
        image_bytes(client, 'host-group', 'v1', APP1, ok=False)
    check('valid fallback cannot replace denied first-source manifest', http('/v2/' + REPOS['host-group'] + '/payload/manifests/v1', role='reader', headers={'Accept': ACCEPT})[0] == 403)
    decision('hosted', target, 'allowed')
    selected_layer = {'kind': 'blobs', 'digest': hosted['manifest']['layers'][-1]['digest']}
    decision('hosted', selected_layer, 'denied')
    for client in ['docker', 'podman']:
        image_bytes(client, 'hosted', 'multi', APP1, ok=False)
    decision('hosted', selected_layer, 'allowed')
    chart_target = {'kind': 'manifests', 'digest': chart_root['digest']}
    decision('hosted', chart_target, 'denied', image='cratectl-application')
    chart_bytes('host-group', 'cratectl-application', '1.0.0', parent_bytes, ok=False)
    decision('hosted', chart_target, 'allowed', image='cratectl-application')
    phase('retained_lifecycle')
    lifecycle('hosted', podman_graph['digest'], 'hold')
    path = 'payload/manifests/' + podman_graph['digest']
    held = value('/api/v1/repositories/' + REPOS['hosted'] + '/artifacts/lifecycle?' + urllib.parse.urlencode({'path': path}))
    denied_delete = {'path': path, 'digest': podman_graph['digest'].removeprefix('sha256:'), 'action': 'delete', 'expected_revision': held['revision'], 'reason': 'Owned held deletion denial'}
    check('active hold rejects native fixture retirement', http('/api/v1/repositories/' + REPOS['hosted'] + '/artifacts/lifecycle', 'PUT', denied_delete)[0] == 409)
    lifecycle('hosted', podman_graph['digest'], 'release_hold')
    lifecycle('hosted', podman_graph['digest'], 'delete')
    for client in ['docker', 'podman']:
        image_bytes(client, 'hosted', podman_graph['digest'], APP2, ok=False, expected_status=404)
    lifecycle('hosted', podman_graph['digest'], 'restore')
    for client in ['docker', 'podman']:
        image_bytes(client, 'hosted', podman_graph['digest'], APP2)
    lifecycle('hosted', chart_root['digest'], 'delete', image='cratectl-application')
    chart_bytes('hosted', 'cratectl-application', '1.0.0', parent_bytes, ok=False, expected_status=404)
    lifecycle('hosted', chart_root['digest'], 'restore', image='cratectl-application')
    chart_bytes('hosted', 'cratectl-application', '1.0.0', parent_bytes)
    phase('grant_revocation')
    grant('hosted', 'reader', read=False)
    for client in ['docker', 'podman']:
        image_bytes(client, 'host-group', 'v1', APP1, ok=False)
    chart_bytes('host-group', 'cratectl-application', '1.0.0', parent_bytes, ok=False)
    grant('hosted', 'reader')
    for client in ['docker', 'podman']:
        image_bytes(client, 'host-group', 'v1', APP1, role='revocable')
    chart_bytes('host-group', 'cratectl-application', '1.0.0', parent_bytes, role='revocable')
    command([SERVER, 'revoke', '--token-file', PRIVATE / 'revocable.token'], 'revoke owned native-client credential', owner=True)
    for client in ['docker', 'podman']:
        image_bytes(client, 'host-group', 'v1', APP1, role='revocable', ok=False, expected_status=401)
    chart_bytes('host-group', 'cratectl-application', '1.0.0', parent_bytes, role='revocable', ok=False, expected_status=401)
    phase('restart')
    stop();start()
    for client in ['docker', 'podman']:
        image_bytes(client, 'proxy-group', 'multi', APP1)
        image_bytes(client, 'host-group', 'podman', APP2)
    chart_bytes('proxy-group', 'cratectl-application', '1.0.0', parent_bytes)
    result['status'] = 'passed'
    phase('complete')
except BaseException as error:
    result['status'] = 'failed'
    result['failure'] = type(error).__name__ + ': ' + str(error)
    print('FAIL: phase=' + result['phase'] + '; ' + result['failure'], flush=True)
finally:
    for client, role, name in list(created):
        try:
            (docker if client == 'docker' else podman)(role, ['rm', name], 'cleanup owned stopped container', ok=None)
        except BaseException:
            result.setdefault('cleanup_failures', []).append('owned stopped ' + client + ' container')
    for reference in sorted(images):
        try:
            docker('admin', ['image', 'rm', reference], 'cleanup owned image reference', ok=None)
        except BaseException:
            result.setdefault('cleanup_failures', []).append('owned Docker image reference')
    if PODMAN_RUNROOT is not None:
        try:
            validate_podman_runroot(*PODMAN_RUNROOT)
            command(['sudo', '-n', 'rm', '--recursive', '--force', '--', PODMAN_RUNROOT[0]], 'remove exact owned Podman runtime directory')
        except BaseException:
            result.setdefault('cleanup_failures', []).append('owned Podman runtime directory')
            result['status'] = 'failed'
            print('FAIL: exact owned Podman runtime directory cleanup', flush=True)
    stop()
    checkpoint()
    folder = ROOT / 'evidence' / datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    folder.mkdir(parents=True, exist_ok=True)
    output = folder / ('oci-clients-' + RUN + '.json')
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(result['status'].upper() + ': ' + str(len(checks)) + ' checks; native OCI clients; ' + str(output), flush=True)
if result['status'] != 'passed':
    raise SystemExit(1)
