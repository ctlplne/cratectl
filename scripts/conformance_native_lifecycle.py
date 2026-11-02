#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Native package clients exercise retained lifecycle in an isolated database.

Package caches are fresh for each observation. Only pinned Maven tool plugins
are reused; the fixture's artifact namespace is excluded from copied caches.
No package scripts, application modules or models are executed.
"""
import argparse
import base64
import csv
import datetime
import hashlib
import io
import json
import os
import platform
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

from qualification_contract import CURRENT_SCHEMA, candidate_binary_directory

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-clean-build', action='store_true')
parser.add_argument('--binary-directory', type=Path)
parser.add_argument('--formats', default='generic,npm,pypi,maven')
args = parser.parse_args()
FORMATS = args.formats.split(',')
if len(set(FORMATS)) != len(FORMATS) or not set(FORMATS) <= {'generic', 'npm', 'pypi', 'maven'}:
    parser.error('choose distinct generic,npm,pypi,maven formats')
ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
os.umask(0o077)
BIN = candidate_binary_directory(args.binary_directory)
SERVER, CLI = BIN / 'cratectld', BIN / 'cratectl'
PYTHON = ROOT / '.cache/clients/bin/python'
MAVEN = ROOT / '.cache/apache-maven-3.10.0/bin/mvn'
PSQL = ROOT / '.cache/postgresql-16.15-install/bin/psql'
RUN = uuid.uuid4().hex[:10]
PRIVATE = ROOT / '.private/native-lifecycle-conformance' / RUN
PRIVATE.mkdir(parents=True, mode=0o700)
BASE = 'http://127.0.0.1:38443'
NAME, DEP = '@owned/lifecycle-app', 'cratectl-lifecycle-dep'
PYNAME, PYDEP = 'cratectl_lifecycle_app', 'cratectl_lifecycle_dep'
GROUP = 'dev.cratectl.lifecycle.r' + RUN
GROUP_PATH = GROUP.replace('.', '/')
env = dict(os.environ)
tokens, inputs, checks, commands, cases = {}, {}, [], [], []
process, server_log = None, None
runtime = {}
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
candidate = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
scope = ['cmd', 'internal', 'scripts', 'web', 'api', 'go.mod', 'go.sum', 'Makefile']


def identity(binary):
    settings = {}
    for line in subprocess.check_output([ROOT / '.cache/go/bin/go', 'version', '-m', binary], text=True).splitlines():
        fields = line.strip().split('\t')
        if len(fields) == 2 and fields[0] == 'build' and '=' in fields[1]:
            key, value = fields[1].split('=', 1)
            settings[key] = value
    return settings


result = {
    'run': RUN, 'candidate': candidate, 'status': 'running', 'formats': FORMATS,
    'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain', '--', *scope]).strip()),
    'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'build_identity': {str(p.relative_to(ROOT)): identity(p) for p in [SERVER, CLI]},
    'artifact_digests': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [SERVER, CLI]},
    'checks': checks, 'commands': commands, 'cases': cases, 'input_digests': {},
    'private_logs': str(PRIVATE.relative_to(ROOT)),
    'topology': f'Native {platform.platform()} registry, isolated PostgreSQL on35432, filesystem objects and stock curl/npm/pip/twine/Maven on loopback38443. Runtime omits owner DSN; clients omit both DSNs.',
    'limits': [
        'Named single-reference hosted/proxy/group workflows with owned dependency fixtures; no full format/legal/retention/GC or release readiness verdict.',
        'One host and explicit loopback HTTP development profile; production TLS, independent machines, other clients/providers/platforms and scale remain required.',
        'Corruption/missing-object faults touch only this run\'s private CAS files. No lifecycle, policy, retrieval, lease or job outcome is manufactured with SQL.',
        'Maven tooling plugins use ordinary configured public Central. Fixture artifacts and dependencies use only the named cratectl repositories. No package scripts, model loading or application modules execute.',
    ],
}
result['build_source_matches_candidate'] = all(v.get('vcs.revision') == candidate and v.get('vcs.modified') == 'false' for v in result['build_identity'].values())


def private(name, value):
    path = PRIVATE / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    path.chmod(0o600)
    return path


def checkpoint():
    private('progress.json', {**result, 'registry_pid': process.pid if process is not None and process.poll() is None else None})


def check(label, condition):
    if not condition:
        raise AssertionError(label)
    checks.append(label)
    checkpoint()
    print('PASS: ' + label, flush=True)


def run(argv, label, extra=None, owner=False, ok=True, cwd=PRIVATE, timeout=180):
    command_env = dict(env)
    if not owner:
        command_env.pop('CRATECTL_OWNER_DSN', None)
        command_env.pop('CRATECTL_DSN', None)
        for key in list(command_env):
            if key.startswith(('PIP_', 'NPM_CONFIG_')) or key == 'PYTHONPATH':
                command_env.pop(key)
    command_env.update(extra or {})
    log = private('command-%04d.log' % len(commands), b'')
    entry = {'label': label, 'binary': Path(str(argv[0])).name, 'expected_success': ok, 'private_log': str(log.relative_to(ROOT))}
    commands.append(entry)
    checkpoint()
    print('RUN: ' + label, flush=True)
    started = time.monotonic()
    try:
        with log.open('ab') as output:
            p = subprocess.run([str(a) for a in argv], env=command_env, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
        entry['exit'] = p.returncode
        if (p.returncode == 0) != ok:
            raise AssertionError('native command status: ' + label + '; inspect ' + entry['private_log'])
        if log.stat().st_size > 8 << 20:
            raise AssertionError('native command output exceeded observation budget')
        return log.read_bytes()
    finally:
        entry['seconds'] = round(time.monotonic() - started, 3)
        checkpoint()


def http(path, method='GET', value=None, role='admin', key=None, headers=None):
    h = {'Authorization': 'Bearer ' + tokens[role], **(headers or {})}
    if isinstance(value, dict):
        value = json.dumps(value).encode()
        h['Content-Type'] = 'application/json'
    if method in ['PUT', 'POST']:
        h['Idempotency-Key'] = key or uuid.uuid4().hex
    request = urllib.request.Request(BASE + path, data=value, method=method, headers=h)
    try:
        response = HTTP.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read((8 << 20) + 1)
        if len(raw) > 8 << 20:
            raise AssertionError('HTTP observation exceeded byte budget')
        return response.status, raw, response.headers


def get(path):
    status, body, _ = http(path)
    if status != 200:
        raise AssertionError('management read status ' + str(status) + ': ' + path)
    return json.loads(body)


def cli(path, body, label, role='admin', key=None, ok=True):
    file = private('request-%04d.json' % len(commands), body)
    raw = run([CLI, '--url', BASE, '--token-file', PRIVATE / (role + '.token'), '--path', path,
               '--method', 'PUT', '--body-file', file, '--idempotency-key', key or uuid.uuid4().hex], label, ok=ok)
    return json.loads(raw) if ok else raw


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
    log = private('registry.log', (PRIVATE / 'registry.log').read_bytes() if (PRIVATE / 'registry.log').exists() else b'')
    server_log = log.open('ab')
    process = subprocess.Popen([str(SERVER), 'serve', '--objects', str(PRIVATE / 'objects'), '--listen', '127.0.0.1:38443',
                                '--public-url', BASE, '--dev-loopback-http', '--allow-private-upstreams', '127.0.0.1/32',
                                '--upstream-credentials', str(PRIVATE / 'upstreams.json')], env=runtime, stdout=server_log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError('owned registry exited; inspect private registry log')
        try:
            with HTTP.open(BASE + '/health/ready', timeout=1) as response:
                if response.status == 200:
                    checkpoint()
                    return
        except OSError:
            pass
        time.sleep(.05)
    raise AssertionError('owned registry readiness observation expired; process retained until cleanup')


def repository(name, fmt, **options):
    check('create ' + name, http('/api/v1/repositories', 'POST', {'name': name, 'format': fmt, **options})[0] == 201)


def inventory(repo):
    value = get('/api/v1/repositories/' + repo + '/artifacts?limit=100')
    if value.get('next'):
        raise AssertionError('fixture inventory unexpectedly exceeded one bounded page')
    return value['items']


def subject(fmt, repo):
    items = inventory(repo)
    if fmt == 'generic':
        selected = [a for a in items if a['path'] == 'app/1.0.0/app.bin']
    elif fmt == 'maven':
        selected = [a for a in items if a['path'] == GROUP_PATH + '/lifecycle-app/1.0.0/lifecycle-app-1.0.0.jar']
    else:
        name = NAME if fmt == 'npm' else PYNAME.replace('_', '-')
        selected = [a for a in items if a['metadata'].get('name') == name and a['metadata'].get('version') == '1.0.0' and 'catalog' not in a['media_type']]
    if len(selected) != 1:
        raise AssertionError('expected one materialized ' + fmt + ' subject in ' + repo)
    return {**selected[0], 'repository': repo}


def state(a):
    return get('/api/v1/repositories/' + a['repository'] + '/artifacts/lifecycle?' + urllib.parse.urlencode({'path': a['path']}))


def request_body(a, action):
    current = state(a)
    return {'path': a['path'], 'digest': a['digest'], 'action': action, 'expected_revision': current['revision'], 'reason': 'Owned exact native lifecycle proof'}


def change(a, action, role='admin', ok=True):
    return cli('/api/v1/repositories/' + a['repository'] + '/artifacts/lifecycle', request_body(a, action), a['repository'] + ' ' + action, role=role, ok=ok)


def client_env():
    out = {k: v for k, v in env.items() if not k.startswith(('PIP_', 'NPM_CONFIG_'))}
    for key in ['CRATECTL_OWNER_DSN', 'CRATECTL_DSN', 'PYTHONPATH']:
        out.pop(key, None)
    return out


def npm_env(repo, label, role='reader'):
    file = private('npmrc-' + label, ('registry=' + BASE + '/npm/' + repo + '/\n//127.0.0.1:38443/npm/' + repo + '/:_authToken=' + tokens[role] + '\n').encode())
    return {**client_env(), 'NPM_CONFIG_USERCONFIG': str(file), 'NPM_CONFIG_GLOBALCONFIG': str(ROOT / '.cache/npm-globalrc'),
            'NPM_CONFIG_CACHE': str(PRIVATE / ('npm-cache-' + label)), 'NPM_CONFIG_FETCH_RETRIES': '0'}


def python_env():
    return {**client_env(), 'NETRC': str(PRIVATE / 'netrc'), 'PIP_CONFIG_FILE': os.devnull, 'PIP_KEYRING_PROVIDER': 'disabled',
            'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_EXTRA_INDEX_URL': '', 'PIP_NO_INPUT': '1'}


def curl(path, label, output=None, upload=None, role='reader', ok=True):
    argv = ['curl', '--fail', '--silent', '--show-error', '--noproxy', '127.0.0.1', '--header', '@' + str(PRIVATE / (role + '.headers'))]
    if output is not None:
        argv += ['--output', output]
    if upload is not None:
        argv += ['--upload-file', upload]
    return run([*argv, BASE + path], label, ok=ok)


def wheel(name, version, side, dependency=None):
    directory = PRIVATE / 'inputs' / 'pypi' / side
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / (name + '-' + version + '-py3-none-any.whl')
    dist = name + '-' + version + '.dist-info'
    core = 'Metadata-Version: 2.4\nName: ' + name.replace('_', '-') + '\nVersion: ' + version + '\n'
    if dependency:
        core += 'Requires-Dist: ' + dependency.replace('_', '-') + '==1.0.0\n'
    files = {name + '/__init__.py': ('# Owned ' + side + ' fixture ' + version + '\nvalue = 42\n').encode(),
             dist + '/METADATA': (core + '\n').encode(), dist + '/WHEEL': b'Wheel-Version: 1.0\nGenerator: cratectl-lifecycle\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
    record = io.StringIO()
    writer = csv.writer(record, lineterminator='\n')
    for path, raw in files.items():
        writer.writerow([path, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('='), len(raw)])
    writer.writerow([dist + '/RECORD', '', ''])
    files[dist + '/RECORD'] = record.getvalue().encode()
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path, raw in files.items():
            archive.writestr(path, raw)
    return destination


def prepare_inputs(fmt):
    for side in ['origin', 'fallback']:
        for name, version in [('dep', '1.0.0'), ('app', '1.0.0'), ('app', '2.0.0')]:
            directory = PRIVATE / 'inputs' / fmt / side / (name + '-' + version)
            directory.mkdir(parents=True, exist_ok=True)
            if fmt == 'generic':
                path = directory / (name + '.bin')
                path.write_bytes(('Owned ' + side + ' ' + name + ' ' + version + '\n').encode() * 1024)
            elif fmt == 'npm':
                package_name = DEP if name == 'dep' else NAME
                doc = {'name': package_name, 'version': version, 'main': 'index.js', 'license': 'MIT'}
                if name == 'app':
                    doc['dependencies'] = {DEP: '1.0.0'}
                (directory / 'package.json').write_text(json.dumps(doc))
                (directory / 'index.js').write_text('// Owned ' + side + ' ' + name + ' ' + version + '\nmodule.exports = 42;\n')
                packed = json.loads(run(['npm', 'pack', '--ignore-scripts', '--json'], 'pack ' + fmt + ' ' + side + ' ' + name + version,
                                        extra=npm_env('native-npm', 'pack-' + side + name + version, 'admin'), cwd=directory))
                path = directory / packed[0]['filename']
            elif fmt == 'pypi':
                path = wheel(PYDEP if name == 'dep' else PYNAME, version, side, PYDEP if name == 'app' else None)
            else:
                artifact = 'lifecycle-' + name
                path = directory / (artifact + '-' + version + '.jar')
                with zipfile.ZipFile(path, 'w') as archive:
                    archive.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')
                    archive.writestr('fixture.txt', 'Owned ' + side + ' ' + name + ' ' + version)
                dependency = '<dependencies><dependency><groupId>' + GROUP + '</groupId><artifactId>lifecycle-dep</artifactId><version>1.0.0</version></dependency></dependencies>' if name == 'app' else ''
                path.with_suffix('.pom').write_text('<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>' + GROUP + '</groupId><artifactId>' + artifact + '</artifactId><version>' + version + '</version>' + dependency + '</project>')
            inputs[(fmt, side, name, version)] = path


def maven(argv, label, cache, ok=True, settings=None):
    return run([MAVEN, '-B', '-s', settings or PRIVATE / 'maven-settings.xml', '-Dmaven.repo.local=' + str(cache), *argv], label,
               extra={'JAVA_HOME': str(ROOT / '.cache/jdk-21.0.13+9/Contents/Home'), 'MAVEN_OPTS': '-Xmx256m'}, ok=ok)


def publish(fmt, repo, side='origin', only_app=False, ok=True):
    for name, version in ([('app', '1.0.0')] if only_app else [('dep', '1.0.0'), ('app', '1.0.0'), ('app', '2.0.0')]):
        path = inputs[(fmt, side, name, version)]
        label = 'publish ' + repo + ' ' + name + version
        if fmt == 'generic':
            curl('/r/' + repo + '/' + name + '/' + version + '/' + name + '.bin', label, upload=path, role='admin', ok=ok)
        elif fmt == 'npm':
            run(['npm', 'publish', path, '--ignore-scripts', '--access', 'public', '--tag', 'latest'], label, extra=npm_env(repo, 'publish-' + repo + name + version, 'admin'), ok=ok)
        elif fmt == 'pypi':
            run([PYTHON, '-m', 'twine', 'upload', '--non-interactive', '--repository-url', BASE + '/pypi/' + repo + '/', path], label,
                extra={**client_env(), 'TWINE_USERNAME': 'token', 'TWINE_PASSWORD': tokens['admin'], 'TWINE_DISABLE_PROGRESS_BAR': '1'}, ok=ok)
        else:
            maven(['org.apache.maven.plugins:maven-deploy-plugin:3.1.4:deploy-file', '-Dfile=' + str(path), '-DpomFile=' + str(path.with_suffix('.pom')),
                   '-DrepositoryId=cratectl', '-Durl=' + BASE + '/r/' + repo + '/'], label, PRIVATE / 'maven-tool-cache', ok=ok)


def consume(fmt, repo, label, side='origin', ok=True, version='1.0.0', dependency_side=None):
    target = PRIVATE / ('consume-' + label)
    target.mkdir()
    dependency_side = dependency_side or side
    if fmt == 'generic':
        for name in ['app', 'dep']:
            selected_version = version if name == 'app' else '1.0.0'
            output = target / (name + '.bin')
            curl('/r/' + repo + '/' + name + '/' + selected_version + '/' + name + '.bin', label + ' ' + name, output=output, ok=ok if name == 'app' else True)
            if ok or name == 'dep':
                check(label + ' exact generic ' + name, output.read_bytes() == inputs[(fmt, side, name, selected_version)].read_bytes())
    elif fmt == 'npm':
        (target / 'package.json').write_text('{"name":"owned-lifecycle-consumer","version":"1.0.0"}')
        run(['npm', 'install', '--ignore-scripts', '--no-audit', '--no-fund', '--save-exact', NAME + '@' + version], label, extra=npm_env(repo, label), cwd=target, ok=ok)
        if ok:
            for name, coordinate in [('app', NAME), ('dep', DEP)]:
                installed = target / 'node_modules' / coordinate / 'index.js'
                with tarfile.open(inputs[(fmt, side if name == 'app' else dependency_side, name, version if name == 'app' else '1.0.0')], 'r:gz') as archive:
                    expected = archive.extractfile('package/index.js').read()
                check(label + ' exact npm ' + name, installed.read_bytes() == expected)
    elif fmt == 'pypi':
        run([PYTHON, '-m', 'pip', 'install', '--no-cache-dir', '--only-binary=:all:', '--no-compile', '--index-url', BASE + '/pypi/' + repo + '/simple/',
             '--target', target, PYNAME.replace('_', '-') + '==' + version], label, extra=python_env(), ok=ok)
        if ok:
            for name, coordinate in [('app', PYNAME), ('dep', PYDEP)]:
                with zipfile.ZipFile(inputs[(fmt, side if name == 'app' else dependency_side, name, version if name == 'app' else '1.0.0')]) as archive:
                    expected = archive.read(coordinate + '/__init__.py')
                check(label + ' exact Python ' + name, (target / coordinate / '__init__.py').read_bytes() == expected)
    else:
        cache = target / 'cache'
        def exclude(directory, names):
            return ['lifecycle'] if Path(directory).as_posix().endswith('/dev/cratectl') and 'lifecycle' in names else []
        shutil.copytree(PRIVATE / 'maven-tool-cache', cache, ignore=exclude)
        check(label + ' Maven cache starts without fixture artifacts', not (cache / GROUP_PATH).exists())
        settings = private('maven-consume-' + label + '.xml', ('<settings><mirrors><mirror><id>central</id><mirrorOf>*</mirrorOf><url>' + BASE + '/r/' + repo + '/</url></mirror></mirrors><servers><server><id>central</id><username>token</username><password>' + tokens['reader'] + '</password></server></servers></settings>').encode())
        maven(['org.apache.maven.plugins:maven-dependency-plugin:3.8.1:get', '-Dartifact=' + GROUP + ':lifecycle-app:' + version,
               '-DremoteRepositories=cratectl::default::' + BASE + '/r/' + repo + '/', '-Dtransitive=true'], label, cache, ok=ok, settings=settings)
        if ok:
            for name in ['app', 'dep']:
                selected_version = version if name == 'app' else '1.0.0'
                installed = cache / GROUP_PATH / ('lifecycle-' + name) / selected_version / ('lifecycle-' + name + '-' + selected_version + '.jar')
                check(label + ' exact Maven ' + name, installed.read_bytes() == inputs[(fmt, side, name, selected_version)].read_bytes())
    if not ok:
        check(label + ' fresh native install fails', True)


def native_metadata(fmt, group):
    if fmt == 'npm':
        status, raw, _ = http('/npm/' + group + '/' + urllib.parse.quote(NAME, safe='@'))
        return status == 200 and '1.0.0' in json.loads(raw).get('versions', {})
    if fmt == 'pypi':
        status, raw, _ = http('/pypi/' + group + '/simple/' + PYNAME.replace('_', '-') + '/', headers={'Accept': 'application/vnd.pypi.simple.v1+json'})
        return status == 200 and any(v['filename'].startswith(PYNAME + '-1.0.0-') for v in json.loads(raw)['files'])
    if fmt == 'maven':
        status, raw, _ = http('/r/' + group + '/' + GROUP_PATH + '/lifecycle-app/maven-metadata.xml')
        return status == 200 and b'<version>1.0.0</version>' in raw
    raise AssertionError('generic files have no native version index')


def lifecycle_case(fmt, mode):
    repo = ('native-' if mode == 'hosted' else 'proxy-') + fmt
    group = ('host-group-' if mode == 'hosted' else 'proxy-group-') + fmt
    label = fmt + '-' + mode
    consume(fmt, group, label + '-initial')
    a = subject(fmt, repo)
    endpoint = '/api/v1/repositories/' + repo + '/artifacts/lifecycle'
    body = request_body(a, 'hold')
    check(label + ' reader and foreign tenant lifecycle denied', http(endpoint, 'PUT', body, role='reader')[0] == 403 and http(endpoint, 'PUT', body, role='other')[0] == 404)
    check(label + ' writer cannot place hold', http(endpoint, 'PUT', body, role='writer')[0] == 403)
    held = change(a, 'hold')['current']
    consume(fmt, group, label + '-held')
    check(label + ' hold blocks deletion', http(endpoint, 'PUT', request_body(a, 'delete'))[0] == 409)
    change(a, 'release_hold')
    check(label + ' stale lifecycle revision rejected', http(endpoint, 'PUT', {**request_body(a, 'delete'), 'expected_revision': held['revision']})[0] == 409)
    if fmt != 'generic':
        check(label + ' native metadata initially selects target', native_metadata(fmt, group))
    change(a, 'delete')
    check(label + ' tombstone retained', state(a)['deleted'])
    consume(fmt, group, label + '-deleted', ok=False)
    consume(fmt, group, label + '-other-version', version='2.0.0')
    if fmt != 'generic':
        check(label + ' native metadata does not substitute fallback', not native_metadata(fmt, group))
    if fmt in ['generic', 'maven']:
        status, raw, _ = http('/r/' + group + '/' + a['path'], role='reader')
        check(label + ' group keeps explicit native tombstone', status == 404 and json.loads(raw)['error']['code'] == 'artifact_deleted')
    elif fmt == 'npm':
        pin = '/npm/' + group + '/' + NAME + '/-/cratectl/fallback-npm/hosted/1.0.0.tgz'
        status, raw, _ = http(pin, role='reader')
        check(label + ' pinned lower-source npm URL cannot bypass tombstone', status == 404 and json.loads(raw)['error']['code'] == 'artifact_deleted')
    else:
        lower = subject(fmt, 'fallback-pypi')
        filename = inputs[(fmt, 'origin', 'app', '1.0.0')].name
        pin = '/pypi/' + group + '/files/fallback-pypi/hosted/' + lower['digest'] + '/' + filename
        status, raw, _ = http(pin, role='reader')
        check(label + ' pinned lower-source Python URL cannot bypass tombstone', status == 404 and json.loads(raw)['error']['code'] == 'artifact_deleted')
    consume(fmt, 'fallback-' + fmt, label + '-direct-fallback', side='fallback')
    if mode == 'hosted':
        publish(fmt, repo, only_app=True, ok=False)
        check(label + ' native republish leaves tombstone', state(a)['deleted'])
    if fmt == 'npm' and mode == 'hosted':
        check(label + ' explicit native tag removal', http('/npm/native-npm/-/package/' + urllib.parse.quote(NAME, safe='@') + '/dist-tags/latest', 'DELETE')[0] == 200)
    if fmt == 'pypi':
        filename = inputs[(fmt, 'origin', 'app', '1.0.0')].name
        check(label + ' preserve native yank', http('/api/v1/repositories/native-pypi/yanks', 'PUT', {'filename': filename, 'yanked': True, 'reason': 'Owned retained yank'})[0] == 200)
    object_path = PRIVATE / 'objects' / tenant / 'sha256' / a['digest'][:2] / a['digest']
    saved = object_path.read_bytes()
    check(label + ' actual CAS identity matches reference', len(saved) == a['size'] and hashlib.sha256(saved).hexdigest() == a['digest'])
    restore = request_body(a, 'restore')
    restore_key = uuid.uuid4().hex
    try:
        object_path.write_bytes(b'X' * len(saved))
        cli(endpoint, restore, label + '-corrupt-restore', key=restore_key, ok=False)
        check(label + ' corrupt restore has no lifecycle effect', state(a)['deleted'] and state(a)['revision'] == restore['expected_revision'])
    finally:
        object_path.write_bytes(saved)
    missing = object_path.with_name(object_path.name + '.owned-missing')
    object_path.rename(missing)
    try:
        cli(endpoint, restore, label + '-missing-restore', key=restore_key, ok=False)
        check(label + ' missing restore has no lifecycle effect', state(a)['deleted'] and state(a)['revision'] == restore['expected_revision'])
    finally:
        missing.rename(object_path)
    check(label + ' current exact digest denial', http('/api/v1/repositories/' + repo + '/decisions', 'PUT', {'path': a['path'], 'digest': a['digest'], 'decision': 'denied'})[0] == 200)
    restored = cli(endpoint, restore, label + '-verified-restore', key=restore_key)
    replay = cli(endpoint, restore, label + '-restore-replay', key=restore_key)
    check(label + ' verified restore and original replay', restored == replay and not state(a)['deleted'])
    consume(fmt, group, label + '-denied-after-restore', ok=False)
    check(label + ' allow exact restored bytes', http('/api/v1/repositories/' + repo + '/decisions', 'PUT', {'path': a['path'], 'digest': a['digest'], 'decision': 'allowed'})[0] == 200)
    consume(fmt, group, label + '-restored')
    stop()
    start()
    consume(fmt, group, label + '-restart')
    if fmt != 'generic':
        check(label + ' restored metadata survives restart', native_metadata(fmt, group))
    if fmt == 'npm':
        doc = json.loads(http('/npm/' + group + '/' + urllib.parse.quote(NAME, safe='@'))[1])
        check(label + ' restore does not resurrect removed npm tag', 'latest' not in doc['dist-tags'])
    if fmt == 'pypi':
        doc = json.loads(http('/pypi/' + group + '/simple/' + PYNAME.replace('_', '-') + '/', headers={'Accept': 'application/vnd.pypi.simple.v1+json'})[1])
        selected = [f for f in doc['files'] if f['filename'] == inputs[(fmt, 'origin', 'app', '1.0.0')].name]
        check(label + ' native yank remains after verified restoration', len(selected) == 1 and selected[0]['yanked'] == 'Owned retained yank')
    revoked = 'revoked-' + label
    file = PRIVATE / (revoked + '.token')
    run([SERVER, 'provision', '--tenant', tenant, '--actor', revoked, '--role', 'admin', '--token-file', file], 'provision ' + revoked, owner=True)
    tokens[revoked] = file.read_text().strip()
    hold_body, hold_key = request_body(a, 'hold'), uuid.uuid4().hex
    cli(endpoint, hold_body, label + '-revocable-hold', role=revoked, key=hold_key)
    run([SERVER, 'revoke', '--token-file', file], 'revoke ' + revoked, owner=True)
    check(label + ' revoked hold replay denied', http(endpoint, 'PUT', hold_body, role=revoked, key=hold_key)[0] == 401)
    check(label + ' hold outlives placing credential', http(endpoint, 'PUT', request_body(a, 'delete'))[0] == 409)
    change(a, 'release_hold', role='recovery')
    check(label + ' current independent administrator releases hold', not state(a)['held'])
    cases.append({'format': fmt, 'mode': mode, 'repository': repo, 'group': group, 'path': a['path'], 'digest': a['digest'], 'size': a['size'], 'final_revision': state(a)['revision']})
    checkpoint()


def catalog_removal(fmt):
    proxy, origin, group = 'proxy-' + fmt, 'native-' + fmt, 'proxy-group-' + fmt
    cached, hosted = subject(fmt, proxy), subject(fmt, origin)
    change(cached, 'delete')
    change(hosted, 'delete')
    catalog = ('npm-catalog/' + NAME) if fmt == 'npm' else ('pypi-catalog/' + PYNAME.replace('_', '-'))
    def invalidate():
        check(fmt + ' catalog invalidation admitted', http('/api/v1/repositories/' + proxy + '/cache', 'PUT', {'path': catalog})[0] == 200)
    invalidate()
    consume(fmt, group, fmt + '-removed-descriptor-fallback', side='fallback', dependency_side='origin')
    check(fmt + ' catalog removal leaves old proxy path deleted', state(cached)['deleted'])
    change(hosted, 'restore')
    invalidate()
    consume(fmt, group, fmt + '-returned-descriptor-still-deleted', ok=False)
    check(fmt + ' returned upstream descriptor does not resurrect local tombstone', state(cached)['deleted'])
    change(cached, 'restore')
    consume(fmt, group, fmt + '-descriptor-explicitly-restored')


def source_replacement(fmt):
    repo = 'proxy-' + fmt
    a = subject(fmt, repo)
    change(a, 'hold')
    config = get('/api/v1/repositories/' + repo + '/configuration')
    settings = json.loads(json.dumps(config['settings']))
    settings['upstream']['url'] = BASE + '/r/fallback-' + fmt + '/'
    settings['upstream']['credential_ref'] = 'fallback-' + fmt
    check(fmt + ' governed source replacement admitted', http('/api/v1/repositories/' + repo + '/configuration', 'PUT', {'expected_revision': config['source_revision'], 'settings': settings, 'reason': 'Owned held reference source replacement'})[0] == 200)
    native = '/r/' + repo + '/' + a['path']
    status, _, _ = http(native, role='reader', headers={'Cache-Control': 'no-cache'})
    check(fmt + ' real changed-byte refresh cannot cross hold', status == 409 and state(a)['digest'] == a['digest'] and state(a)['held'])
    change(a, 'release_hold')
    history_path = '/api/v1/repositories/' + repo + '/artifacts/lifecycle/history?' + urllib.parse.urlencode({'path': a['path']})
    previous_history = get(history_path)
    old_preview = request_body(a, 'delete')
    old_state = state(a)
    output = PRIVATE / ('source-replacement-' + fmt + '.bin')
    curl(native, fmt + ' permitted replacement after release', output=output)
    expected = inputs[(fmt, 'fallback', 'app', '1.0.0')].read_bytes()
    current = state(a)
    check(fmt + ' permitted replacement advances exact lifecycle identity', output.read_bytes() == expected and current['digest'] == hashlib.sha256(expected).hexdigest() and current['revision'] == old_state['revision'] + 1)
    check(fmt + ' old hold snapshots stay immutable after byte replacement', get(history_path) == previous_history)
    check(fmt + ' old preview cannot act on replacement bytes', http('/api/v1/repositories/' + repo + '/artifacts/lifecycle', 'PUT', old_preview)[0] == 409)
    observations = get('/api/v1/holds?' + urllib.parse.urlencode({'repository': repo, 'state': 'all'}))
    check(fmt + ' original receipts do not invent a hold for replacement digest', not observations['items'])


try:
    checkpoint()
    with socket.socket() as probe:
        check('owned registry port38443 is free', probe.connect_ex(('127.0.0.1', 38443)) != 0)
    if args.require_clean_build:
        check('source and selected binaries identify a clean candidate', not result['source_dirty'] and result['build_source_matches_candidate'])
    owner = urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN'])
    check('owned PostgreSQL uses loopback35432', owner.hostname == '127.0.0.1' and owner.port == 35432)
    database = 'cratectl_native_lifecycle_' + RUN
    pgenv = dict(env, PGHOST=owner.hostname, PGPORT=str(owner.port), PGUSER=urllib.parse.unquote(owner.username), PGPASSWORD=urllib.parse.unquote(owner.password), PGDATABASE=owner.path[1:])
    run([PSQL, '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', 'CREATE DATABASE ' + database], 'create isolated database', extra=pgenv, owner=True)
    for key in ['CRATECTL_OWNER_DSN', 'CRATECTL_DSN']:
        u = urllib.parse.urlsplit(env[key])
        env[key] = urllib.parse.urlunsplit((u.scheme, u.netloc, '/' + database, u.query, u.fragment))
    private('database.json', {'owner': env['CRATECTL_OWNER_DSN'], 'runtime': env['CRATECTL_DSN']})
    run([SERVER, 'migrate'], 'migrate isolated fixture', owner=True)
    plan = json.loads(run([SERVER, 'migrate', '--plan'], 'read isolated schema plan', owner=True))
    check('isolated schema receipts are complete and safe', plan['binary_version'] == CURRENT_SCHEMA and len(plan['applied']) == CURRENT_SCHEMA and plan['safety_valid'] and not plan['pending'])
    tenant = 'native-life-' + RUN
    for label, role, target in [('admin', 'admin', tenant), ('recovery', 'admin', tenant), ('reader', 'reader', tenant), ('writer', 'writer', tenant), ('other', 'admin', tenant + '-other')]:
        file = PRIVATE / (label + '.token')
        run([SERVER, 'provision', '--tenant', target, '--actor', label, '--role', role, '--token-file', file], 'provision ' + label, owner=True)
        tokens[label] = file.read_text().strip()
        private(label + '.headers', ('Authorization: Bearer ' + tokens[label] + '\n').encode())
    private('netrc', ('machine 127.0.0.1 login token password ' + tokens['reader'] + '\n').encode())
    private('maven-settings.xml', ('<settings><servers><server><id>cratectl</id><username>token</username><password>' + tokens['admin'] + '</password></server></servers></settings>').encode())
    upstreams = {}
    for fmt in FORMATS:
        prefix = {'generic': 'r', 'maven': 'r', 'npm': 'npm', 'pypi': 'pypi'}[fmt]
        for kind in ['native', 'fallback']:
            upstreams[tenant + '/' + kind + '-' + fmt] = {'value': tokens['reader'], 'allowed_url': BASE + '/' + prefix + '/' + kind + '-' + fmt + '/'}
    private('upstreams.json', upstreams)
    runtime = dict(env)
    runtime.pop('CRATECTL_OWNER_DSN', None)
    start()
    for fmt in FORMATS:
        repository('native-' + fmt, fmt)
        repository('fallback-' + fmt, fmt)
        prefix = {'generic': 'r', 'maven': 'r', 'npm': 'npm', 'pypi': 'pypi'}[fmt]
        source_url = BASE + '/' + prefix + '/native-' + fmt + '/'
        settings = {'upstream': {'url': source_url + ('simple/' if fmt == 'pypi' else ''), 'networks': ['127.0.0.1/32'], 'credential_ref': 'native-' + fmt}, 'cache': {'fresh_seconds': 300, 'negative_seconds': 2, 'stale_seconds': 0, 'require_checksum': True, 'allow_no_store': True}}
        if fmt == 'pypi':
            settings['download_sources'] = [{'url': source_url + 'files/', 'networks': ['127.0.0.1/32'], 'credential_ref': 'native-pypi'}]
        repository('proxy-' + fmt, fmt, mode='proxy', settings=settings)
        for mode, source in [('host', 'native-'), ('proxy', 'proxy-')]:
            repository(mode + '-group-' + fmt, fmt, mode='group', settings={'members': [source + fmt, 'fallback-' + fmt]})
        prepare_inputs(fmt)
        publish(fmt, 'native-' + fmt)
        publish(fmt, 'fallback-' + fmt, 'fallback')
        if fmt == 'maven':
            maven(['org.apache.maven.plugins:maven-dependency-plugin:3.8.1:help', '-Ddetail=false'],
                  'warm pinned Maven tooling before fresh mirrored consumers', PRIVATE / 'maven-tool-cache')
        lifecycle_case(fmt, 'hosted')
        lifecycle_case(fmt, 'proxy')
        if fmt in ['npm', 'pypi']:
            catalog_removal(fmt)
        else:
            source_replacement(fmt)
    result['status'] = 'passed'
except BaseException as error:
    result['status'] = 'failed'
    result['failure'] = type(error).__name__ + ': ' + str(error)
    print('FAIL: ' + result['failure'], flush=True)
finally:
    stop()
    result['input_digests'] = {str(p.relative_to(PRIVATE)): {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'size': p.stat().st_size} for p in inputs.values()}
    checkpoint()
    target = ROOT / 'evidence' / datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    target.mkdir(parents=True, exist_ok=True)
    output = target / ('native-lifecycle-' + RUN + '.json')
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(result['status'].upper() + ': ' + str(len(checks)) + ' checks; ' + str(output), flush=True)
if result['status'] != 'passed':
    raise SystemExit(1)
