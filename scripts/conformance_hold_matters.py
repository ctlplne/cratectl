#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned native matter recovery with real worker death, leases and revocation.

The ordinal-two SQL trigger is a declared timing fault in an isolated database.
It pauses an unfinished transaction; it does not manufacture an outcome or edit
the lease clock. All raw command output and credentials remain private.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
from qualification_contract import candidate_binary_directory, candidate_artifact_names
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from qualification_contract import CURRENT_SCHEMA

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-clean-build', action='store_true')
parser.add_argument('--binary-directory', type=Path)
args = parser.parse_args()
ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
os.umask(0o077)
BIN = candidate_binary_directory(args.binary_directory)
NEW, CLI, ORAS = BIN / 'cratectld', BIN / 'cratectl', ROOT / '.cache/bin/oras'
PSQL = ROOT / '.cache/postgresql-16.15-install/bin/psql'
RUN = uuid.uuid4().hex[:10]
PRIVATE = ROOT / '.private/hold-matters-conformance' / RUN
PRIVATE.mkdir(parents=True, mode=0o700)
PRIVATE.chmod(0o700)
BASE = 'http://127.0.0.1:38443'
env = dict(os.environ)
tokens, processes, logs = {}, {}, {}
checks, commands, process_events = [], [], []
barrier_state = None
barrier_installed = False
barrier_number = 0


def identity(binary):
    settings = {}
    for line in subprocess.check_output([ROOT / '.cache/go/bin/go', 'version', '-m', binary], text=True).splitlines():
        fields = line.strip().split('\t')
        if len(fields) == 2 and fields[0] == 'build' and '=' in fields[1]:
            key, value = fields[1].split('=', 1)
            settings[key] = value
    return settings


candidate = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
scope = ['cmd', 'internal', 'scripts', 'web', 'api', 'go.mod', 'go.sum', 'Makefile']
result = {
    'run': RUN, 'candidate': candidate, 'status': 'running', 'expected_schema': CURRENT_SCHEMA,
    'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain', '--', *scope]).strip()),
    'build_identity': {str(p.relative_to(ROOT)): identity(p) for p in [NEW, CLI]},
    'artifact_digests': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [NEW, CLI, ORAS]},
    'checks': checks, 'commands': commands, 'process_events': process_events, 'timing_helpers': [],
    'private_logs': str(PRIVATE.relative_to(ROOT)),
    'topology': 'Native registry and maintenance workers, isolated forced-RLS PostgreSQL on 35432, stock ORAS and cratectl CLI on loopback HTTP38443. Runtime processes omit the owner DSN; clients omit both DSNs.',
    'limits': [
        'Canonical OCI references across two repositories on one native host; broader formats, legal policy, providers/platforms, HA and scale remain required.',
        'An ordinal-two outcome trigger is an explicit SQL timing fault. Worker death, lease expiry, transaction rollback, revocation and API recovery use actual processes and clocks.',
        'No lease/outcome/membership values are manufactured through SQL. Immutable snapshots, committed progress and API observations determine assertions.',
        'Private raw logs, timing ownership records, credentials, objects and the isolated database are retained; no physical deletion, production maintenance or release readiness is established.',
    ],
}
result['build_source_matches_candidate'] = all(v.get('vcs.revision') == candidate and v.get('vcs.modified') == 'false' for v in result['build_identity'].values())


def private(name, value):
    path = PRIVATE / name
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    path.chmod(0o600)
    return path


def checkpoint():
    private('progress.json', {**result, 'live_processes': {k: p.pid for k, p in processes.items() if p.poll() is None}})


def check(label, condition):
    if not condition:
        raise AssertionError(label)
    checks.append(label)
    checkpoint()
    print('PASS: ' + label, flush=True)


def run(argv, extra=None, input_bytes=None, ok=True, cwd=PRIVATE):
    command_env = dict(env)
    command_env.update(extra or {})
    if Path(str(argv[0])).name in ['oras', 'cratectl']:
        for key in ['CRATECTL_OWNER_DSN', 'CRATECTL_DSN']:
            command_env.pop(key, None)
    log = private('command-%04d.log' % len(commands), b'')
    entry = {'argv': [str(a).replace(str(PRIVATE), 'PRIVATE') for a in argv], 'private_log': str(log.relative_to(ROOT)), 'expected_success': ok}
    started = time.monotonic()
    try:
        with log.open('ab') as output:
            p = subprocess.run([str(a) for a in argv], env=command_env, input=input_bytes, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, timeout=30)
        entry['exit'] = p.returncode
    except subprocess.TimeoutExpired:
        entry['timeout'] = True
        raise AssertionError('native command timed out; inspect ' + entry['private_log'])
    finally:
        entry['seconds'] = round(time.monotonic() - started, 3)
        commands.append(entry)
        checkpoint()
    if (p.returncode == 0) != ok:
        raise AssertionError('native command status; inspect ' + entry['private_log'])
    if log.stat().st_size > 4 << 20:
        raise AssertionError('native output exceeded observation budget; raw log retained')
    return log.read_bytes()


def stop(name, kill=False):
    p = processes.pop(name, None)
    if p is not None:
        if p.poll() is None:
            p.kill() if kill else p.terminate()
        try:
            code = p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
            code = p.wait(timeout=5)
        process_events.append({'process': name, 'pid': p.pid, 'exit': code, 'kill_requested': kill})
    if name in logs:
        logs.pop(name).close()
    checkpoint()


def spawn(name, argv, process_env=None):
    if name in processes:
        raise AssertionError('owned process identity already active')
    path = PRIVATE / (name + '.log')
    if not path.exists():
        private(name + '.log', b'')
    logs[name] = path.open('ab')
    processes[name] = subprocess.Popen([str(a) for a in argv], env=process_env or runtime, stdout=logs[name], stderr=subprocess.STDOUT)
    checkpoint()
    return processes[name]


def wait(label, predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        for name, p in processes.items():
            if p.poll() is not None:
                raise AssertionError('owned process exited unexpectedly: ' + name)
        time.sleep(.05)
    raise AssertionError('bounded observation expired: ' + label)


def api(path, method='GET', body=None, role='admin', key=None):
    headers = {'Authorization': 'Bearer ' + tokens[role], 'Content-Type': 'application/json'}
    if method in ['POST', 'PUT']:
        headers['Idempotency-Key'] = key or uuid.uuid4().hex
    request = urllib.request.Request(BASE + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=headers)
    try:
        response = urllib.request.urlopen(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read((4 << 20) + 1)
        if len(raw) > 4 << 20:
            raise AssertionError('management observation exceeded byte budget')
        return response.status, json.loads(raw) if raw else None


def get(path, role='admin'):
    status, body = api(path, role=role)
    if status != 200:
        raise AssertionError('management observation status ' + str(status))
    return body


def cli(path, body=None, method='POST', role='admin', key=None, ok=True):
    argv = [CLI, '--url', BASE, '--token-file', PRIVATE / (role + '.token'), '--path', path]
    if body is not None:
        argv += ['--method', method, '--body-file', private('request-%04d.json' % len(commands), body), '--idempotency-key', key or uuid.uuid4().hex]
    output = run(argv, ok=ok)
    return json.loads(output) if ok else output


def oras(*argv, cwd=PRIVATE, ok=True):
    return run([ORAS, *argv, '--plain-http', '--registry-config', PRIVATE / 'oras-auth.json'], cwd=cwd, ok=ok)


def start_registry():
    spawn('registry', [NEW, 'serve', '--objects', PRIVATE / 'objects', '--listen', '127.0.0.1:38443', '--public-url', BASE, '--dev-loopback-http'])
    def ready():
        try:
            with urllib.request.urlopen(BASE + '/health/ready', timeout=1) as response:
                return response.status == 200
        except OSError:
            return False
    wait('owned registry readiness', ready)


def start_worker():
    spawn('worker', [NEW, 'worker', '--objects', PRIVATE / 'objects', '--identities', PRIVATE / 'workers.json', '--name', 'cratectl-matter-' + RUN, '--lease', '2s', '--job-timeout', '2s', '--poll', '20ms'])


def create(name):
    return cli('/api/v1/hold-matters/' + name, {'expected_revision': 0, 'state': 'open', 'title': 'Owned native investigation ' + name, 'reason': 'Preserve exact native references across repositories'}, method='PUT')


def preview(action, targets, role='admin'):
    return cli(base + '/operations/preview', {'action': action, 'reason': 'Reviewed exact native matter targets', 'targets': targets}, role=role)


def admit(plan, role='admin', key=None):
    return cli(base + '/operations', plan, role=role, key=key)['operation']


def approve(operation, role='reviewer'):
    return cli(base + '/operations/' + str(operation['sequence']) + '/approve', {'expected_revision': operation['revision'], 'preview_digest': operation['plan']['preview_digest'], 'reason': 'Distinct current administrator reviewed every native target'}, role=role)['operation']


def detail(operation):
    return get(base + '/operations/' + str(operation['sequence']))


def items(operation):
    return get(base + '/operations/' + str(operation['sequence']) + '/items?limit=100')['items']


def finished(operation, state='succeeded'):
    def outcome():
        value = detail(operation)
        if value['job']['state'] == state:
            return value
        if value['job']['state'] in ['failed', 'cancelled'] and state == 'succeeded':
            raise AssertionError('matter worker failed: ' + value['job']['last_error'])
        return None
    return wait('durable matter ' + state, outcome)


def lifecycle(target):
    return get('/api/v1/repositories/' + target['repository'] + '/artifacts/lifecycle?' + urllib.parse.urlencode({'path': target['path']}))


def sql(statement):
    return run([PSQL, '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', statement], pgenv).decode().strip()


def install_barrier(operation):
    global barrier_number, barrier_state, barrier_installed
    if barrier_state is not None:
        raise AssertionError('previous timing barrier is not closed')
    barrier_number += 1
    lock = 1000000 + int(RUN[:6], 16)
    barrier_state = PRIVATE / ('timing-helper-%d.json' % barrier_number)
    child = spawn('timing', [sys.executable, ROOT / 'scripts/sql_timing.py', 'hold', '--state', barrier_state, '--label', 'cratectl-barrier-matter-' + RUN + '-' + str(barrier_number), '--lock', lock], pgenv)
    wait('exact timing helper ready', lambda: child.poll() is None and barrier_state.exists() and json.loads(barrier_state.read_bytes())['status'] == 'ready')
    sql("CREATE FUNCTION cratectl.matter_native_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant='" + tenant + "' AND NEW.operation=" + str(operation['sequence']) + " AND NEW.ordinal=2 THEN PERFORM pg_advisory_xact_lock(" + str(lock) + "); END IF; RETURN NEW; END $$; CREATE TRIGGER cratectl_matter_native_barrier BEFORE INSERT ON cratectl.hold_matter_outcomes FOR EACH ROW EXECUTE FUNCTION cratectl.matter_native_barrier()")
    barrier_installed = True


def clear_barrier():
    global barrier_state, barrier_installed
    # Release the declared lock before DDL so the paused transaction can finish
    # its real lease/authority check. Dropping its trigger first would wait on it.
    child = processes.get('timing')
    stop('timing')
    if barrier_state is not None:
        run([sys.executable, ROOT / 'scripts/sql_timing.py', 'close', '--state', barrier_state], pgenv)
        state = json.loads(barrier_state.read_bytes())
        check('exact owned timing backend is absent after cleanup', state['status'] == 'closed' and state['cleanup']['backend_absent'] and (child is None or child.returncode == 0))
        result['timing_helpers'].append(state)
        barrier_state = None
    if barrier_installed:
        sql('DROP TRIGGER cratectl_matter_native_barrier ON cratectl.hold_matter_outcomes; DROP FUNCTION cratectl.matter_native_barrier()')
        barrier_installed = False


def partial(operation):
    def observed():
        value = detail(operation)
        if value['processed'] != 1 or value['job']['state'] != 'running':
            return None
        rows = json.loads(sql("SELECT COALESCE(json_agg(json_build_object('pid',pid,'backend_start',backend_start)), '[]') FROM pg_stat_activity WHERE datname=current_database() AND usename='" + runtime_user + "' AND state='active' AND wait_event='advisory' AND query LIKE 'INSERT INTO cratectl.hold_matter_outcomes%'"))
        return (value, rows[0]) if len(rows) == 1 else None
    return wait('one committed target and an independently observed paused second transaction', observed)


def kill_partial(operation):
    value, backend = partial(operation)
    before = items(operation)
    stop('worker', kill=True)
    lease_until = datetime.datetime.fromisoformat(value['job']['lease_until'].replace('Z', '+00:00'))
    wait('actual post-kill lease expiry', lambda: datetime.datetime.now(datetime.timezone.utc) > lease_until + datetime.timedelta(milliseconds=100), seconds=5)
    clear_barrier()
    wait('killed worker exact backend is absent', lambda: sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid=" + str(backend['pid']) + " AND backend_start='" + backend['backend_start'] + "'::timestamptz") == '0')
    check('SIGKILL and real lease expiry preserve the committed target and roll back target two', items(operation) == before and detail(operation)['processed'] == 1)
    return value, before


try:
    checkpoint()
    with socket.socket() as probe:
        check('owned registry port is available', probe.connect_ex(('127.0.0.1', 38443)) != 0)
    if args.require_clean_build:
        check('native matter source and artifacts identify one clean candidate', not result['source_dirty'] and result['build_source_matches_candidate'])
    owner = urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN'])
    database = 'cratectl_matter_' + RUN
    pgenv = dict(env, PGHOST=owner.hostname, PGPORT=str(owner.port), PGUSER=urllib.parse.unquote(owner.username), PGPASSWORD=urllib.parse.unquote(owner.password), PGDATABASE=owner.path[1:])
    check('native PostgreSQL is project-owned loopback35432', pgenv['PGHOST'] == '127.0.0.1' and pgenv['PGPORT'] == '35432')
    sql('CREATE DATABASE ' + database)
    for key in ['CRATECTL_OWNER_DSN', 'CRATECTL_DSN']:
        u = urllib.parse.urlsplit(env[key])
        env[key] = urllib.parse.urlunsplit((u.scheme, u.netloc, '/' + database, u.query, u.fragment))
    pgenv['PGDATABASE'] = database
    runtime_user = urllib.parse.unquote(urllib.parse.urlsplit(env['CRATECTL_DSN']).username)
    private('database.json', {'owner': env['CRATECTL_OWNER_DSN'], 'runtime': env['CRATECTL_DSN']})
    run([NEW, 'migrate'])
    plan = json.loads(run([NEW, 'migrate', '--plan']))
    check('isolated native matter database has safe exact current receipts', plan['binary_version'] == CURRENT_SCHEMA and len(plan['applied']) == CURRENT_SCHEMA and plan['safety_valid'] and not plan['pending'])
    tenant = 'matter-' + RUN
    roles = [('admin', 'admin', tenant), ('recovery', 'admin', tenant), ('reviewer', 'admin', tenant), ('reader', 'reader', tenant), ('worker', 'worker', tenant), ('other', 'admin', tenant + '-other')]
    for label, role, target in roles:
        file = PRIVATE / (label + '.token')
        run([NEW, 'provision', '--tenant', target, '--actor', label, '--role', role, '--token-file', file])
        tokens[label] = file.read_text().strip()
    private('workers.json', {'token_files': [str(PRIVATE / 'worker.token')]})
    runtime = dict(env)
    runtime.pop('CRATECTL_OWNER_DSN', None)
    start_registry()
    base = '/api/v1/hold-matters/investigation'
    create('investigation')
    check('reader worker and other tenant cannot inspect this matter', api(base, role='reader')[0] == 403 and api(base, role='worker')[0] == 401 and api(base, role='other')[0] == 404)
    for repo in ['matter-a', 'matter-b']:
        cli('/api/v1/repositories', {'name': repo, 'format': 'oci'})
    run([ORAS, 'login', '--plain-http', '--registry-config', PRIVATE / 'oras-auth.json', '--username', 'admin', '--password-stdin', '127.0.0.1:38443'], input_bytes=(tokens['admin'] + '\n').encode())
    dependency = b'Owned native matter independent dependency\n' * 256
    private('dependency.txt', dependency)
    targets, payloads = [], {}
    for n, repo in enumerate(['matter-a', 'matter-a', 'matter-b']):
        body = ('Owned native matter package ' + str(n) + '\n').encode() * 1024
        private('package.txt', body)
        ref = '127.0.0.1:38443/' + repo + '/app:v' + str(n)
        oras('push', ref, 'package.txt:text/plain', 'dependency.txt:text/plain')
        digest = oras('resolve', ref).decode().strip()
        target = {'repository': repo, 'path': 'app/manifests/' + digest}
        targets.append(target)
        payloads[repo + '\n' + target['path']] = body
    placement_plan = preview('hold', targets)
    placement = admit(placement_plan, key='native-lost-admission')
    replay = admit(placement_plan, key='native-lost-admission')
    check('CLI confirms exact placement admission without duplicate operation', replay == placement and len(get(base + '/operations')['items']) == 1)
    stop('registry')
    start_registry()
    check('actual registry restart retains the complete immutable pending intent', detail(placement)['job']['state'] == 'pending' and len(items(placement)) == 3)
    install_barrier(placement)
    start_worker()
    killed, original_items = kill_partial(placement)
    start_worker()
    complete = finished(placement)
    check('replacement worker resumes only unfinished targets after SIGKILL', complete['processed'] == 3 and complete['effected'] == 3 and complete['job']['generation'] > killed['job']['generation'] and items(placement)[0] == original_items[0])
    for target in targets:
        check('native deletion is fenced by the placed matter', api('/v2/' + target['repository'] + '/' + target['path'], method='DELETE')[0] == 409)
        directory = PRIVATE / ('pull-' + str(len(checks)))
        directory.mkdir()
        oras('pull', '127.0.0.1:38443/' + target['repository'] + '/app@' + target['path'].split('/')[-1], cwd=directory)
        check('stock ORAS consumes exact held package and dependency bytes', (directory / 'package.txt').read_bytes() == payloads[target['repository'] + '\n' + target['path']] and (directory / 'dependency.txt').read_bytes() == dependency)
    stop('worker')
    release = admit(preview('release_hold', targets))
    check('release proposal has no admitted release job', release['state'] == 'awaiting_approval' and 'job' not in release)
    cli(base + '/operations/' + str(release['sequence']) + '/approve', {'expected_revision': release['revision'], 'preview_digest': release['plan']['preview_digest'], 'reason': 'Requester attempts self approval'}, ok=False)
    approved = approve(release)
    install_barrier(approved)
    start_worker()
    _, partial_items = kill_partial(approved)
    cli('/api/v1/jobs/' + approved['job'] + '/cancel', {})
    start_worker()
    cancelled = finished(approved, 'cancelled')
    check('native cancellation preserves committed release and leaves remaining targets protected', cancelled['processed'] == 1 and items(approved) == partial_items and sum(bool(lifecycle(t).get('matter_held')) for t in targets) == 2)
    stop('worker')
    cli('/api/v1/jobs/' + approved['job'] + '/retry', {})
    start_worker()
    check('native retry completes only the original unobserved release targets', finished(approved)['processed'] == 3 and items(approved)[0] == partial_items[0] and all(v['member_revision'] == 2 for v in items(approved)))
    stop('worker')
    for revoked in ['requester', 'approver']:
        replacement = admit(preview('hold', targets))
        start_worker()
        finished(replacement)
        stop('worker')
        requester, approver = 'requester-' + revoked, 'approver-' + revoked
        for label in [requester, approver]:
            file = PRIVATE / (label + '.token')
            run([NEW, 'provision', '--tenant', tenant, '--actor', label, '--role', 'admin', '--token-file', file])
            tokens[label] = file.read_text().strip()
        proposal = admit(preview('release_hold', targets, role=requester), role=requester)
        approved = approve(proposal, role=approver)
        install_barrier(approved)
        start_worker()
        partial(approved)
        run([NEW, 'revoke', '--token-file', PRIVATE / ((requester if revoked == 'requester' else approver) + '.token')])
        clear_barrier()
        failed = finished(approved, 'failed')
        check('current ' + revoked + ' revocation rolls back the in-flight second release', failed['processed'] == 1 and failed['job']['last_error'] == 'hold_matter_authorization' and sum(bool(lifecycle(t).get('matter_held')) for t in targets) == 2)
        old_outcomes = items(approved)
        cli('/api/v1/jobs/' + approved['job'] + '/retry', {}, role='recovery')
        check('job retry by recovery administrator cannot transfer ' + revoked + ' authority', finished(approved, 'failed')['processed'] == 1 and items(approved) == old_outcomes)
        stop('worker')
        remaining = [{'repository': v['repository'], 'path': v['path']} for v in old_outcomes if v['outcome'] == 'pending']
        fresh = approve(admit(preview('release_hold', remaining, role='recovery'), role='recovery'))
        start_worker()
        recovered = finished(fresh)
        check('fresh requester and independent approval recover only remaining ' + revoked + ' targets', recovered['processed'] == 2 and recovered['effected'] == 2 and not any(lifecycle(t).get('matter_held') for t in targets) and items(approved) == old_outcomes)
        stop('worker')
    history = get(base + '/history?limit=100')['items']
    original = [v for v in history if v['kind'] == 'hold.matter.target' and v['data']['operation'] == placement['sequence']]
    check('original placement receipts survive all subsequent release and recovery operations', len(original) == 3 and all(v['data']['member']['held'] for v in original))
    check('every declared timing helper was closed by exact owned identity', len(result['timing_helpers']) == 4 and all(v['status'] == 'closed' and v['cleanup']['backend_absent'] for v in result['timing_helpers']))
    result['status'] = 'passed'
except BaseException as error:
    result['status'] = 'failed'
    result['failure'] = type(error).__name__ + ': ' + str(error)
finally:
    stop('worker')
    if barrier_state is not None or barrier_installed:
        try:
            clear_barrier()
        except BaseException as error:
            result['status'] = 'failed'
            result['cleanup_failure'] = type(error).__name__ + ': ' + str(error)
    for name in list(processes):
        stop(name)
    target = ROOT / 'evidence' / datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    target.mkdir(parents=True, exist_ok=True)
    path = target / ('hold-matters-' + RUN + '.json')
    path.write_text(json.dumps(result, indent=2) + '\n')
    print(result['status'].upper() + ': ' + str(len(checks)) + ' native matter assertions; ' + str(path), flush=True)
if result['status'] != 'passed':
    raise SystemExit(result.get('failure', result.get('cleanup_failure', 'native matter journey failed')))
