#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned schema-7 upgrade and real scheduled-retirement ORAS/CLI recovery.

All native output, including failed and timed-out commands, stays in permanent
private logs. The public record contains identities, observations and log paths.
Artifact ages and two explicit SQL timing barriers are test fixtures. Schedule
clocks and worker leases advance through actual elapsed time, never owner edits.
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
from pathlib import Path
from qualification_contract import candidate_binary_directory, candidate_artifact_names
BIN = candidate_binary_directory()
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--require-clean-build', action='store_true')
args = parser.parse_args()
from qualification_contract import CURRENT_SCHEMA
ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
RUN = uuid.uuid4().hex[:10]
PRIVATE = ROOT / '.private/retention-schedule-conformance' / RUN
PRIVATE.mkdir(parents=True, mode=0o700)
PRIVATE.chmod(0o700)
OLD = ROOT / '.cache/retention-final-production/cratectld'
OLD_SOURCE = '6cac8851da675dcaf531d6f8ed2aa26c927a243b'
NEW, CLI = BIN / 'cratectld', BIN / 'cratectl'
ORAS = ROOT / '.cache/bin/oras'
PSQL = ROOT / '.cache/postgresql-16.15-install/bin/psql'
BASE = 'http://127.0.0.1:38443'
env = dict(os.environ)
tokens, processes, logs = {}, {}, {}
commands, checks, process_events = [], [], []
barrier = None
barrier_state = None
barrier_number = 0


def identity(binary):
    values = {}
    output = subprocess.check_output([ROOT / '.cache/go/bin/go', 'version', '-m', binary], text=True)
    for line in output.splitlines():
        fields = line.strip().split('\t')
        if len(fields) == 2 and fields[0] == 'build' and '=' in fields[1]:
            key, value = fields[1].split('=', 1)
            values[key] = value
    return values


candidate = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
scope = ['cmd', 'internal', 'scripts', 'web', 'api', 'go.mod', 'go.sum', 'Makefile']
result = {
    'run': RUN, 'candidate': candidate, 'status': 'running',
    'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain', '--', *scope]).strip()),
    'build_identity': {str(p.relative_to(ROOT)): identity(p) for p in [OLD, NEW, CLI]},
    'artifact_digests': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [OLD, NEW, CLI, ORAS]},
    'checks': checks, 'commands': commands, 'process_events': process_events,
    'timing_helpers': [],
    'private_logs': str(PRIVATE.relative_to(ROOT)),
    'topology': f'Native {platform.platform()}, qualified schema-7 binary then schema-{CURRENT_SCHEMA} registry/worker, PostgreSQL 16.15 forced RLS and restricted runtime, stock ORAS 1.3.6 and cratectl CLI. Explicit HTTP loopback 38443. Runtime processes omit the owner DSN; native clients omit both database DSNs.',
    'limits': [
        'Canonical OCI manifest creation-age/newest/tag/hold/reference rules. No physical erasure or reclaimed storage; other formats/rules and production recovery remain required.',
        'Artifact creation age is an owned SQL fixture. Claim and second-outcome barriers are declared timing faults in the isolated database, not supported product hooks or metadata repair.',
        'Schedule due slots, credential expiration and post-kill worker lease expiry use real elapsed time. Controlled maintenance stops old processes; rolling compatibility, HA, scale and backup/restore are not established.',
        'Private raw native logs and isolated databases remain retained on success or failure. The public record does not include credentials or raw process output.',
    ],
}
result['expected_schema'] = CURRENT_SCHEMA
result['build_source_matches_candidate'] = all(
    result['build_identity'][str(p.relative_to(ROOT))].get('vcs.revision') == candidate
    and result['build_identity'][str(p.relative_to(ROOT))].get('vcs.modified') == 'false'
    for p in [NEW, CLI]
)


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


def run(argv, extra=None, input_bytes=None, ok=True, cwd=PRIVATE, timeout=90):
    command_env = dict(env)
    command_env.update(extra or {})
    if Path(str(argv[0])).name in ['oras', 'cratectl']:
        for key in ['CRATECTL_OWNER_DSN', 'CRATECTL_DSN']:
            command_env.pop(key, None)
    log = private('command-%04d.log' % len(commands), b'')
    entry = {'argv': [str(a).replace(str(PRIVATE), 'PRIVATE') for a in argv],
             'private_log': str(log.relative_to(ROOT)), 'expected_success': ok}
    started = time.monotonic()
    try:
        with log.open('ab') as output:
            p = subprocess.run([str(a) for a in argv], env=command_env, input=input_bytes,
                               cwd=cwd, stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
        entry['exit'] = p.returncode
    except subprocess.TimeoutExpired:
        entry['timeout'] = True
        raise AssertionError('native command timeout; retained log: ' + entry['private_log'])
    finally:
        entry['seconds'] = round(time.monotonic() - started, 3)
        entry['log_bytes'] = log.stat().st_size
        commands.append(entry)
        checkpoint()
    if (p.returncode == 0) != ok:
        raise AssertionError('native command status; retained log: ' + entry['private_log'])
    if log.stat().st_size > 4 << 20:
        raise AssertionError('native output exceeded observation budget; full private log retained')
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


def spawn(name, argv, runtime=None):
    if name in processes:
        raise AssertionError('owned process identity already active: ' + name)
    path = private(name + '.log', b'') if not (PRIVATE / (name + '.log')).exists() else PRIVATE / (name + '.log')
    logs[name] = path.open('ab')
    processes[name] = subprocess.Popen([str(a) for a in argv], env=runtime or env,
                                       stdin=subprocess.DEVNULL, stdout=logs[name], stderr=subprocess.STDOUT)
    process_events.append({'process': name, 'pid': processes[name].pid,
                           'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           'private_log': str(path.relative_to(ROOT))})
    checkpoint()
    return processes[name]


def start(name, binary=NEW, worker=False, reject=False):
    argv = [binary, 'worker' if worker else 'serve', '--objects', PRIVATE / 'objects']
    if worker:
        argv += ['--identities', PRIVATE / 'workers.json', '--poll', '20ms', '--lease', '3s']
    else:
        argv += ['--listen', '127.0.0.1:38443', '--public-url', BASE, '--dev-loopback-http',
                 '--allow-private-upstreams', '127.0.0.1/32', '--upstream-credentials', PRIVATE / 'upstreams.json']
    runtime = dict(env)
    runtime.pop('CRATECTL_OWNER_DSN', None)
    p = spawn(name, argv, runtime)
    if reject:
        try:
            code = p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            raise AssertionError('old runtime stayed admitted to the upgraded schema')
        text = (PRIVATE / (name + '.log')).read_text(errors='replace').lower()
        check('actual old ' + name + f' rejects schema {CURRENT_SCHEMA}', code != 0 and 'schema' in text and 'flag provided but not defined' not in text)
        stop(name)
    elif not worker:
        def ready():
            if p.poll() is not None:
                raise AssertionError('registry exited; retained private log')
            try:
                with urllib.request.urlopen(BASE + '/health/ready', timeout=1) as response:
                    return response.status == 200
            except OSError:
                return False
        wait('owned registry readiness', ready, timeout=10)


def wait(label, condition, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError('timeout: ' + label)


def api(path, method='GET', body=None, role='admin', key=None, headers=None):
    if isinstance(body, dict):
        body = json.dumps(body).encode()
    h = {'Authorization': 'Bearer ' + tokens[role], 'Content-Type': 'application/json', **(headers or {})}
    if method in ['POST', 'PUT']:
        h['Idempotency-Key'] = key or uuid.uuid4().hex
    request = urllib.request.Request(BASE + path, data=body, method=method, headers=h)
    try:
        response = urllib.request.urlopen(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read((4 << 20) + 1)
        if len(body) > 4 << 20:
            raise AssertionError('management observation exceeded byte budget')
        return response.status, body, dict(response.headers)


def get(path, role='admin'):
    code, body, _ = api(path, role=role)
    if code != 200:
        raise AssertionError('management observation status ' + str(code) + ': ' + path)
    return json.loads(body)


def cli(path, body=None, role='admin', key=None, method='PUT', ok=True):
    argv = [CLI, '--url', BASE, '--token-file', PRIVATE / (role + '.token'), '--path', path]
    if body is not None:
        argv += ['--method', method, '--body-file', private('request-%04d.json' % len(commands), body),
                 '--idempotency-key', key or uuid.uuid4().hex]
    output = run(argv, ok=ok)
    return json.loads(output) if ok else output


def oras(*argv, reader=False, ok=True, cwd=PRIVATE):
    return run([ORAS, *argv, '--plain-http', '--registry-config', PRIVATE / ('reader-auth.json' if reader else 'publisher-auth.json')], ok=ok, cwd=cwd)


def policy(repo):
    return '/api/v1/repositories/' + repo + '/retention-policies/age'


def configure_policy(repo, role='admin', revision=0, keep=1, tagged=True):
    return cli(policy(repo), {'expected_revision': revision, 'min_age_seconds': 60, 'keep_last': keep,
                             'protect_tagged': tagged, 'enabled': True, 'reason': 'Retain current and protected owned native releases'}, role=role)


def schedule(repo='containers', role='admin'):
    return get(policy(repo) + '/schedule', role)


def settings(repo='containers', role='admin', enabled=True, immediate=True, maximum=100):
    response = api(policy(repo) + '/schedule', role=role)
    current = json.loads(response[1]) if response[0] == 200 else None
    if response[0] not in [200, 404]:
        raise AssertionError('cannot read current automatic approval')
    return {'expected_revision': current['revision'] if current else 0,
            'expected_policy_revision': get(policy(repo), role)['revision'],
            'expected_source_revision': get('/api/v1/repositories/' + repo, role)['source_revision'],
            'interval_seconds': 60, 'max_targets': maximum, 'enabled': enabled,
            'authorize_future_retirements': enabled, 'run_immediately': enabled and immediate,
            'reason': 'Explicit native approval for future complete retained retirement'}


def configure(repo='containers', role='admin', **options):
    return cli(policy(repo) + '/schedule', settings(repo, role, **options), role=role)


def detail(job, role='admin'):
    return get('/api/v1/maintenance/retention-runs/' + job, role)


def await_run(repo='containers', previous=None, role='admin', state='succeeded'):
    job = wait('new automatic run', lambda: (lambda v: v if v and v != previous else None)(schedule(repo, role).get('last_job')))
    def complete():
        value = detail(job, role)
        if value['job']['state'] == state:
            return value
        if value['job']['state'] in ['failed', 'cancelled'] and state == 'succeeded':
            raise AssertionError('automatic run failed: ' + value['job']['last_error'])
        return None
    return wait('automatic run durable outcome', complete)


def pull(repo, digest, label, expected, ok=True):
    directory = PRIVATE / label
    directory.mkdir()
    output = oras('pull', '127.0.0.1:38443/' + repo + '/proof@' + digest, reader=True, ok=ok, cwd=directory)
    if ok:
        check('stock ORAS exact application/dependency bytes: ' + label,
              (directory / 'primary.txt').read_bytes() == expected and (directory / 'dependency.txt').read_bytes() == dependency)
    else:
        check('stock ORAS rejects retired or denied target: ' + label, b'Error' in output or b'error' in output)


def restore(repo, digest, role='admin'):
    path = 'proof/manifests/' + digest
    current = get('/api/v1/repositories/' + repo + '/artifacts/lifecycle?' + urllib.parse.urlencode({'path': path}), role)
    return cli('/api/v1/repositories/' + repo + '/artifacts/lifecycle',
               {'path': path, 'digest': digest[7:], 'expected_revision': current['revision'],
                'action': 'restore', 'reason': 'Verify and restore exact retained native bytes'}, role=role)


def sql(statement):
    return run([PSQL, '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', statement], pgenv).decode().strip()


def install_barrier(repo, observations=False):
    global barrier, barrier_state, barrier_number
    if barrier is not None:
        raise AssertionError('timing barrier already present')
    lock = 1000000 + int(RUN[:6], 16)
    table = 'retention_observations' if observations else 'jobs'
    barrier = table
    barrier_number += 1
    barrier_state = PRIVATE / ('timing-helper-%d.json' % barrier_number)
    child = spawn('timing-lock', [sys.executable, ROOT / 'scripts/sql_timing.py', 'hold',
        '--state', barrier_state, '--label', 'cratectl-barrier-native-' + RUN + '-' + str(barrier_number),
        '--lock', str(lock)], pgenv)

    def ready():
        if child.poll() is not None:
            raise AssertionError('owned timing controller exited before readiness; inspect private log')
        if not barrier_state.exists():
            return False
        state = json.loads(barrier_state.read_text())
        if state['status'] != 'ready':
            return False
        return sql(f"SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid={int(state['backend']['pid'])} AND locktype='advisory' AND objid={lock} AND classid=0 AND objsubid=1 AND granted)") == 't'

    wait('exact owned timing session holds its lock', ready, timeout=15)
    predicate = (f"NEW.ordinal=2 AND EXISTS(SELECT 1 FROM cratectl.retention_runs r WHERE(r.tenant,r.sequence,r.task)=(NEW.tenant,NEW.sequence,NEW.task) AND r.repository='{repo}')"
                 if observations else f"NEW.kind='repository.retention' AND NEW.state='running' AND NEW.payload->'policy'->>'repository'='{repo}'")
    event = 'INSERT' if observations else 'UPDATE'
    sql(f"CREATE FUNCTION cratectl.retention_native_timing_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant='{tenant}' AND {predicate} THEN PERFORM pg_advisory_xact_lock({lock}); END IF; RETURN NEW; END $$; CREATE TRIGGER cratectl_retention_native_timing_barrier BEFORE {event} ON cratectl.{table} FOR EACH ROW EXECUTE FUNCTION cratectl.retention_native_timing_barrier()")


def clear_barrier():
    global barrier, barrier_state
    try:
        if barrier is not None:
            sql(f'DROP TRIGGER IF EXISTS cratectl_retention_native_timing_barrier ON cratectl.{barrier}; DROP FUNCTION IF EXISTS cratectl.retention_native_timing_barrier()')
            barrier = None
    finally:
        child = processes.get('timing-lock')
        stop('timing-lock')
        if barrier_state is not None:
            run([sys.executable, ROOT / 'scripts/sql_timing.py', 'close', '--state', barrier_state], pgenv)
            state = json.loads(barrier_state.read_text())
            check('owned timing helper backend closes before the next native step',
                  state['status'] == 'closed' and state['cleanup']['backend_absent']
                  and (child is None or child.returncode == 0))
            result['timing_helpers'].append(state)
            barrier_state = None


def age(repo):
    sql(f"UPDATE cratectl.artifacts SET created_at=created_at-interval '600 seconds' WHERE tenant='{tenant}' AND repository='{repo}'")


try:
    checkpoint()
    with socket.socket() as probe:
        check('owned native loopback port available', probe.connect_ex(('127.0.0.1', 38443)) != 0)
    if args.require_clean_build:
        check('native source and artifacts identify one exact clean candidate', not result['source_dirty'] and result['build_source_matches_candidate'])
    check('retained baseline is the qualified clean schema-7 source', identity(OLD).get('vcs.revision') == OLD_SOURCE and identity(OLD).get('vcs.modified') == 'false')
    check('stock client identifies ORAS 1.3.6', b'1.3.6' in run([ORAS, 'version']))
    owner = urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN'])
    database = 'cratectl_retention_schedules_' + RUN
    pgenv = dict(env, PGHOST=owner.hostname, PGPORT=str(owner.port or 5432),
                 PGUSER=urllib.parse.unquote(owner.username), PGPASSWORD=urllib.parse.unquote(owner.password),
                 PGDATABASE=owner.path.lstrip('/'))
    sql('CREATE DATABASE ' + database)
    pgenv['PGDATABASE'] = database
    for key in ['CRATECTL_OWNER_DSN', 'CRATECTL_DSN']:
        u = urllib.parse.urlsplit(env[key])
        env[key] = urllib.parse.urlunsplit((u.scheme, u.netloc, '/' + database, u.query, u.fragment))
    private('database.json', {'owner': env['CRATECTL_OWNER_DSN'], 'runtime': env['CRATECTL_DSN']})
    result['database'] = database
    run([OLD, 'migrate'])
    before = json.loads(run([OLD, 'migrate', '--plan']))
    check('old binary creates seven safe frozen migration receipts', len(before['applied']) == 7 and before['safety_valid'])
    tenant = 'retention-auto-' + RUN
    for role, kind, target in [('admin', 'admin', tenant), ('recovery', 'admin', tenant),
                                ('reader', 'reader', tenant), ('worker', 'worker', tenant), ('other', 'admin', tenant + '-other')]:
        file = PRIVATE / (role + '.token')
        run([OLD, 'provision', '--tenant', target, '--actor', role, '--role', kind, '--token-file', file])
        tokens[role] = file.read_text().strip()
    private('workers.json', {'token_files': [str(PRIVATE / 'worker.token')]})
    private('upstreams.json', {tenant + '/self': {'value': tokens['reader'], 'allowed_url': BASE + '/v2/containers/'}})
    start('registry', OLD)
    check('old baseline creates hosted OCI', api('/api/v1/repositories', 'POST', {'name': 'containers', 'format': 'oci'})[0] == 201)
    for role in ['admin', 'reader']:
        run([ORAS, 'login', '--plain-http', '--registry-config', PRIVATE / ('publisher-auth.json' if role == 'admin' else 'reader-auth.json'),
             '--username', 'token', '--password-stdin', '127.0.0.1:38443'], input_bytes=(tokens[role] + '\n').encode())
    dependency = b'owned independent scheduled native dependency\n' * 1024
    private('dependency.txt', dependency)
    roots, payloads = [], []
    for label in ['held', 'eligible', 'child']:
        payload = ('owned scheduled native ' + label + '\n').encode() * 2048
        payloads.append(payload)
        private('primary.txt', payload)
        oras('push', '127.0.0.1:38443/containers/proof:latest', 'primary.txt:text/plain', 'dependency.txt:text/plain')
        roots.append(oras('resolve', '127.0.0.1:38443/containers/proof:latest').decode().strip())
        if label == 'eligible':
            cache_settings = {'upstream': {'url': BASE + '/v2/containers/', 'networks': ['127.0.0.1/32'], 'credential_ref': 'self'},
                              'cache': {'fresh_seconds': 3600, 'stale_seconds': 0, 'allow_no_store': True}}
            check('old baseline creates a governed proxy and group', api('/api/v1/repositories', 'POST', {'name': 'cache', 'format': 'oci', 'mode': 'proxy', 'settings': cache_settings})[0] == 201
                  and api('/api/v1/repositories', 'POST', {'name': 'combined', 'format': 'oci', 'mode': 'group', 'settings': {'members': ['cache', 'containers']}})[0] == 201)
            pull('cache', roots[-1], 'old-cached-native', payload)
    child_bytes = api('/v2/containers/proof/manifests/' + roots[2])[1]
    child = json.loads(child_bytes)
    index = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
             'manifests': [{'mediaType': child['mediaType'], 'digest': roots[2], 'size': len(child_bytes)}]}
    private('index.json', index)
    oras('manifest', 'push', '127.0.0.1:38443/containers/proof:latest', 'index.json', '--media-type', index['mediaType'])
    index_digest = oras('resolve', '127.0.0.1:38443/containers/proof:latest').decode().strip()
    check('old baseline establishes an active hold', api('/api/v1/repositories/containers/artifacts/lifecycle', 'PUT',
          {'path': 'proof/manifests/' + roots[0], 'digest': roots[0][7:], 'action': 'hold', 'expected_revision': 0, 'reason': 'Retain owned scheduled release'})[0] == 200)
    age('containers')
    configure_policy('containers')
    negative = api(policy('containers') + '/schedule')
    check('old baseline has no automatic retirement route', negative[0] == 404)
    old_plan = cli(policy('containers') + '/runs', {'expected_revision': 1, 'reason': 'Preserve a pending approved run across upgrade', 'dry_run': True}, method='POST')
    manual = cli(policy('containers') + '/runs', {'expected_revision': 1, 'reason': old_plan['reason'],
                 'evaluated_at': old_plan['evaluated_at'], 'preview_digest': old_plan['preview_digest']}, method='POST')['job']
    stop('registry')
    planned = json.loads(run([NEW, 'migrate', '--plan']))
    check(f'new migrator plans immutable schema steps 8 through {CURRENT_SCHEMA}', planned['binary_version'] == CURRENT_SCHEMA and planned['pending'] == list(range(8,CURRENT_SCHEMA+1)) and planned['safety_valid'])
    run([NEW, 'migrate'])
    after = json.loads(run([NEW, 'migrate', '--plan']))
    check('controlled upgrade preserves all seven receipts and adds safe schedule tables', after['applied'][:7] == before['applied'] and after['binary_version'] == CURRENT_SCHEMA and len(after['applied']) == CURRENT_SCHEMA and not after['pending'] and after['safety_valid'])
    result['schema_upgrade'] = {'before': before, 'after': after}
    start('old-worker', OLD, worker=True, reject=True)
    start('old-registry', OLD, reject=True)
    run([OLD, 'migrate', '--plan'], ok=False)
    start('registry')
    check('upgrade preserves pending manual approval identity', detail(manual)['plan']['preview_digest'] == old_plan['preview_digest'] and detail(manual)['job']['state'] == 'pending' and 'schedule' not in detail(manual)['plan'])
    start('worker', worker=True)
    wait('preserved manual run finishes', lambda: detail(manual)['job']['state'] == 'succeeded')
    check('new worker resumes preserved one-time targets', detail(manual)['retired'] == 1 and detail(manual)['skipped'] == 3)
    restore('containers', roots[1])
    pull('containers', roots[1], 'post-upgrade-restore', payloads[1])
    stop('worker')
    request = settings(maximum=2)
    cli(policy('containers') + '/schedule', dict(request, dry_run=True))
    check('native schedule preview saves no authority or work', api(policy('containers') + '/schedule')[0] == 404)
    data = json.dumps(request).encode()
    key = 'unread-native-approval-' + RUN
    with socket.create_connection(('127.0.0.1', 38443), timeout=10) as connection:
        header = ('PUT ' + policy('containers') + '/schedule HTTP/1.1\r\nHost: 127.0.0.1:38443\r\nAuthorization: Bearer ' + tokens['admin']
                  + '\r\nIdempotency-Key: ' + key + '\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(data)) + '\r\n\r\n').encode()
        connection.sendall(header + data)
        wait('independently observed unread configuration commit', lambda: api(policy('containers') + '/schedule')[0] == 200)
    replay = cli(policy('containers') + '/schedule', request, key=key)
    check('CLI confirms one actual lost-response future approval', replay['revision'] == 1 and len(get(policy('containers') + '/schedule/history?limit=100')['items']) == 1)
    due = schedule()['next_due_at']
    start('worker', worker=True)
    wait('complete-set budget deferral', lambda: schedule()['last_error'] == 'plan_budget_exceeded')
    check('oversized complete capture defers without partial work or due advance', schedule()['next_due_at'] == due and not get(policy('containers') + '/schedule/runs?limit=100')['items'])
    check('native current denial is set before automatic retirement', api('/api/v1/repositories/containers/decisions', 'PUT',
          {'path': 'proof/manifests/' + roots[1], 'digest': roots[1][7:], 'decision': 'denied'})[0] == 200)
    recurrence_started = time.monotonic()
    configure()
    first = await_run()
    first_id = schedule()['last_job']
    check('first scheduled capture records complete protected native outcomes', first['plan']['targets'] == 4 and first['retired'] == 1 and first['skipped'] == 3 and first['bytes_reclaimed'] == 0)
    pull('containers', roots[1], 'first-retired-native', payloads[1], ok=False)
    restore('containers', roots[1])
    pull('containers', roots[1], 'restored-still-denied', payloads[1], ok=False)
    check('restore preserves current digest decision', api('/v2/containers/proof/manifests/' + roots[1])[0] == 403)
    check('explicit current allowance permits exact restored bytes', api('/api/v1/repositories/containers/decisions', 'PUT',
          {'path': 'proof/manifests/' + roots[1], 'digest': roots[1][7:], 'decision': 'allowed'})[0] == 200)
    pull('containers', roots[1], 'restored-before-real-recurrence', payloads[1])
    scheduled = schedule()
    stop('worker')
    stop('registry')
    first_unexecuted_due = datetime.datetime.fromisoformat(scheduled['next_due_at'].replace('Z', '+00:00'))
    stopped_at = datetime.datetime.now(datetime.timezone.utc)
    check('worker stops before the first unexecuted due slot', stopped_at < first_unexecuted_due)
    restart_at = first_unexecuted_due + datetime.timedelta(seconds=63)
    started_wait = time.monotonic()
    required_stopped_seconds = (restart_at - stopped_at).total_seconds()
    resume_after = started_wait + required_stopped_seconds
    print('Waiting with registry/worker stopped across real due slots until ' + restart_at.isoformat(), flush=True)
    while time.monotonic() < resume_after:
        time.sleep(.2)
    stopped_seconds = time.monotonic() - started_wait
    result['actual_stopped_recurrence_seconds'] = round(stopped_seconds, 3)
    result['required_stopped_seconds'] = round(required_stopped_seconds, 3)
    start('registry')
    check('real registry restart preserves due authority and exact prior receipt', schedule()['revision'] == 2 and schedule()['last_job'] == first_id and schedule()['next_due_at'] == scheduled['next_due_at'])
    start('worker', worker=True)
    second = await_run(previous=first_id)
    result['actual_recurrence_seconds'] = round(time.monotonic() - recurrence_started, 3)
    second_id = schedule()['last_job']
    a, b = first['plan']['schedule'], second['plan']['schedule']
    result['clock_observations'] = {
        'first_capture': a, 'second_capture': b,
        'worker_and_registry_stopped_at': stopped_at.isoformat(),
        'first_unexecuted_due_at': first_unexecuted_due.isoformat(),
        'planned_restart_at': restart_at.isoformat(),
        'second_capture_evaluated_at': second['plan']['evaluated_at'],
        'next_due_after_second_capture': schedule()['next_due_at'],
        'first_run': first_id, 'second_run': second_id,
        'second_retired': second['retired'],
    }
    elapsed_slots = (datetime.datetime.fromisoformat(b['due_at'].replace('Z', '+00:00')) - datetime.datetime.fromisoformat(a['due_at'].replace('Z', '+00:00'))).total_seconds()
    check('real sixty-second due slots survive process downtime and coalesce missed intervals',
          result['actual_recurrence_seconds'] >= 120 and stopped_seconds >= required_stopped_seconds
          and elapsed_slots == 60 and b['coalesced_intervals'] >= 1 and second['retired'] == 1)
    rows = get(policy('containers') + '/schedule/runs?limit=100')['items']
    check('restart admits one current capture without a catch-up burst', [r['job'] for r in rows] == [first_id, second_id] and datetime.datetime.fromisoformat(schedule()['next_due_at'].replace('Z', '+00:00')) > datetime.datetime.now(datetime.timezone.utc))
    configure(enabled=False)
    restore('containers', roots[1])
    pull('containers', roots[0], 'held-after-real-recurrence', payloads[0])
    pull('containers', roots[2], 'child-after-real-recurrence', payloads[2])
    check('restore does not rebind current native tag', oras('resolve', '127.0.0.1:38443/containers/proof:latest').decode().strip() == index_digest)
    stop('worker')
    install_barrier('containers')
    configure()
    start('worker', worker=True)
    pending = await_run(previous=second_id, state='pending')
    pending_id = schedule()['last_job']
    stop('worker')
    clear_barrier()
    cli('/api/v1/jobs/' + pending_id + '/cancel', {}, method='POST')
    check('actual pending automatic cancellation records zero effects and leaves future schedule enabled', detail(pending_id)['job']['state'] == 'cancelled' and detail(pending_id)['retired'] == 0 and schedule()['enabled'])
    install_barrier('containers')
    configure()
    start('worker', worker=True)
    await_run(previous=pending_id, state='pending')
    fenced_id = schedule()['last_job']
    stop('worker')
    configure(enabled=False)
    clear_barrier()
    stop('registry')
    start('registry')
    start('worker', worker=True)
    fenced = await_run(previous=pending_id, state='failed')
    check('explicit pause fences a real pending capture across registry/worker restart', fenced['job']['last_error'] == 'retention_schedule_changed' and fenced['retired'] == 0 and api('/v2/containers/proof/manifests/' + roots[1])[0] == 200)
    stop('worker')
    configure()
    run([NEW, 'revoke', '--token-file', PRIVATE / 'admin.token'])
    start('worker', worker=True)
    wait('revoked future authority blocks admission', lambda: schedule(role='recovery')['last_error'] == 'requester_authorization_unavailable')
    check('revoked authorizer cannot create another capture or use CLI', schedule(role='recovery')['last_job'] == fenced_id and bool(cli(policy('containers') + '/schedule', role='admin', ok=False)))
    configure(role='recovery')
    recovered = await_run(previous=fenced_id, role='recovery')
    recovered_id = schedule(role='recovery')['last_job']
    check('replacement administrator explicitly reauthorizes without changing prior failed run', recovered['retired'] == 1 and detail(fenced_id, 'recovery')['job']['state'] == 'failed')
    configure(role='recovery', enabled=False)
    restore('containers', roots[1], 'recovery')
    stop('worker')
    expiry_file = PRIVATE / 'expiring.token'
    run([NEW, 'provision', '--tenant', tenant, '--actor', 'expiring', '--role', 'admin', '--token-file', expiry_file, '--expires-in', '8s'])
    tokens['expiring'] = expiry_file.read_text().strip()
    expiring_approval = configure(role='expiring')
    wait('actual authorizing credential expires', lambda: api('/api/v1/session', role='expiring')[0] == 401, timeout=15)
    start('worker', worker=True)
    wait('expired future authority blocks admission', lambda: schedule(role='recovery')['last_error'] == 'requester_authorization_unavailable')
    check('real credential expiry consumes no due slot or new job', schedule(role='recovery')['last_job'] == recovered_id
          and schedule(role='recovery')['next_due_at'] == expiring_approval['next_due_at'])
    configure(role='recovery')
    expiry_recovered = await_run(previous=recovered_id, role='recovery')
    expiry_id = schedule(role='recovery')['last_job']
    check('current credential supplies a new approval after actual expiry', expiry_recovered['retired'] == 1 and schedule(role='recovery')['authorized_actor'] == 'recovery')
    configure(role='recovery', enabled=False)
    restore('containers', roots[1], 'recovery')
    stop('worker')
    configure(role='recovery')
    configure_policy('containers', role='recovery', revision=1)
    start('worker', worker=True)
    wait('changed policy blocks original future approval', lambda: schedule(role='recovery')['last_error'] == 'policy_changed')
    check('policy change admits no target under earlier authority', schedule(role='recovery')['last_job'] == expiry_id)
    configure(role='recovery')
    policy_recovered = await_run(previous=expiry_id, role='recovery')
    check('new explicit approval binds current policy revision', policy_recovered['plan']['policy']['revision'] == 2 and policy_recovered['retired'] == 1)
    configure(role='recovery', enabled=False)
    restore('containers', roots[1], 'recovery')
    stop('worker')
    configure_policy('cache', role='recovery', keep=0, tagged=False)
    configure('cache', role='recovery')
    next_settings = {**cache_settings, 'cache': {**cache_settings['cache'], 'fresh_seconds': 300}}
    cli('/api/v1/repositories/cache/configuration', {'expected_revision': 0, 'settings': next_settings, 'reason': 'Replace exact source/cache revision before future capture'}, role='recovery')
    start('worker', worker=True)
    wait('changed source blocks original future approval', lambda: schedule('cache', 'recovery')['last_error'] == 'source_changed')
    check('source replacement admits no automatic proxy run', not get(policy('cache') + '/schedule/runs?limit=100', 'recovery')['items'])
    pull('cache', roots[1], 'current-source-before-reapproval', payloads[1])
    configure('cache', role='recovery')
    proxy_run = await_run('cache', role='recovery')
    check('fresh source approval retires exact retained proxy target', proxy_run['plan']['source_revision'] == 1 and proxy_run['retired'] == 1)
    configure('cache', role='recovery', enabled=False)
    pull('combined', roots[1], 'retired-group-source', payloads[1], ok=False)
    check('proxy tombstone stops group fallback to still-live hosted content', api('/v2/cache/proof/manifests/' + roots[1], role='recovery')[0] == 404 and api('/v2/containers/proof/manifests/' + roots[1], role='recovery')[0] == 200)
    restore('cache', roots[1], 'recovery')
    pull('combined', roots[1], 'restored-current-proxy-group', payloads[1])
    stop('worker')
    check('native crash fixture creates separate hosted repository', api('/api/v1/repositories', 'POST', {'name': 'crash-recovery', 'format': 'oci'}, role='recovery')[0] == 201)
    run([ORAS, 'login', '--plain-http', '--registry-config', PRIVATE / 'recovery-auth.json', '--username', 'token', '--password-stdin', '127.0.0.1:38443'], input_bytes=(tokens['recovery'] + '\n').encode())
    for number in range(3):
        private('primary.txt', ('owned committed-before-kill ' + str(number)).encode() * 2048)
        run([ORAS, 'push', '127.0.0.1:38443/crash-recovery/proof:latest', 'primary.txt:text/plain', 'dependency.txt:text/plain', '--plain-http', '--registry-config', PRIVATE / 'recovery-auth.json'])
    age('crash-recovery')
    configure_policy('crash-recovery', role='recovery', keep=0, tagged=False)
    install_barrier('crash-recovery', observations=True)
    configure('crash-recovery', role='recovery')
    start('worker', worker=True)
    crash_id = wait('native crash capture admitted', lambda: schedule('crash-recovery', 'recovery').get('last_job'))
    wait('first target outcome commits before blocked second outcome', lambda: detail(crash_id, 'recovery')['processed'] == 1)
    initial = detail(crash_id, 'recovery')
    stop('worker', kill=True)
    clear_barrier()
    first_outcome = get('/api/v1/maintenance/retention-runs/' + crash_id + '/items?limit=100', 'recovery')['items'][0]
    start('worker', worker=True)
    resumed = await_run('crash-recovery', role='recovery')
    final_outcomes = get('/api/v1/maintenance/retention-runs/' + crash_id + '/items?limit=100', 'recovery')['items']
    check('real worker SIGKILL resumes only remaining targets after actual lease expiry', initial['retired'] == 1 and resumed['retired'] == 3 and resumed['processed'] == 3 and resumed['job']['generation'] > initial['job']['generation'] and final_outcomes[0] == first_outcome)
    check('crash recovery keeps unique committed target and lifecycle outcomes', len(final_outcomes) == 3 and all(row['outcome'] == 'retired' and row['outcome_revision'] == 1 for row in final_outcomes))
    configure('crash-recovery', role='recovery', enabled=False)
    for role, expected in [('reader', 403), ('worker', 401), ('other', 404)]:
        check(role + ' cannot administer this schedule', api(policy('containers') + '/schedule', role=role)[0] == expected)
    native_rows = get(policy('containers') + '/schedule/runs?limit=100', 'recovery')['items']
    traversed, after_cursor = [], '0'
    while True:
        part = cli(policy('containers') + '/schedule/runs?limit=1&after=' + after_cursor, role='recovery')
        traversed += [item['job'] for item in part['items']]
        if not part['more']:
            break
        after_cursor = part['items'][-1]['job'].split(':')[0]
    check('native CLI traverses every immutable scheduled run over bounded pages', traversed == [row['job'] for row in native_rows] and manual not in traversed)
    final_state = schedule(role='recovery')
    history = get(policy('containers') + '/schedule/history?limit=100', 'recovery')['items']
    public = json.dumps({'configuration': final_state, 'history': history, 'runs': native_rows})
    check('public automatic receipts omit all credential values and private hashes', all(value not in public and hashlib.sha256(value.encode()).hexdigest() not in public for value in tokens.values()))
    stop('worker')
    stop('registry')
    start('registry')
    check('final registry restart preserves paused authority and exact immutable receipts', not schedule(role='recovery')['enabled'] and get(policy('containers') + '/schedule/runs?limit=100', 'recovery')['items'] == native_rows and schedule(role='recovery')['revision'] == final_state['revision'])
    result['status'] = 'passed'
except BaseException as error:
    result['status'] = 'failed'
    result['failure'] = type(error).__name__ + ': ' + str(error)
finally:
    stop('worker')
    try:
        if barrier is not None or barrier_state is not None or 'timing-lock' in processes:
            clear_barrier()
    except BaseException as error:
        result['status'] = 'failed'
        result['cleanup_failure'] = type(error).__name__ + ': ' + str(error)
    for name in list(processes):
        stop(name)
    checkpoint()
    target = ROOT / 'evidence' / datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    target.mkdir(parents=True, exist_ok=True)
    evidence = target / ('retention-schedules-' + RUN + '.json')
    evidence.write_text(json.dumps(result, indent=2) + '\n')
    print(result['status'].upper() + ': ' + str(len(checks)) + ' native scheduled-retirement assertions; ' + str(evidence), flush=True)
if result['status'] != 'passed':
    raise SystemExit(result.get('failure', result.get('cleanup_failure', 'native scheduled-retirement failed')))
