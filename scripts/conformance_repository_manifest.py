#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Replay the declarative hosted repository journey against an owned native PostgreSQL."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from bounded_client import run_owned_client
from qualification_contract import candidate_binary_directory


ROOT = Path(__file__).resolve().parents[1]
BASE = 'https://localhost:38443'
TENANT = 'cratectl-manifest'
OTHER = 'cratectl-other'
NAME = 'cratectl-packages'
REPOSITORY = '/api/v1/repositories/' + NAME


def sha(file):
    with file.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def evaluate(args):
    os.umask(0o077)
    private = ROOT / '.private'
    if private.is_symlink() or private.stat().st_mode & 0o077:
        raise ValueError('use the existing owner-only .private directory')
    for port in (35432, 38443):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', port))
    work = Path(tempfile.mkdtemp(prefix='cratectl-manifest-', dir=private))
    print('Private fixture records at', work.relative_to(ROOT), flush=True)
    binary = candidate_binary_directory(args.binary_directory)
    client, daemon = binary / 'cratectl', binary / 'cratectld'
    postgres = args.pg_bin.resolve()
    app = work / 'installation'
    data = work / 'postgres'
    public_env = {key: value for key, value in os.environ.items()
                  if not key.startswith(('CRATECTL_', 'PG', 'npm_config_', 'NPM_CONFIG_'))
                  and key not in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')}
    checks = []
    server = None

    def check(name, passed):
        if not passed:
            raise ValueError(name)
        checks.append(name)

    def call(label, *command, cwd=ROOT, environment=public_env, status=0, timeout=35):
        with (work / (label + '.log')).open('wb') as log:
            code, output = run_owned_client(command, cwd, environment, timeout=timeout,
                                            output_limit=2 << 20, capture_limit=256 << 10, output_sink=log)
        if status is not None and code != status:
            raise ValueError(f'{label} returned {code}, expected {status}')
        return code, output

    def write(name, content):
        path = work / name
        with path.open('x') as stream:
            json.dump(content, stream)
        return path

    def cli(label, *argv, config=None, status=0):
        return call(label, client, *argv, '--config', config or app / 'client.json', status=status)

    def api(label, endpoint, method='GET', payload=None):
        flags = ['--path', endpoint, '--method', method]
        if payload is not None:
            flags += ['--body-file', write(label + '.json', payload), '--idempotency-key', 'cratectl-manifest-' + label]
        return json.loads(cli(label, *flags)[1])

    def start_server():
        process = subprocess.Popen([daemon, 'serve', '--config', app / 'runtime.json'], env=public_env,
                                   stdout=server_log, stderr=subprocess.STDOUT)
        trust = ssl.create_default_context(cafile=str(app / 'ca.crt'))
        local_http = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))
        try:
            for _ in range(120):
                if process.poll() is not None:
                    raise ValueError('owned registry stopped before readiness')
                try:
                    with local_http.open(BASE + '/health/ready', timeout=1) as reply:
                        if reply.status == 200:
                            return process
                except (OSError, urllib.error.URLError):
                    time.sleep(.05)
            raise ValueError('trusted registry did not reach readiness')
        except BaseException:
            stop_server(process)
            raise

    def stop_server(process):
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)

    report = {'schema': 1, 'profile': 'cratectl-repository-manifest-native-v1', 'status': 'failed',
              'checks': checks, 'platform': platform.platform(), 'goal_complete': False, 'broad_readiness': False,
              'private_fixture': str(work.relative_to(ROOT)),
              'limits': ['Hosted npm and the version 1 manifest fields on one native server.',
                         'Broader source configuration and Terraform/OpenTofu provider qualification remain open.']}
    started = False
    server_log = (work / 'registry.log').open('ab')
    try:
        candidate = call('candidate', 'git', 'rev-parse', 'HEAD')[1].strip()
        check('clean exact source', not call('source-clean', 'git', 'status', '--porcelain')[1].strip())
        report['candidate'] = candidate
        report['binary_sha256'] = {}
        for program in (client, daemon):
            build = call(program.name + '-build-info', ROOT / '.cache/go/bin/go', 'version', '-m', program)[1]
            check(program.name + ' matches the clean candidate', f'vcs.revision={candidate}' in build and 'vcs.modified=false' in build)
            report['binary_sha256'][program.name] = sha(program)
        report['postgres'] = call('postgres-version', postgres / 'postgres', '--version')[1].strip()
        check('real PostgreSQL 16.15', report['postgres'].endswith('16.15'))
        report['npm'] = call('stock-npm-version', 'npm', '--version')[1].strip()
        owner, runtime = secrets.token_hex(24), secrets.token_hex(24)
        password = work / 'pg-init-password'
        password.write_text(owner + '\n')
        try:
            call('initialize-owned-postgres', postgres / 'initdb', '-D', data, '--username=cratectl_owner',
                 '--pwfile=' + str(password), '--auth=scram-sha-256', '--locale=C', '--encoding=UTF8')
        finally:
            password.unlink(missing_ok=True)
        call('start-owned-postgres', postgres / 'pg_ctl', '-D', data, '-l', work / 'postgres.log',
             '-o', "-h 127.0.0.1 -p 35432 -c unix_socket_directories='' -c max_connections=24", 'start', '-w')
        started = True
        pg_env = dict(public_env, PGHOST='127.0.0.1', PGPORT='35432', PGUSER='cratectl_owner',
                      PGPASSWORD=owner, PGDATABASE='postgres')
        call('create-database', postgres / 'createdb', 'cratectl_manifest', environment=pg_env)
        pg_env['PGDATABASE'] = 'cratectl_manifest'
        roles = work / 'pg-runtime.sql'
        roles.write_text("CREATE ROLE cratectl_app LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT PASSWORD '" + runtime + "';\n")
        try:
            call('create-runtime-role', postgres / 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', roles, environment=pg_env)
        finally:
            roles.unlink(missing_ok=True)
        suffix = '@127.0.0.1:35432/cratectl_manifest?sslmode=disable'
        owner_env = dict(public_env, CRATECTL_OWNER_DSN='postgres://cratectl_owner:' + owner + suffix,
                         CRATECTL_DSN='postgres://cratectl_app:' + runtime + suffix)
        call('initialize-registry', daemon, 'init', '--tenant', TENANT, '--directory', app, environment=owner_env)
        for label, tenant, role in (('reader', TENANT, 'reader'), ('other', OTHER, 'admin')):
            token = work / (label + '.token')
            call('provision-' + label, daemon, 'provision', '--tenant', tenant, '--actor', 'cratectl-' + label,
                 '--role', role, '--token-file', token, environment=owner_env)
            write(label + '.json', {'version': 1, 'url': BASE, 'token_file': str(token), 'ca_file': str(app / 'ca.crt')})
        server = start_server()
        desired = {'version': 1, 'tenant': TENANT, 'name': NAME, 'format': 'npm',
                   'access': 'restricted', 'require_review': True}
        manifest = write('manifest.json', desired)
        plan_flags = ['repository-plan', '--manifest', manifest]
        apply_flags = ['repository-apply', '--manifest', manifest, '--approve']
        before = api('before-plan-audit', '/api/v1/audit/checkpoint')
        plan = json.loads(cli('plan-missing', *plan_flags)[1])
        check('absent repository has an authority and tenant bound creation plan',
              plan['action'] == 'create' and plan['current'] is None and plan['authority'] == BASE and plan['desired'] == desired)
        approval = plan['approval_sha256']
        cli('wrong-approval', *apply_flags, '0' * 64, status=1)
        cli('reader-denied', *plan_flags, config=work / 'reader.json', status=1)
        cli('other-tenant-denied', *apply_flags, approval, config=work / 'other.json', status=1)
        check('plan, wrong approval and denied callers leave the tenant journal unchanged',
              api('after-plan-audit', '/api/v1/audit/checkpoint') == before)
        other = write('other-manifest.json', {**desired, 'tenant': OTHER})
        with ThreadPoolExecutor(max_workers=2) as executor:
            pair = [executor.submit(cli, f'concurrent-create-{i}', *apply_flags, approval, status=None) for i in (1, 2)]
            outcomes = [attempt.result() for attempt in pair]
        check('concurrent approved requests produce one creation or a safe retry',
              any(code == 0 and json.loads(output)['action'] == 'created' for code, output in outcomes))
        check('retry after successful creation returns unchanged',
              json.loads(cli('retry-create', *apply_flags, approval)[1])['action'] == 'unchanged')
        events = api('create-audit', '/api/v1/audit?limit=100')['items']
        check('one repository creation event despite concurrent retry',
              sum(json.loads(event['payload'])['kind'] == 'repository.created' for event in events) == 1)
        check('second tenant can plan an independent same-name repository',
              json.loads(cli('independent-tenant-plan', 'repository-plan', '--manifest', other,
                             config=work / 'other.json')[1])['action'] == 'create')
        check('import returns the exact active hosted fields',
              json.loads(cli('import', 'repository-import', '--tenant', TENANT, '--name', NAME)[1]) == desired)
        divergent = write('divergent.json', {**desired, 'require_review': False})
        drift = json.loads(cli('review-drift', 'repository-plan', '--manifest', divergent)[1])
        check('plan exposes review drift without writing', drift['action'] == 'drift' and drift['drift'] == ['require_review'])
        package = work / 'package'
        package.mkdir()
        artifact_name = 'cratectl-manifest-fixture'
        (package / 'package.json').write_text(json.dumps({'name': artifact_name, 'version': '1.0.0',
                                                         'license': 'MIT', 'files': ['payload.txt']}))
        (package / 'payload.txt').write_text('Owned declarative publication bytes.\n')
        rc = work / 'npmrc'
        cli('private-npm-config', 'npm-config', '--repository', NAME, '--output', rc)
        npm_env = dict(public_env, NPM_CONFIG_USERCONFIG=str(rc), NPM_CONFIG_CACHE=str(work / 'publisher-cache'),
                       NPM_CONFIG_AUDIT='false', NPM_CONFIG_FUND='false')
        packed = json.loads(call('stock-npm-pack', 'npm', 'pack', '--ignore-scripts', '--json',
                                 cwd=package, environment=npm_env)[1])
        tarball = package / packed[0]['filename']
        call('stock-npm-publish', 'npm', 'publish', '--ignore-scripts', tarball, cwd=package, environment=npm_env)
        download = work / 'download'
        download.mkdir()
        consumer = dict(npm_env, NPM_CONFIG_CACHE=str(work / 'consumer-cache'))
        target = artifact_name + '@1.0.0'
        call('stock-pending-denial', 'npm', 'pack', target, '--ignore-scripts', '--json',
             cwd=download, environment=consumer, status=1)
        artifacts = api('inspect-unassessed', REPOSITORY + '/artifacts')['items']
        check('stock npm published its exact bytes and unassessed input was denied',
              len(artifacts) == 1 and artifacts[0]['decision'] == 'unassessed'
              and artifacts[0]['digest'] == sha(tarball) and not list(download.iterdir()))
        api('approve', REPOSITORY + '/decisions', 'PUT',
            {'path': artifacts[0]['path'], 'digest': artifacts[0]['digest'], 'decision': 'allowed'})
        stop_server(server)
        server = None
        server = start_server()
        check('registry restart preserves the declared state',
              json.loads(cli('restart-plan', *plan_flags)[1])['action'] == 'unchanged')
        restored = json.loads(call('stock-verified-download', 'npm', 'pack', target, '--ignore-scripts', '--json',
                                   cwd=download, environment=dict(consumer, NPM_CONFIG_CACHE=str(work / 'approved-cache')))[1])
        check('fresh stock npm downloads the exact approved archive after restart',
              sha(download / restored[0]['filename']) == sha(tarball))
        report['archive_sha256'] = sha(tarball)
        api('suspend', REPOSITORY + '/state', 'PUT',
            {'action': 'suspend', 'expected_revision': 0, 'reason': 'Retain the owned manifest fixture'})
        cli('stale-approved-create', *apply_flags, approval, status=1)
        retained = json.loads(cli('suspension-drift', *plan_flags)[1])
        check('stale approval leaves suspended repository retained',
              retained['action'] == 'drift' and retained['drift'] == ['state'] and retained['current']['state_revision'] == 1)
        cli('suspended-import-refused', 'repository-import', '--tenant', TENANT, '--name', NAME, status=1)
        check('suspended repository cannot be imported as active', True)
        call('revoke-other', daemon, 'revoke', '--token-file', work / 'other.token', environment=owner_env)
        result = cli('revoked-manifest-auth', 'repository-plan', '--manifest', other, config=work / 'other.json', status=1)
        check('revoked administrator cannot plan', 'HTTP 401' in result[1])
        audit = call('postgres-rls', postgres / 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', """
            SELECT count(*)||'/'||count(*) FILTER (WHERE c.relrowsecurity AND c.relforcerowsecurity)
                   ||'/'||count(*) FILTER (WHERE pg_get_userbyid(c.relowner)='cratectl_app')
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='cratectl' AND c.relkind IN ('r','p')
            AND EXISTS (SELECT FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant' AND NOT a.attisdropped);
            SELECT (NOT rolsuper AND NOT rolbypassrls AND rolcanlogin) FROM pg_roles WHERE rolname='cratectl_app';
            SELECT max(version) FROM cratectl_private.schema_migrations
            """, environment=pg_env)[1].splitlines()
        check('schema 18 with all 57 tenant tables forced RLS and a restricted runtime role', audit == ['57/57/0', 't', '18'])
        report['status'] = 'passed'
    finally:
        stop_server(server)
        server_log.close()
        if started or (data / 'postmaster.pid').exists():
            call('stop-owned-postgres', postgres / 'pg_ctl', '-D', data, 'stop', '-m', 'fast', '-w')
        (work / 'safe-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(checks)} native declarative repository checks')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary-directory', type=Path)
    parser.add_argument('--pg-bin', type=Path, default=ROOT / '.cache/postgresql-16.15-install/bin')
    evaluate(parser.parse_args())
