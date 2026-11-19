# SPDX-License-Identifier: BUSL-1.1
"""Qualify the pinned SDK against an isolated blank cratectl PostgreSQL server."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

from bounded_client import run_owned_client
from qualification_contract import CURRENT_TENANT_TABLES, candidate_binary_directory
from nuget_proxy_evidence import (CHECKS, COMBINED_CHECKS, COMBINED_PROFILE, COMBINED_SOURCE_PATHS,
                                 FIXTURES, GROUP_FIXTURES, PROFILE, SERVICE_INDEX_FIXTURE, SOURCE_PATHS,
                                 postgres_version, validate)


def digest(file):
    with file.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def qualify(pg, binary, architecture, combined):
    os.umask(0o077)
    private = ROOT / '.private'
    if private.is_symlink() or private.stat().st_mode & 0o077:
        raise ValueError('use an existing owner-only .private directory')
    for port in (35432, 38443):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', port))
    work = Path(tempfile.mkdtemp(prefix='cratectl-nuget-proxy-db-', dir=private))
    print('Private PostgreSQL fixture', work.relative_to(ROOT), flush=True)
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(('CRATECTL_', 'PG'))
           and key.upper() not in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')}

    def run(label, *argv, environment=env, data=None, timeout=30):
        with (work / (label + '.log')).open('xb') as log:
            code, result = run_owned_client(argv, ROOT, environment, timeout=timeout, capture_limit=64 << 10,
                                            output_sink=log, input_text=data)
        if code != 0:
            raise ValueError(f'owned fixture step {label} returned {code}')
        return result.strip()

    sha = run('candidate', 'git', 'rev-parse', 'HEAD')
    if run('clean-source', 'git', 'status', '--porcelain'):
        raise ValueError('the exact clean source is required')
    postgres = run('postgres', pg / 'postgres', '--version')
    if not postgres_version(postgres):
        raise ValueError('the installed PostgreSQL version is outside the reviewed PostgreSQL 16 scope')
    owner, runtime = secrets.token_hex(24), secrets.token_hex(24)
    data = work / 'postgres'
    secret = work / 'init-password'
    secret.write_text(owner + '\n')
    try:
        run('initialize', pg / 'initdb', '-D', data, '--username=cratectl_owner', '--pwfile=' + str(secret),
            '--auth=scram-sha-256', '--locale=C', '--encoding=UTF8')
    finally:
        secret.unlink(missing_ok=True)
    owner_env = dict(env, PGPASSWORD=owner)
    runtime_env = dict(env, PGPASSWORD=runtime)
    psql = (pg / 'psql', '-qXAtw', '-h', '127.0.0.1', '-p', '35432', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1')
    suffix = '@127.0.0.1:35432/postgres?sslmode=disable'
    database = {'owner': 'postgres://cratectl_owner:' + owner + suffix,
                'runtime': 'postgres://cratectl_app:' + runtime + suffix}
    config = work / 'connections.json'
    config.write_text(json.dumps(database))
    try:
        run('start', pg / 'pg_ctl', '-D', data, '-l', work / 'postgres.log', '-o',
            "-h 127.0.0.1 -p 35432 -c unix_socket_directories='' -c max_connections=24", 'start', '-w')
        run('runtime-role', *psql, '-U', 'cratectl_owner', environment=owner_env,
            data=f"CREATE ROLE cratectl_app LOGIN NOSUPERUSER NOINHERIT NOBYPASSRLS PASSWORD '{runtime}';\n")
        run('migrate', binary / 'cratectld', 'migrate', environment=dict(env, CRATECTL_OWNER_DSN=database['owner'],
                                                                     CRATECTL_DSN=database['runtime']))
        audit = run('runtime-audit', *psql, '-U', 'cratectl_app', environment=runtime_env, data='''
SELECT current_setting('server_version_num')::int/10000=16;
SELECT (NOT rolsuper AND NOT rolbypassrls AND rolcanlogin) FROM pg_roles WHERE rolname=current_user;
SELECT count(*),count(*) FILTER (WHERE c.relrowsecurity AND c.relforcerowsecurity AND c.relowner<>r.oid)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.rolname=current_user
WHERE n.nspname='cratectl' AND c.relkind IN ('r','p') AND EXISTS
 (SELECT FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant' AND NOT a.attisdropped);
''')
        if audit.splitlines() != ['t', 't', f'{CURRENT_TENANT_TABLES}|{CURRENT_TENANT_TABLES}']:
            raise ValueError('actual PostgreSQL runtime does not have the reviewed tenant isolation')
        profile = 'nugetsource' if combined else 'nugetproxy'
        output = run('stock-dotnet', sys.executable, ROOT / 'scripts/conformance.py', profile, '--require-clean-build',
                     environment=dict(env, CRATECTL_CONFORMANCE_DATABASE_FILE=str(config),
                                      CRATECTL_DEV_DATABASE='native', CRATECTL_QUALIFICATION_BIN_DIR=str(binary)), timeout=350)
    finally:
        if (data / 'postmaster.pid').exists():
            run('stop', pg / 'pg_ctl', '-D', data, 'stop', '-w', '-m', 'fast')
    paths = re.findall(r'^Evidence: (.+)$', output, re.M)
    if len(paths) != 1:
        raise ValueError('the stock replay did not yield one private report')
    report_path = Path(paths[0])
    relative = report_path.resolve().relative_to(private / 'conformance')
    if not re.fullmatch(r'([a-f0-9]{10})/conformance-\1\.json', relative.as_posix()) or report_path.stat().st_size > 1 << 20:
        raise ValueError('unreviewed native replay report path or size')
    native = json.loads(report_path.read_bytes())
    checks = COMBINED_CHECKS if combined else CHECKS
    binary_hashes = {path.name: digest(path) for path in (binary / 'cratectl', binary / 'cratectld')}
    if (native['candidate'] != sha or native['source_dirty'] is not False or native['build_source_matches_candidate'] is not True
            or native['status'] != 'passed' or native['checks'] != list(checks) or native['nuget_proxy']['fixtures'] != FIXTURES
            or native['artifact_digests'] != {str(binary.relative_to(ROOT) / name): value for name, value in binary_hashes.items()}):
        raise ValueError('the owned stock run failed exact source, binary or fixture binding')
    if combined and (native.get('nuget_group') != GROUP_FIXTURES or native.get('nuget_service_index') != SERVICE_INDEX_FIXTURE):
        raise ValueError('the owned stock run failed the group or service-index fixture binding')
    if architecture:
        machine, runner_arch = {'amd64': ('x86_64', 'X64'), 'arm64': ('aarch64', 'ARM64')}[architecture]
        if (platform.system(), platform.machine(), env.get('RUNNER_OS'), env.get('RUNNER_ARCH'), env.get('GITHUB_SHA'),
                env.get('GITHUB_RUN_ATTEMPT')) != ('Linux', machine, 'Linux', runner_arch, sha, '1'):
            raise ValueError('the hosted report requires an original exact native Linux job')
        sources = COMBINED_SOURCE_PATHS if combined else SOURCE_PATHS
        report = {'schema': 1, 'profile': COMBINED_PROFILE if combined else PROFILE, 'candidate': sha, 'status': 'passed', 'runner_os': 'Linux',
                  'runner_arch': runner_arch, 'run_id': env['GITHUB_RUN_ID'], 'source_dirty': False,
                  'source_sha256': {path: digest(ROOT / path) for path in sources}, 'binary_sha256': binary_hashes,
                  'postgres': postgres, 'database_safety': True, 'checks': native['checks'], 'nuget_proxy': native['nuget_proxy'],
                  'goal_complete': False, 'broad_readiness': False}
        if combined:
            report.update(nuget_group=native['nuget_group'], nuget_service_index=native['nuget_service_index'])
        with (ROOT / '.cache/ci-nuget-proxy.json').open('x') as stream:
            json.dump(validate(report), stream, indent=2)
            stream.write('\n')
    scope = 'flat-container, ordered group and service-index' if combined else 'flat-container proxy'
    print(f'PASS: {len(checks)} stock NuGet {scope} checks')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pg-bin', required=True, type=Path)
    parser.add_argument('--binary-directory', required=True, type=Path)
    parser.add_argument('--architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--with-groups-and-service-index', action='store_true')
    args = parser.parse_args()
    qualify(args.pg_bin.resolve(), candidate_binary_directory(args.binary_directory), args.architecture,
            args.with_groups_and_service_index)
