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
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from bounded_client import run_owned_client
from cargo_hosted_fixture import evaluate_cargo
from ci.cargo_evidence import PINS as CARGO_PINS, SOURCE_PATHS as CARGO_SOURCE_PATHS, validate as validate_cargo
from ci.terraform_provider_evidence import ARCHIVE_PINS, SOURCE_PATHS, postgres_version, validate
from qualification_contract import candidate_binary_directory
from terraform_repository_fixture import evaluate_tools


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
    runtime_config = app / 'runtime.json'
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

    def call(label, *command, cwd=ROOT, environment=public_env, status=0, timeout=35, input_text=None):
        with (work / (label + '.log')).open('wb') as log:
            code, output = run_owned_client(command, cwd, environment, timeout=timeout,
                                            output_limit=2 << 20, capture_limit=256 << 10, output_sink=log,
                                            input_text=input_text)
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

    def api(label, endpoint, method='GET', payload=None, *, status=0):
        flags = ['--path', endpoint, '--method', method]
        if payload is not None:
            flags += ['--body-file', write(label + '.json', payload), '--idempotency-key', 'cratectl-manifest-' + label]
        _, output = cli(label, *flags, status=status)
        return json.loads(output) if status == 0 else output

    def start_server():
        process = subprocess.Popen([daemon, 'serve', '--config', runtime_config], env=public_env,
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

    def restart_server():
        nonlocal server
        stop_server(server)
        server = None
        server = start_server()

    report = {'schema': 1, 'profile': 'cratectl-repository-manifest-native-v1', 'status': 'failed',
              'checks': checks, 'platform': platform.platform(), 'goal_complete': False, 'broad_readiness': False,
              'private_fixture': str(work.relative_to(ROOT)),
              'limits': ['Hosted npm and the version 1 manifest fields on one native server.',
                         'Broader source configuration and production provider distribution remain open.']}
    started = False
    server_log = (work / 'registry.log').open('ab')
    try:
        candidate = call('candidate', 'git', 'rev-parse', 'HEAD')[1].strip()
        check('clean exact source', not call('source-clean', 'git', 'status', '--porcelain')[1].strip())
        report['candidate'] = candidate
        go = ROOT / '.cache/go/bin/go'
        if not go.is_file():
            go = shutil.which('go')
        if not go:
            raise ValueError('the exact candidate Go toolchain is required')
        report['binary_sha256'] = {}
        for program in (client, daemon):
            build = call(program.name + '-build-info', go, 'version', '-m', program)[1]
            check(program.name + ' matches the clean candidate', f'vcs.revision={candidate}' in build and 'vcs.modified=false' in build)
            report['binary_sha256'][program.name] = sha(program)
        report['postgres'] = call('postgres-version', postgres / 'postgres', '--version')[1].strip()
        check('real reviewed PostgreSQL 16 patch release', postgres_version(report['postgres']))
        print('Reviewed native PostgreSQL version', report['postgres'].split()[2], flush=True)
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
        actors = [('reader', TENANT, 'reader'), ('other', OTHER, 'admin')]
        if args.cargo_toolchain:
            actors.append(('writer', TENANT, 'writer'))
        for label, tenant, role in actors:
            token = work / (label + '.token')
            call('provision-' + label, daemon, 'provision', '--tenant', tenant, '--actor', 'cratectl-' + label,
                 '--role', role, '--token-file', token, environment=owner_env)
            write(label + '.json', {'version': 1, 'url': BASE, 'token_file': str(token), 'ca_file': str(app / 'ca.crt')})
        server = start_server()
        if args.promtool:
            promtool = args.promtool.resolve()
            prometheus = call('stock-promtool-version', promtool, '--version')[1].splitlines()[0]
            check('stock Prometheus 3.16.0 metric parser', prometheus.startswith('promtool, version 3.16.0'))
            trust = ssl.create_default_context(cafile=str(app / 'ca.crt'))
            scrape_http = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))
            metrics_token = secrets.token_hex(32)

            def scrape(credential=None):
                headers = {} if credential is None else {'Authorization': 'Bearer ' + credential}
                request = urllib.request.Request(BASE + '/metrics', headers=headers)
                try:
                    with scrape_http.open(request, timeout=5) as response:
                        data = response.read((64 << 10) + 1)
                        if len(data) > 64 << 10:
                            raise ValueError('metrics escaped the fixed process output budget')
                        return response.status, response.headers['Content-Type'], data.decode('ascii')
                except urllib.error.HTTPError as error:
                    error.close()
                    return error.code, '', ''

            check('metrics are absent until explicitly enabled', scrape(metrics_token)[0] in (401, 404))
            stop_server(server)
            server = None
            token_input = work / 'metrics.token'
            token_input.write_text(metrics_token + '\n')
            runtime_config = write('metrics-runtime.json', {**json.loads(runtime_config.read_text()),
                                                            'metrics_token_file': str(token_input)})
            server = start_server()
            status, content_type, text = scrape(metrics_token)
            check('dedicated credential reads metrics over trusted TLS', status == 200 and
                  content_type == 'text/plain; version=0.0.4; charset=utf-8' and text.endswith('\n'))
            admin_token = (app / 'admin.token').read_text().strip()
            check('anonymous and ordinary tenant credentials cannot scrape', scrape()[0] == scrape(admin_token)[0] == 401)
            seen_metrics = []

            def metrics_values(label):
                status, _, scrape_text = scrape(metrics_token)
                if status != 200:
                    raise ValueError('authorized metrics scrape did not complete')
                call(label + '-check-metrics', promtool, 'check', 'metrics', input_text=scrape_text)
                (work / (label + '.prom')).write_text(scrape_text)
                seen_metrics.append({'phase': label, 'sha256': hashlib.sha256(scrape_text.encode()).hexdigest(),
                                     'bytes': len(scrape_text.encode())})
                return {line.rsplit(' ', 1)[0]: line.rsplit(' ', 1)[1] for line in scrape_text.splitlines() if not line.startswith('#')}
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
        phases = []

        def mcp_phase(phase, config):
            raw = call('mcp-' + phase, mcp_client, '--phase', phase, '--server', mcp_server, '--config', config,
                       '--authority', BASE, '--tenant', TENANT, '--repository', NAME,
                       '--artifact-path', artifacts[0]['path'], '--digest', artifacts[0]['digest'])[1]
            result = json.loads(raw)
            if result['phase'] != phase or result['protocol'] != '2026-07-28' or not result['checks']:
                raise ValueError('invalid official MCP phase evidence')
            phases.append(result)

        if args.mcp_binary:
            mcp_server, mcp_client = args.mcp_binary.resolve(), args.mcp_client.resolve()
            if not mcp_server.is_relative_to(ROOT) or not mcp_client.is_relative_to(ROOT):
                raise ValueError('use MCP binaries built within the cratectl workspace')
            for component in (mcp_server, mcp_client):
                build = call(component.name + '-build-info', go, 'version', '-m', component)[1]
                check(component.name + ' matches the clean candidate', f'vcs.revision={candidate}' in build and 'vcs.modified=false' in build)
            call('mcp-require-metadata-consent', mcp_server, '--client-config', app / 'client.json',
                 '--authority', BASE, '--tenant', TENANT, status=1)
            check('MCP binary requires explicit scoped metadata consent', True)
            api('mcp-create-second-repository', '/api/v1/repositories', 'POST',
                {'name': 'cratectl-secondary', 'format': 'npm', 'require_review': False})
            mcp_phase('admin-pending', app / 'client.json')
            mcp_phase('reader-ungranted', work / 'reader.json')
            api('mcp-grant-reader', REPOSITORY + '/grants', 'PUT', {'actor': 'cratectl-reader', 'read': True, 'write': False})
            mcp_phase('reader-pending', work / 'reader.json')
            mcp_phase('other-tenant', work / 'other.json')
        api('approve', REPOSITORY + '/decisions', 'PUT',
            {'path': artifacts[0]['path'], 'digest': artifacts[0]['digest'], 'decision': 'allowed'})
        if args.promtool:
            denied = cli('metrics-real-grant-denial', '--path', REPOSITORY, config=work / 'reader.json', status=1)
            check('actual restricted repository produced HTTP 403 before restart', 'HTTP 403' in denied[1])
            metrics = metrics_values('stock-publication')
            check('Prometheus parses real publication, denial and admission observations',
                  int(metrics['cratectl_http_request_body_bytes_total{protocol="npm"}']) >= tarball.stat().st_size
                  and int(metrics['cratectl_http_requests_total{protocol="management",outcome="auth_denied"}']) >= 1
                  and metrics['cratectl_transfer_capacity'] == '16')
        restart_server()
        check('registry restart preserves the declared state',
              json.loads(cli('restart-plan', *plan_flags)[1])['action'] == 'unchanged')
        restored = json.loads(call('stock-verified-download', 'npm', 'pack', target, '--ignore-scripts', '--json',
                                   cwd=download, environment=dict(consumer, NPM_CONFIG_CACHE=str(work / 'approved-cache')))[1])
        check('fresh stock npm downloads the exact approved archive after restart',
              sha(download / restored[0]['filename']) == sha(tarball))
        report['archive_sha256'] = sha(tarball)
        if args.cargo_toolchain:
            report['cargo'] = evaluate_cargo(work, app, BASE, args.cargo_toolchain.resolve(),
                                            public_env, call, api, restart_server, sha)
        if args.promtool:
            metrics = metrics_values('stock-download-after-restart')
            check('stock npm download contributes bytes and a complete latency histogram',
                  int(metrics['cratectl_http_response_body_bytes_total{protocol="npm"}']) >= tarball.stat().st_size
                  and metrics['cratectl_http_request_duration_seconds_bucket{protocol="npm",le="+Inf"}'] ==
                      metrics['cratectl_http_request_duration_seconds_count{protocol="npm"}']
                  and int(metrics['cratectl_http_request_duration_seconds_count{protocol="npm"}']) > 0)
            combined = ''.join((work / (entry['phase'] + '.prom')).read_text() for entry in seen_metrics)
            check('metrics contain fixed labels and omit tenant, artifact and credential values',
                  not any(value in combined for value in (TENANT, NAME, artifact_name, metrics_token, admin_token, artifacts[0]['digest'])))
            report['metrics'] = {'tool': prometheus, 'tool_sha256': sha(promtool), 'scrapes': seen_metrics}
        if args.mcp_binary:
            mcp_phase('reader-approved', work / 'reader.json')
            call('revoke-mcp-reader', daemon, 'revoke', '--token-file', work / 'reader.token', environment=owner_env)
            mcp_phase('revoked', work / 'reader.json')
            report['mcp'] = {'server_sha256': sha(mcp_server), 'client_sha256': sha(mcp_client), 'phases': phases}
        api('suspend', REPOSITORY + '/state', 'PUT',
            {'action': 'suspend', 'expected_revision': 0, 'reason': 'Retain the owned manifest fixture'})
        cli('stale-approved-create', *apply_flags, approval, status=1)
        retained = json.loads(cli('suspension-drift', *plan_flags)[1])
        check('stale approval leaves suspended repository retained',
              retained['action'] == 'drift' and retained['drift'] == ['state'] and retained['current']['state_revision'] == 1)
        cli('suspended-import-refused', 'repository-import', '--tenant', TENANT, '--name', NAME, status=1)
        check('suspended repository cannot be imported as active', True)
        if args.provider_binary:
            provider_bin = args.provider_binary.resolve()
            if not provider_bin.is_relative_to(ROOT):
                raise ValueError('use a provider built within the cratectl workspace')
            build = call('provider-build-info', go, 'version', '-m', provider_bin)[1]
            check('provider matches the clean candidate', f'vcs.revision={candidate}' in build and 'vcs.modified=false' in build)
            clients = [('terraform', args.terraform.resolve()), ('tofu', args.tofu.resolve())]
            report['provider'] = evaluate_tools(work, clients, provider_bin, public_env, app / 'client.json', api, sha)
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
    if args.provider_binary:
        totals = {row['client']: len(row['checks']) for row in report['provider']['clients']}
        print(f"PASS: Terraform {totals['terraform']} and OpenTofu {totals['tofu']} scoped provider checks")
    if args.mcp_binary:
        print(f"PASS: {sum(len(phase['checks']) for phase in report['mcp']['phases'])} scoped official MCP checks")
    if args.cargo_toolchain:
        print(f"PASS: {len(report['cargo']['checks'])} scoped stock Cargo checks")
    if args.ci_architecture:
        record_ci(report, args.ci_architecture)
    if args.cargo_ci_architecture:
        record_cargo_ci(report, args.cargo_ci_architecture)


def hosted_runner(report, architecture):
    runner, host = {'amd64': ('X64', 'x86_64'), 'arm64': ('ARM64', 'aarch64')}[architecture]
    if (platform.system() != 'Linux' or platform.machine() != host or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('GITHUB_REPOSITORY') != 'ctlplne/cratectl' or os.environ.get('GITHUB_REF') != 'refs/heads/main'
            or os.environ.get('RUNNER_ARCH') != runner or os.environ.get('GITHUB_RUN_ATTEMPT') != '1'
            or os.environ.get('GITHUB_SHA') != report['candidate']):
        raise ValueError('exact first native hosted source required')
    return runner


def record_ci(report, architecture):
    runner = hosted_runner(report, architecture)
    projection = {key: report[key] for key in ('candidate', 'status', 'checks', 'binary_sha256',
                                                'archive_sha256', 'postgres', 'npm', 'goal_complete', 'broad_readiness')}
    projection.update(schema=1, profile='cratectl-native-terraform-provider-v1', runner_os='Linux', runner_arch=runner,
                      run_id=os.environ.get('GITHUB_RUN_ID'), source_dirty=False, client_archives=ARCHIVE_PINS[architecture],
                      clients=report['provider']['clients'], provider_sha256=report['provider']['provider_sha256'],
                      source_sha256={name: sha(ROOT / name) for name in SOURCE_PATHS})
    validate(projection)
    with (ROOT / '.cache/ci-terraform-provider.json').open('x') as stream:
        json.dump(projection, stream, indent=2)
        stream.write('\n')


def record_cargo_ci(report, architecture):
    runner = hosted_runner(report, architecture)
    projection = {key: report[key] for key in ('candidate', 'status', 'binary_sha256', 'postgres',
                                                'goal_complete', 'broad_readiness')}
    projection.update(report['cargo'], schema=1, profile='cratectl-native-cargo-v1', runner_os='Linux',
                      runner_arch=runner, run_id=os.environ.get('GITHUB_RUN_ID'), source_dirty=False,
                      source_sha256={name: sha(ROOT / name) for name in CARGO_SOURCE_PATHS},
                      sdk_archives_sha256=CARGO_PINS[architecture], base_checks=report['checks'])
    validate_cargo(projection)
    with (ROOT / '.cache/ci-cargo.json').open('x') as stream:
        json.dump(projection, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary-directory', type=Path)
    parser.add_argument('--pg-bin', type=Path, default=ROOT / '.cache/postgresql-16.15-install/bin')
    parser.add_argument('--provider-binary', type=Path)
    parser.add_argument('--terraform', type=Path)
    parser.add_argument('--tofu', type=Path)
    parser.add_argument('--ci-architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--mcp-binary', type=Path)
    parser.add_argument('--mcp-client', type=Path)
    parser.add_argument('--promtool', type=Path)
    parser.add_argument('--cargo-toolchain', type=Path)
    parser.add_argument('--cargo-ci-architecture', choices=('amd64', 'arm64'))
    options = parser.parse_args()
    if len([value for value in (options.provider_binary, options.terraform, options.tofu) if value]) not in (0, 3):
        parser.error('provide the local provider and both stock clients together')
    if options.ci_architecture and not options.provider_binary:
        parser.error('the hosted evidence profile requires both stock clients and the provider')
    if bool(options.mcp_binary) != bool(options.mcp_client) or options.ci_architecture and options.mcp_binary:
        parser.error('the local MCP profile requires both candidate MCP binaries')
    if options.ci_architecture and options.promtool:
        parser.error('the native Prometheus profile runs separately from hosted provider qualification')
    if options.ci_architecture and options.cargo_toolchain:
        parser.error('the native Cargo profile runs separately from hosted provider qualification')
    if options.cargo_ci_architecture and (not options.cargo_toolchain or options.promtool or options.mcp_binary or options.provider_binary):
        parser.error('hosted Cargo evidence requires the stock toolchain in the isolated Cargo profile')
    evaluate(options)
