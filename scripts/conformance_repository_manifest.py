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
from cargo_group_fixture import evaluate_groups
from cargo_hosted_fixture import evaluate_cargo
from cargo_ownership_upgrade_fixture import BASELINE as CARGO_UPGRADE_BASELINE, replay_legacy_cargo
from cargo_proxy_fixture import evaluate_proxy, INDEX_ORIGIN, DOWNLOAD_ORIGIN
from ci.cargo_evidence import PINS as CARGO_PINS, SOURCE_PATHS as CARGO_SOURCE_PATHS, validate as validate_cargo
from ci.terraform_provider_evidence import ARCHIVE_PINS, SOURCE_PATHS, postgres_version, validate
from qualification_contract import CURRENT_SCHEMA, CURRENT_TENANT_TABLES, candidate_binary_directory
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
    authority = ('https://127.0.0.1:38443' if args.cargo_toolchain or args.npm_search or args.python_search_client
                 or args.oci_catalog_cached or args.maven_index_cached or args.debian_apt or args.composer_phar
                 or args.conda_micromamba or args.cran_r else BASE)
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
    server_flags = []
    origin_credentials = {}
    composer_credentials = {}
    if args.oci_catalog_client:
        server_flags.extend(('--oci-page-size', '1'))

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

    def api(label, endpoint, method='GET', payload=None, *, status=0, config=None):
        flags = ['--path', endpoint, '--method', method]
        if payload is not None:
            flags += ['--body-file', write(label + '.json', payload), '--idempotency-key', 'cratectl-manifest-' + label]
        _, output = cli(label, *flags, config=config, status=status)
        return json.loads(output) if status == 0 else output

    def start_server(executable=None):
        binary = executable or daemon
        flags = server_flags if binary == daemon else []
        process = subprocess.Popen([binary, 'serve', '--config', runtime_config, *flags], env=public_env,
                                   stdout=server_log, stderr=subprocess.STDOUT)
        trust = ssl.create_default_context(cafile=str(app / 'ca.crt'))
        local_http = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))
        try:
            for _ in range(120):
                if process.poll() is not None:
                    raise ValueError('owned registry stopped before readiness')
                try:
                    with local_http.open(authority + '/health/ready', timeout=1) as reply:
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
        bootstrap = daemon
        if args.legacy_cargo_daemon:
            bootstrap = args.legacy_cargo_daemon.resolve()
            build = call('legacy-cargo-baseline-build', go, 'version', '-m', bootstrap)[1]
            if (f'vcs.revision={CARGO_UPGRADE_BASELINE}' not in build or 'vcs.modified=false' not in build
                    or '\tpath\tctlplne.dev/cratectl/cmd/cratectld\n' not in build):
                raise ValueError('legacy Cargo upgrade requires the exact reviewed schema 18 daemon')
        call('initialize-registry', bootstrap, 'init', '--tenant', TENANT, '--directory', app,
             '--public-url', authority, environment=owner_env)
        actors = [('reader', TENANT, 'reader'), ('other', OTHER, 'admin')]
        if any((args.cargo_toolchain, args.npm_search, args.python_search_client, args.oci_catalog_cached,
                args.maven_index_cached, args.composer_proxy, args.cran_proxy)):
            server_flags.extend(('--allow-private-upstreams', '::1/128'))
        if args.cargo_toolchain:
            actors.extend([('writer', TENANT, 'writer'), ('maintainer', TENANT, 'writer')])
        for label, tenant, role in actors:
            token = work / (label + '.token')
            call('provision-' + label, bootstrap, 'provision', '--tenant', tenant, '--actor', 'cratectl-' + label,
                 '--role', role, '--token-file', token, environment=owner_env)
            write(label + '.json', {'version': 1, 'url': authority, 'token_file': str(token), 'ca_file': str(app / 'ca.crt')})
        if args.cargo_toolchain:
            origin_credentials = {label: secrets.token_urlsafe(32) for label in ('index', 'download')}
            credentials = write('cargo-origin-credentials.json', {
                TENANT + '/cratectl-cargo-' + label: {'value': origin_credentials[label], 'allowed_url': url,
                                                      'authentication': 'cargo-token'}
                for label, url in (('index', INDEX_ORIGIN), ('download', DOWNLOAD_ORIGIN))})
            server_flags.extend(('--upstream-credentials', str(credentials)))
        if args.composer_proxy:
            from composer_proxy_fixture import ARCHIVE_ORIGIN, CATALOG_ORIGIN

            composer_credentials = {label: secrets.token_urlsafe(32) for label in ('index', 'download')}
            credentials = write('composer-origin-credentials.json', {
                TENANT + '/cratectl-composer-' + label: {'value': composer_credentials[label], 'allowed_url': uri,
                                                          'authentication': 'bearer'}
                for label, uri in (('index', CATALOG_ORIGIN), ('download', ARCHIVE_ORIGIN))})
            server_flags.extend(('--upstream-credentials', str(credentials)))
        cran_proxy_credential = None
        if args.cran_proxy:
            from cran_proxy_fixture import ORIGIN, ORIGIN_CREDENTIAL

            cran_proxy_credential = secrets.token_urlsafe(32)
            credentials = write('cran-origin-credentials.json', {TENANT + '/' + ORIGIN_CREDENTIAL: {
                'value': cran_proxy_credential, 'allowed_url': ORIGIN, 'authentication': 'bearer'}})
            server_flags.extend(('--upstream-credentials', str(credentials)))
        server = start_server(bootstrap)
        if args.legacy_cargo_daemon:
            def controlled_upgrade():
                nonlocal server
                def migration_plan(binary, label):
                    return json.loads(call(label, binary, 'migrate', '--plan', environment=owner_env)[1])

                before = migration_plan(bootstrap, 'legacy-cargo-before-migration-plan')
                if before['binary_version'] != 18 or len(before['applied']) != 18 or not before['safety_valid'] or before['pending']:
                    raise ValueError('legacy Cargo baseline receipts differ')
                stop_server(server)
                server = None
                pending = migration_plan(daemon, 'legacy-cargo-pending-migration-plan')
                if pending['binary_version'] != CURRENT_SCHEMA or pending['pending'] != [19] or pending['applied'] != before['applied']:
                    raise ValueError('Cargo ownership migration changes the older receipt inventory')
                call('apply-cargo-ownership-migration', daemon, 'migrate', environment=owner_env)
                after = migration_plan(daemon, 'legacy-cargo-after-migration-plan')
                if (after['applied'][:-1] != before['applied'] or len(after['applied']) != CURRENT_SCHEMA
                        or after['pending'] or not after['safety_valid']):
                    raise ValueError('Cargo ownership migration did not preserve the older receipts')
                _, refusal = call('legacy-cargo-old-daemon-refused', bootstrap, 'serve', '--config', runtime_config,
                                  environment=public_env, status=1, timeout=10)
                if 'schema' not in refusal.lower():
                    raise ValueError('legacy Cargo runtime did not explicitly refuse the migrated schema')
                server = start_server()
                return {'baseline_binary_sha256': sha(bootstrap), 'preserved_receipts': len(before['applied']),
                        'applied': after['applied'][-1], 'old_daemon_refused_current_schema': True}

            report['cargo_upgrade'] = replay_legacy_cargo(work, app, authority, args.cargo_toolchain.resolve(),
                                                        public_env, call, api, controlled_upgrade, sha)
        if args.promtool:
            promtool = args.promtool.resolve()
            prometheus = call('stock-promtool-version', promtool, '--version')[1].splitlines()[0]
            check('stock Prometheus 3.16.0 metric parser', prometheus.startswith('promtool, version 3.16.0'))
            trust = ssl.create_default_context(cafile=str(app / 'ca.crt'))
            scrape_http = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))
            metrics_token = secrets.token_hex(32)

            def scrape(credential=None):
                headers = {} if credential is None else {'Authorization': 'Bearer ' + credential}
                request = urllib.request.Request(authority + '/metrics', headers=headers)
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
              plan['action'] == 'create' and plan['current'] is None and plan['authority'] == authority and plan['desired'] == desired)
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
        events = [json.loads(event['payload']) for event in api('create-audit', '/api/v1/audit?limit=100')['items']]
        check('one repository creation event despite concurrent retry',
              sum(event['kind'] == 'repository.created' and event['data']['name'] == NAME for event in events) == 1)
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
                       '--authority', authority, '--tenant', TENANT, '--repository', NAME,
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
                 '--authority', authority, '--tenant', TENANT, status=1)
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
        if args.oci_catalog_client:
            from oci_repository_catalog_fixture import evaluate_oci_catalog

            report['oci_repository_catalog'] = evaluate_oci_catalog(
                work, app, authority, args.oci_catalog_client.absolute(), public_env, call, api, restart_server, sha,
                cached=args.oci_catalog_cached)
        if args.maven_index_reader:
            from maven_index_fixture import hosted_maven_index

            report['maven_index'] = hosted_maven_index(work, app, authority, args.maven_index_java.absolute(),
                                                      args.maven_index_reader.absolute(), public_env, call, api, restart_server, sha,
                                                      cached=args.maven_index_cached)
        if args.debian_apt:
            from debian_apt_fixture import evaluate_debian_apt

            report['debian_apt'] = evaluate_debian_apt(work, app, authority, public_env, call, api, restart_server, sha)
            if args.debian_apt_suite:
                report['debian_apt_suite'] = evaluate_debian_apt(work, app, authority, public_env, call, api, restart_server, sha, named=True)
        if args.composer_phar:
            from composer_hosted_fixture import evaluate_hosted_composer

            report['composer_hosted'] = evaluate_hosted_composer(work, app, authority, public_env, call, api, restart_server,
                                                                sha, args.composer_php.resolve(), args.composer_phar.resolve(),
                                                                versions=args.composer_versions)
            if args.composer_group:
                report['composer_group'] = evaluate_hosted_composer(work, app, authority, public_env, call, api, restart_server,
                                                                   sha, args.composer_php.resolve(), args.composer_phar.resolve(), grouped=True)
            if args.composer_proxy:
                from composer_proxy_fixture import evaluate_composer_proxy

                report['composer_proxy'] = evaluate_composer_proxy(work, app, authority, public_env, call, api, restart_server, sha,
                                                                  args.composer_php.resolve(), args.composer_phar.resolve(), composer_credentials)
            if args.composer_search:
                from composer_search_fixture import evaluate_composer_search

                report['composer_search'] = evaluate_composer_search(work, app, authority, public_env, call, api, restart_server,
                                                                    args.composer_php.resolve(), args.composer_phar.resolve(),
                                                                    lifecycle=args.composer_lifecycle)
        if args.conda_micromamba:
            from conda_hosted_fixture import evaluate_conda

            report['conda_hosted'] = evaluate_conda(work, app, authority, call, api, restart_server, sha,
                                                    args.conda_micromamba.resolve(), grouped=args.conda_group)
        if args.cran_r:
            from cran_hosted_fixture import evaluate_cran

            report['cran_hosted'] = evaluate_cran(work, app, authority, call, api, restart_server, sha,
                                                  args.cran_r.resolve(), args.cran_r_home.resolve(), args.cran_tool_archive.resolve(),
                                                  install=args.cran_install, history=args.cran_history, grouped=args.cran_group,
                                                  binary=args.cran_binary, proxy_credential=cran_proxy_credential)
        if args.npm_search:
            from npm_search_fixture import evaluate_cached_search, evaluate_search

            report['npm_search'] = evaluate_search(work, public_env, call, cli, api, restart_server, sha)
            report['npm_cached_search'] = evaluate_cached_search(work, public_env, call, cli, api, restart_server, sha)
        if args.python_search_client:
            from python_search_fixture import evaluate_cached_python_search, evaluate_python_search

            report['python_search'] = evaluate_python_search(
                work, app, authority, args.python_search_client.absolute(), public_env, call, api, restart_server, sha)
            report['python_cached_search'] = evaluate_cached_python_search(
                work, app, authority, args.python_search_client.absolute(), public_env, call, api, restart_server, sha)
        if args.cargo_toolchain:
            report['cargo'] = evaluate_cargo(work, app, authority, args.cargo_toolchain.resolve(),
                                            public_env, call, api, restart_server, sha)
            group = evaluate_groups(work, app, authority, args.cargo_toolchain.resolve(),
                                    public_env, call, api, restart_server, sha)
            report['cargo']['checks'].extend(group['checks'])
            report['cargo']['archive_sha256'].update(group['archive_sha256'])
            proxy = evaluate_proxy(work, app, authority, args.cargo_toolchain.resolve(), public_env,
                                   call, api, restart_server, sha, origin_credentials)
            report['cargo']['checks'].extend(proxy['checks'])
            report['cargo']['archive_sha256'].update(proxy['archive_sha256'])
            if args.cargo_public_origin:
                from cargo_public_fixture import evaluate_public_origin

                report['cargo_public_origin'] = evaluate_public_origin(
                    work, app, authority, args.cargo_toolchain.resolve(), public_env, call, api, restart_server, sha)
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
        check(f'schema {CURRENT_SCHEMA} with all {CURRENT_TENANT_TABLES} tenant tables forced RLS and a restricted runtime role',
              audit == [f'{CURRENT_TENANT_TABLES}/{CURRENT_TENANT_TABLES}/0', 't', str(CURRENT_SCHEMA)])
        report['status'] = 'passed'
    finally:
        stop_server(server)
        server_log.close()
        if started or (data / 'postmaster.pid').exists():
            call('stop-owned-postgres', postgres / 'pg_ctl', '-D', data, 'stop', '-m', 'fast', '-w')
        (work / 'safe-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {len(checks)} native declarative repository checks')
    if args.oci_catalog_client:
        print(f"PASS: {len(report['oci_repository_catalog']['checks'])} stock ORAS repository catalog checks")
    if args.oci_catalog_cached:
        print(f"PASS: {len(report['oci_repository_catalog']['cached']['checks'])} stock ORAS cached repository catalog checks")
        print(f"PASS: {len(report['oci_repository_catalog']['cached']['groups']['checks'])} stock ORAS ordered group catalog checks")
    if args.maven_index_reader:
        print(f"PASS: {len(report['maven_index']['checks'])} stock Apache Maven Indexer checks")
    if args.maven_index_cached:
        print(f"PASS: {len(report['maven_index']['cached']['checks'])} stock Apache cached Maven index checks")
        print(f"PASS: {len(report['maven_index']['cached']['groups']['checks'])} stock Apache ordered Maven index checks")
    if args.debian_apt:
        print(f"PASS: {len(report['debian_apt']['checks'])} stock signed Debian APT checks")
    if args.debian_apt_suite:
        print(f"PASS: {len(report['debian_apt_suite']['checks'])} stock signed Debian named-suite checks")
    if args.composer_phar:
        print(f"PASS: {len(report['composer_hosted']['checks'])} stock Composer hosted ZIP checks")
    if args.composer_group:
        print(f"PASS: {len(report['composer_group']['checks'])} stock Composer ordered group checks")
    if args.composer_versions:
        print(f"PASS: {len(report['composer_hosted']['version_forms']['checks'])} stock Composer development and prerelease checks")
    if args.composer_proxy:
        print(f"PASS: {len(report['composer_proxy']['checks'])} stock Composer checksum-bound proxy checks")
    if args.composer_search:
        print(f"PASS: {len(report['composer_search']['checks'])} stock Composer hosted discovery checks")
    if args.composer_lifecycle:
        print(f"PASS: {len(report['composer_search']['lifecycle']['checks'])} stock Composer retained lifecycle checks")
    if args.conda_micromamba:
        print(f"PASS: {len(report['conda_hosted']['checks'])} stock micromamba hosted Conda checks")
    if args.conda_group:
        print(f"PASS: {len(report['conda_hosted']['group']['checks'])} stock micromamba ordered Conda group checks")
    if args.cran_r:
        print(f"PASS: {len(report['cran_hosted']['checks'])} stock R hosted CRAN source checks")
    if args.cran_install:
        print(f"PASS: {len(report['cran_hosted']['installation']['checks'])} stock R inert archive installation checks")
    if args.cran_history:
        print(f"PASS: {len(report['cran_hosted']['history']['checks'])} stock R historical source archive checks")
    if args.cran_group:
        print(f"PASS: {len(report['cran_hosted']['group']['checks'])} stock R ordered CRAN group checks")
    if args.cran_binary:
        print(f"PASS: {len(report['cran_hosted']['binary']['checks'])} stock R hosted CRAN binary checks")
    if args.cran_proxy:
        print(f"PASS: {len(report['cran_hosted']['proxy']['checks'])} stock R checksum-bound CRAN proxy checks")
    if args.npm_search:
        print(f"PASS: {len(report['npm_search']['checks'])} stock hosted npm search checks")
        print(f"PASS: {len(report['npm_cached_search']['checks'])} stock cached npm search checks")
    if args.python_search_client:
        print(f"PASS: {len(report['python_search']['checks'])} stock hosted Python search checks")
        print(f"PASS: {len(report['python_cached_search']['checks'])} stock cached Python search checks")
    if args.provider_binary:
        totals = {row['client']: len(row['checks']) for row in report['provider']['clients']}
        print(f"PASS: Terraform {totals['terraform']} and OpenTofu {totals['tofu']} scoped provider checks")
    if args.mcp_binary:
        print(f"PASS: {sum(len(phase['checks']) for phase in report['mcp']['phases'])} scoped official MCP checks")
    if args.cargo_toolchain:
        print(f"PASS: {len(report['cargo']['checks'])} scoped stock Cargo checks")
    if args.cargo_public_origin:
        print(f"PASS: {len(report['cargo_public_origin']['checks'])} stock Cargo public-origin checks")
    if args.legacy_cargo_daemon:
        print(f"PASS: {len(report['cargo_upgrade']['checks'])} stock Cargo historical adoption checks")
    if args.ci_architecture:
        record_ci(report, args.ci_architecture)
    if args.cargo_ci_architecture:
        record_cargo_ci(report, args.cargo_ci_architecture)
    if args.npm_search_ci_architecture:
        record_npm_search_ci(report, args.npm_search_ci_architecture)
    if args.python_search_ci_architecture:
        record_python_search_ci(report, args.python_search_ci_architecture)
    if args.oci_catalog_ci_architecture:
        record_oci_catalog_ci(report, args.oci_catalog_ci_architecture)
    if args.maven_index_ci_architecture:
        record_maven_index_ci(report, args.maven_index_ci_architecture)
    if args.debian_apt_ci_architecture:
        record_debian_apt_ci(report, args.debian_apt_ci_architecture)
    if args.composer_ci_architecture:
        record_composer_ci(report, args.composer_ci_architecture)
    if args.conda_ci_architecture:
        record_conda_ci(report, args.conda_ci_architecture)
    if args.cran_ci_architecture:
        record_cran_ci(report, args.cran_ci_architecture)


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
    output = '.cache/ci-cargo.json'
    if 'cargo_public_origin' in report:
        from ci.cargo_public_evidence import SOURCE_PATHS as public_sources, validate as validate_public

        output = '.cache/ci-cargo-public.json'
        projection.update(profile='cratectl-native-cargo-public-v1', public_origin=report['cargo_public_origin'],
                          public_source_sha256={name: sha(ROOT / name) for name in public_sources})
        validate_public(projection)
    else:
        validate_cargo(projection)
    with (ROOT / output).open('x') as stream:
        json.dump(projection, stream, indent=2)
        stream.write('\n')


def record_npm_search_ci(report, architecture):
    from ci.npm_search_evidence import SOURCE_PATHS as npm_sources, validate as validate_npm

    runner = hosted_runner(report, architecture)
    projection = {key: report[key] for key in ('candidate', 'status', 'checks', 'binary_sha256', 'archive_sha256',
                                                'postgres', 'npm', 'npm_search', 'npm_cached_search', 'goal_complete', 'broad_readiness')}
    projection.update(schema=1, profile='cratectl-native-npm-search-v1', runner_os='Linux', runner_arch=runner,
                      run_id=os.environ.get('GITHUB_RUN_ID'), source_dirty=False,
                      source_sha256={name: sha(ROOT / name) for name in npm_sources})
    validate_npm(projection)
    with (ROOT / '.cache/ci-npm-search.json').open('x') as stream:
        json.dump(projection, stream, indent=2)
        stream.write('\n')


def record_python_search_ci(report, architecture):
    from ci.python_search_evidence import SOURCE_PATHS as python_sources, validate as validate_python

    runner = hosted_runner(report, architecture)
    projection = {key: report[key] for key in ('candidate', 'status', 'checks', 'binary_sha256', 'archive_sha256',
                                                'postgres', 'npm', 'python_search', 'python_cached_search',
                                                'goal_complete', 'broad_readiness')}
    projection.update(schema=1, profile='cratectl-native-python-search-v1', runner_os='Linux', runner_arch=runner,
                      run_id=os.environ.get('GITHUB_RUN_ID'), source_dirty=False,
                      source_sha256={name: sha(ROOT / name) for name in python_sources})
    validate_python(projection)
    with (ROOT / '.cache/ci-python-search.json').open('x') as stream:
        json.dump(projection, stream, indent=2)
        stream.write('\n')


def record_oci_catalog_ci(report, architecture):
    from ci.oci_repository_catalog_evidence import CACHED_PROFILE, CACHED_SOURCE_PATHS, HOSTED_PROFILE, SOURCE_PATHS, validate as validate_catalog

    runner = hosted_runner(report, architecture)
    projection = {key: report[key] for key in ('candidate', 'status', 'checks', 'binary_sha256', 'archive_sha256',
                                                'postgres', 'npm', 'oci_repository_catalog', 'goal_complete', 'broad_readiness')}
    cached = 'cached' in report['oci_repository_catalog']
    projection.update(schema=1, profile=CACHED_PROFILE if cached else HOSTED_PROFILE, runner_os='Linux', runner_arch=runner,
                      run_id=os.environ.get('GITHUB_RUN_ID'), source_dirty=False,
                      oras_archive_sha256=sha(ROOT / f'.cache/oras_1.3.6_linux_{architecture}.tar.gz'),
                      source_sha256={name: sha(ROOT / name) for name in (CACHED_SOURCE_PATHS if cached else SOURCE_PATHS)})
    validate_catalog(projection)
    with (ROOT / '.cache/ci-oci-catalog.json').open('x') as stream:
        json.dump(projection, stream, indent=2)
        stream.write('\n')


def record_maven_index_ci(report, architecture):
    from ci.maven_index_evidence import CACHED_PROFILE, CACHED_SOURCE_PATHS, PROFILE, SOURCE_PATHS, validate as validate_index

    runner = hosted_runner(report, architecture)
    projection = {key: report[key] for key in ('candidate', 'status', 'checks', 'binary_sha256', 'archive_sha256',
                                                'postgres', 'npm', 'maven_index', 'goal_complete', 'broad_readiness')}
    cached = 'cached' in report['maven_index']
    projection.update(schema=1, profile=CACHED_PROFILE if cached else PROFILE, runner_os='Linux', runner_arch=runner,
                      run_id=os.environ.get('GITHUB_RUN_ID'), source_dirty=False,
                      source_sha256={name: sha(ROOT / name) for name in (CACHED_SOURCE_PATHS if cached else SOURCE_PATHS)})
    validate_index(projection)
    with (ROOT / '.cache/ci-maven-index.json').open('x') as stream:
        json.dump(projection, stream, indent=2)
        stream.write('\n')


def record_debian_apt_ci(report, architecture):
    from ci.debian_apt_evidence import PROFILE, SOURCE_PATHS, SUITE_PROFILE, SUITE_SOURCE_PATHS, validate as validate_debian

    runner = hosted_runner(report, architecture)
    projection = {key: report[key] for key in ('candidate', 'status', 'checks', 'binary_sha256', 'archive_sha256',
                                                'postgres', 'npm', 'debian_apt', 'goal_complete', 'broad_readiness')}
    profile, source_paths = PROFILE, SOURCE_PATHS
    if 'debian_apt_suite' in report:
        projection['debian_apt_suite'] = report['debian_apt_suite']
        profile, source_paths = SUITE_PROFILE, SUITE_SOURCE_PATHS
    projection.update(schema=1, profile=profile, runner_os='Linux', runner_arch=runner,
                      run_id=os.environ.get('GITHUB_RUN_ID'), source_dirty=False,
                      source_sha256={name: sha(ROOT / name) for name in source_paths})
    with (ROOT / '.cache/ci-debian-apt.json').open('x') as stream:
        json.dump(validate_debian(projection), stream, indent=2)
        stream.write('\n')


def record_composer_ci(report, architecture):
    from ci.composer_hosted_evidence import (FILES, GROUP_FILES, GROUP_PROFILE, LIFECYCLE_FILES, LIFECYCLE_PROFILE, PROFILE, PROXY_FILES, PROXY_PROFILE,
                                             SEARCH_FILES, SEARCH_PROFILE, VERSIONS_PROFILE, validate as validate_composer)

    runner = hosted_runner(report, architecture)
    projection = {key: report[key] for key in ('candidate', 'status', 'checks', 'binary_sha256', 'archive_sha256',
                                                'postgres', 'npm', 'composer_hosted', 'goal_complete', 'broad_readiness')}
    profile, paths = PROFILE, FILES
    if 'composer_group' in report:
        projection['composer_group'] = report['composer_group']
        profile = VERSIONS_PROFILE if 'version_forms' in report['composer_hosted'] else GROUP_PROFILE
        paths = GROUP_FILES
    if 'composer_proxy' in report:
        projection['composer_proxy'] = report['composer_proxy']
        profile, paths = PROXY_PROFILE, PROXY_FILES
    if 'composer_search' in report:
        projection['composer_search'] = report['composer_search']
        profile, paths = SEARCH_PROFILE, SEARCH_FILES
        if 'lifecycle' in report['composer_search']:
            profile, paths = LIFECYCLE_PROFILE, LIFECYCLE_FILES
    projection.update(schema=1, profile=profile, runner_os='Linux', runner_arch=runner,
                      run_id=os.environ.get('GITHUB_RUN_ID'), source_dirty=False,
                      source_sha256={name: sha(ROOT / name) for name in paths})
    with (ROOT / '.cache/ci-composer-hosted.json').open('x') as stream:
        json.dump(validate_composer(projection), stream, indent=2)
        stream.write('\n')


def record_conda_ci(report, architecture):
    from ci.conda_hosted_evidence import FILES, GROUP_FILES, GROUP_PROFILE, PROFILE, validate as validate_conda

    runner = hosted_runner(report, architecture)
    projection = {key: report[key] for key in ('candidate', 'status', 'checks', 'binary_sha256', 'archive_sha256',
                                                'postgres', 'npm', 'conda_hosted', 'goal_complete', 'broad_readiness')}
    grouped = 'group' in projection['conda_hosted']
    projection.update(schema=1, profile=GROUP_PROFILE if grouped else PROFILE, runner_os='Linux', runner_arch=runner,
                      run_id=os.environ.get('GITHUB_RUN_ID'), source_dirty=False,
                      source_sha256={name: sha(ROOT / name) for name in (GROUP_FILES if grouped else FILES)})
    with (ROOT / '.cache/ci-conda-hosted.json').open('x') as stream:
        json.dump(validate_conda(projection), stream, indent=2)
        stream.write('\n')


def record_cran_ci(report, architecture):
    from ci.cran_hosted_evidence import PROFILES, source_files, validate as validate_cran

    runner = hosted_runner(report, architecture)
    installed = 'installation' in report['cran_hosted']
    history = 'history' in report['cran_hosted']
    grouped = 'group' in report['cran_hosted']
    proxied = 'proxy' in report['cran_hosted']
    profile, files = PROFILES[installed, history, grouped, proxied], source_files(installed, history, grouped, proxied)
    projection = {key: report[key] for key in ('candidate', 'status', 'checks', 'binary_sha256', 'archive_sha256',
                                                'postgres', 'npm', 'cran_hosted', 'goal_complete', 'broad_readiness')}
    projection.update(schema=1, profile=profile, runner_os='Linux', runner_arch=runner,
                      run_id=os.environ.get('GITHUB_RUN_ID'), source_dirty=False,
                      source_sha256={name: sha(ROOT / name) for name in files})
    with (ROOT / '.cache/ci-cran-hosted.json').open('x') as stream:
        json.dump(validate_cran(projection), stream, indent=2)
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
    parser.add_argument('--oci-catalog-client', type=Path,
                        help='also verify the hosted OCI repository catalog using stock ORAS')
    parser.add_argument('--oci-catalog-ci-architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--oci-catalog-cached', action='store_true',
                        help='also exercise the scoped cached proxy and ordered OCI group discovery fixture')
    parser.add_argument('--maven-index-reader', type=Path, help='the pinned Apache Maven Indexer Reader JAR')
    parser.add_argument('--maven-index-java', type=Path, help='the JDK 21 executable for the stock index reader')
    parser.add_argument('--maven-index-ci-architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--maven-index-cached', action='store_true', help='also verify cached Maven proxy and ordered group indexes')
    parser.add_argument('--debian-apt', action='store_true', help='verify a signed hosted repository using stock APT')
    parser.add_argument('--debian-apt-suite', action='store_true', help='also verify a signed Debian suite using stock APT')
    parser.add_argument('--debian-apt-ci-architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--composer-php', type=Path, help='the native PHP executable for the stock Composer PHAR')
    parser.add_argument('--composer-phar', type=Path, help='the digest-pinned Composer client PHAR')
    parser.add_argument('--composer-group', action='store_true', help='also verify a Composer group over ordered hosted members')
    parser.add_argument('--composer-versions', action='store_true', help='also verify Composer development and prerelease ZIPs')
    parser.add_argument('--composer-proxy', action='store_true', help='also verify a checksum-bound Composer v2 upstream')
    parser.add_argument('--composer-search', action='store_true', help='also verify stock hosted Composer search and package names')
    parser.add_argument('--composer-lifecycle', action='store_true', help='also verify stock locked downloads across retained lifecycle')
    parser.add_argument('--composer-ci-architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--conda-micromamba', type=Path, help='the digest-pinned stock micromamba binary')
    parser.add_argument('--conda-group', action='store_true', help='also exercise the ordered Conda group with stock micromamba')
    parser.add_argument('--conda-ci-architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--cran-r', type=Path, help='the original interpreter in the pinned R distribution')
    parser.add_argument('--cran-r-home', type=Path, help='the private R home unpacked from the pinned distribution')
    parser.add_argument('--cran-tool-archive', type=Path, help='the pinned native R distribution archive')
    parser.add_argument('--cran-ci-architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--cran-install', action='store_true', help='also install the exact owned inert source archives')
    parser.add_argument('--cran-history', action='store_true', help='also exercise the reviewed historical archive directory')
    parser.add_argument('--cran-group', action='store_true', help='also exercise the digest-bound ordered CRAN group')
    parser.add_argument('--cran-binary', action='store_true', help='also build and install a stock macOS R binary fixture')
    parser.add_argument('--cran-proxy', action='store_true', help='also exercise a checksum-extended native CRAN source mirror')
    parser.add_argument('--npm-search', action='store_true',
                        help='also verify npm hosted and cached search using stock clients')
    parser.add_argument('--npm-search-ci-architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--python-search-client', type=Path,
                        help='also verify hosted and cached search with a Python environment containing stock pip and Twine')
    parser.add_argument('--python-search-ci-architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--cargo-toolchain', type=Path)
    parser.add_argument('--cargo-ci-architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--cargo-public-origin', action='store_true',
                        help='also fetch a pinned dependency graph from the public crates.io index and CDN')
    parser.add_argument('--legacy-cargo-daemon', type=Path)
    options = parser.parse_args()
    cran_tools = (options.cran_r, options.cran_r_home, options.cran_tool_archive)
    if any(cran_tools) and not all(cran_tools):
        parser.error('native CRAN evidence requires the original R interpreter, its home and pinned distribution archive')
    if options.cran_ci_architecture and not all(cran_tools):
        parser.error('hosted CRAN evidence requires the complete pinned stock R runtime')
    if options.cran_install and not all(cran_tools):
        parser.error('the owned CRAN installation requires the complete pinned stock R runtime')
    if options.cran_history and not all(cran_tools):
        parser.error('the owned CRAN archive replay requires the complete pinned stock R runtime')
    if options.cran_group and not all(cran_tools):
        parser.error('the owned CRAN group replay requires the complete pinned stock R runtime')
    if options.cran_proxy and not all(cran_tools):
        parser.error('the owned CRAN proxy replay requires the complete pinned stock R runtime')
    if options.cran_binary and (not all(cran_tools) or options.cran_ci_architecture or platform.system() != 'Darwin'):
        parser.error('the CRAN binary replay requires the complete pinned macOS R runtime and local native reporting')
    if options.cran_r and any((options.provider_binary, options.npm_search, options.python_search_client,
                               options.cargo_toolchain, options.mcp_binary, options.oci_catalog_client,
                               options.maven_index_reader, options.promtool, options.debian_apt, options.composer_phar,
                               options.conda_micromamba)):
        parser.error('native CRAN evidence requires the isolated stock R profile')
    if options.conda_ci_architecture and not options.conda_micromamba:
        parser.error('native Conda evidence requires the pinned micromamba binary')
    if options.conda_group and not options.conda_micromamba:
        parser.error('the native Conda group requires the pinned micromamba binary')
    if options.conda_micromamba and any((options.provider_binary, options.npm_search, options.python_search_client,
                                        options.cargo_toolchain, options.mcp_binary, options.oci_catalog_client,
                                        options.maven_index_reader, options.promtool, options.debian_apt, options.composer_phar)):
        parser.error('native Conda evidence requires an isolated stock micromamba profile')
    if bool(options.composer_php) != bool(options.composer_phar):
        parser.error('Composer qualification requires the PHP runtime and pinned PHAR')
    if options.composer_group and not options.composer_phar:
        parser.error('Composer group qualification requires the hosted stock client profile')
    if options.composer_versions and not options.composer_group:
        parser.error('Composer version qualification requires the combined stock client profile')
    if options.composer_proxy and (not options.composer_versions or options.cargo_toolchain):
        parser.error('Composer proxy qualification requires the combined Composer profile and its own upstream credential scope')
    if options.composer_search and not options.composer_proxy:
        parser.error('Composer search qualification requires the combined stock Composer profile')
    if options.composer_lifecycle and not options.composer_search:
        parser.error('Composer lifecycle qualification requires the hosted discovery fixture')
    if options.composer_ci_architecture and (not options.composer_phar or options.provider_binary or options.npm_search
                                              or options.python_search_client or options.cargo_toolchain or options.mcp_binary
                                              or options.oci_catalog_client or options.maven_index_reader or options.promtool
                                              or options.debian_apt):
        parser.error('native Composer evidence requires the isolated stock Composer profile')
    if options.debian_apt_suite and not options.debian_apt:
        parser.error('the named Debian suite profile requires the flat APT baseline')
    if options.debian_apt_ci_architecture and (not options.debian_apt or options.provider_binary or options.npm_search
                                               or options.python_search_client or options.cargo_toolchain or options.mcp_binary
                                               or options.oci_catalog_client or options.maven_index_reader or options.promtool):
        parser.error('native Debian evidence requires the isolated stock APT profile')
    if bool(options.maven_index_reader) != bool(options.maven_index_java):
        parser.error('the Maven index profile requires both the JDK and stock index reader')
    if options.maven_index_cached and not options.maven_index_reader:
        parser.error('cached Maven index requires the stock Apache reader')
    if options.maven_index_reader and (options.ci_architecture or options.cargo_ci_architecture or options.npm_search_ci_architecture
                                        or options.python_search_ci_architecture or options.oci_catalog_ci_architecture):
        parser.error('Maven index evidence uses its own stock profile')
    if options.maven_index_ci_architecture and (not options.maven_index_reader or options.provider_binary
                                               or options.npm_search or options.python_search_client or options.cargo_toolchain
                                               or options.oci_catalog_client or options.mcp_binary or options.promtool):
        parser.error('native Maven index evidence requires the isolated stock Apache reader profile')
    if options.oci_catalog_client and (options.ci_architecture or options.cargo_ci_architecture
                                       or options.npm_search_ci_architecture or options.python_search_ci_architecture):
        parser.error('OCI repository catalog uses its own stock evidence profile')
    if options.oci_catalog_ci_architecture and (not options.oci_catalog_client or options.provider_binary
                                               or options.npm_search or options.python_search_client or options.cargo_toolchain
                                               or options.mcp_binary or options.promtool):
        parser.error('native OCI catalog evidence requires the isolated stock ORAS catalog profile')
    if options.oci_catalog_cached and not options.oci_catalog_client:
        parser.error('cached OCI catalog requires stock ORAS')
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
    if options.cargo_public_origin and not options.cargo_toolchain:
        parser.error('the public origin check requires the stock Cargo profile')
    if options.npm_search and (options.ci_architecture or options.cargo_ci_architecture):
        parser.error('npm search uses its own stock npm evidence profile')
    if options.npm_search_ci_architecture and (not options.npm_search or options.cargo_toolchain
                                                or options.promtool or options.mcp_binary or options.provider_binary):
        parser.error('hosted npm search evidence requires the isolated stock npm search profile')
    if options.python_search_client and (options.ci_architecture or options.cargo_ci_architecture
                                         or options.npm_search_ci_architecture):
        parser.error('Python search uses its own stock evidence profile')
    if options.python_search_ci_architecture and (not options.python_search_client or options.cargo_toolchain
                                                   or options.npm_search or options.promtool
                                                   or options.mcp_binary or options.provider_binary):
        parser.error('hosted Python evidence requires the isolated stock Python search profile')
    if options.legacy_cargo_daemon and (not options.cargo_toolchain or options.cargo_ci_architecture):
        parser.error('historical Cargo adoption requires the local stock Cargo profile and reviewed schema 18 daemon')
    evaluate(options)
