#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Run the blank Compose bootstrap, npm policy and persistent restart journey."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import sys
import time

from bounded_client import run_owned_client
from ci.compose_evidence import CHECKS, SOURCE_PATHS, safe_compose_contract
from compose_evaluation import ROOT, private_directory, private_save, read_state


URL = 'https://127.0.0.1:38443'
PAYLOAD = b'Exact inert cratectl Compose fixture.\n'
TABLES = """SELECT count(*), count(*) FILTER(WHERE c.relrowsecurity AND c.relforcerowsecurity),
count(*) FILTER(WHERE pg_get_userbyid(c.relowner)='cratectl_app')
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='cratectl' AND c.relkind IN ('r','p') AND EXISTS
(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant' AND NOT a.attisdropped)"""


def require(condition, label):
    if not condition:
        raise ValueError(label)


def digest(path):
    state = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(128 << 10), b''):
            state.update(block)
    return state.hexdigest()


class Journey:
    def __init__(self, architecture):
        self.architecture = architecture
        self.project = 'cratectl-compose-' + secrets.token_hex(6)
        private_directory(ROOT / '.private')
        self.state = ROOT / '.private' / self.project
        self.state.mkdir(mode=0o700)
        self.work = self.state / 'qualification'
        self.work.mkdir(mode=0o700)
        self.install = self.state / 'installation'
        self.config = self.state / 'client.json'
        self.launcher = [sys.executable, 'scripts/compose_evaluation.py']
        self.build = ROOT / '.cache' / self.project
        self.cli = self.build / 'host/cratectl'
        self.npm = self.work / 'npmrc'
        self.package = self.project + '-proof'
        self.env = {key: value for key, value in os.environ.items() if not key.lower().startswith('npm_config_')}
        self.env.update(NPM_CONFIG_USERCONFIG=str(self.npm), NPM_CONFIG_GLOBALCONFIG='/dev/null',
                        NPM_CONFIG_CACHE=str(self.work / 'publish-cache'), NPM_CONFIG_AUDIT='false',
                        NPM_CONFIG_FUND='false', NPM_CONFIG_REGISTRY=URL + '/npm/packages/', NO_PROXY='*')
        self.checks = []
        self.command_index = 0
        self.stopped = False

    def run(self, label, argv, *, cwd=ROOT, env=None, timeout=90, expected=0):
        self.command_index += 1
        log = self.work / f'{self.command_index:03d}-{label}.log'
        try:
            with log.open('xb') as output:
                code, text = run_owned_client(argv, cwd, os.environ if env is None else env,
                                              timeout=timeout, capture_limit=2 << 20, output_sink=output)
        except (OSError, RuntimeError, ValueError):
            raise ValueError('owned command refused at ' + label) from None
        require(code == expected if expected is not None else code != 0, 'unexpected command result at ' + label)
        return text

    def check(self, label, passed):
        require(passed, 'Compose check failed at ' + label)
        self.checks.append(label)

    def compose(self, action):
        return self.run('compose-' + action, [*self.launcher, action, '--project', self.project], timeout=590)

    def services(self):
        listing = self.run('services', ['docker', 'ps', '--filter', 'label=com.docker.compose.project=' + self.project,
                                       '--format', '{{.ID}} {{.Label "com.docker.compose.service"}}'])
        rows = listing.splitlines()
        services = {service: container for container, service in (row.split() for row in rows)}
        require(len(services) == len(rows), 'duplicate owned Compose services')
        return services

    def management(self, label, path, *, payload=None, method='GET'):
        argv = [self.cli, '--config', self.config, '--path', '/api/v1/' + path, '--method', method]
        if payload is not None:
            body = self.work / (label + '.json')
            private_save(body, json.dumps(payload))
            argv.extend(['--body-file', body, '--idempotency-key', self.project + '-' + label])
        return json.loads(self.run(label, argv))

    def install_package(self, label, expected=0):
        location = self.work / label
        location.mkdir(mode=0o700)
        self.run(label, ['npm', 'install', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false',
                         self.package + '@1.0.0'], cwd=location, expected=expected,
                 env={**self.env, 'NPM_CONFIG_CACHE': str(location / 'cache')})
        installed = location / 'node_modules' / self.package / 'proof.txt'
        return installed.read_bytes() if installed.is_file() else None

    def qualify(self, candidate):
        self.check('clean-source', not self.run('source-clean', ['git', 'status', '--porcelain']))
        self.compose('up')
        services = self.services()
        go = ROOT / '.cache/go/bin/go'
        if not go.is_file():
            go = shutil.which('go')
        require(go is not None, 'Go SDK required')
        env = {k: v for k, v in os.environ.items() if k not in ('GOOS', 'GOARCH')}
        self.run('host-build', ['make', 'build', 'BINDIR=' + str(self.cli.parent)], env=env, timeout=300)
        output = self.build / ('linux-' + self.architecture)
        binaries = {}
        for label, name in [('linux-cli', 'cratectl'), ('linux-daemon', 'cratectld')]:
            path = output / name
            identity = self.run(label, [go, 'version', '-m', path])
            self.check(label, all('\tbuild\t' + value + '\n' in identity for value in
                                  ('vcs.revision=' + candidate, 'vcs.modified=false', 'GOOS=linux', 'GOARCH=' + self.architecture))
                       and '\tpath\tctlplne.dev/cratectl/cmd/' + name + '\n' in identity)
            binaries[name] = digest(path)
        self.check('owned-topology', set(services) == {'postgres', 'registry', 'worker'})

        def postgres(statement):
            return self.run('postgres-metadata', ['docker', 'exec', services['postgres'], 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
                                                  '-At', '-U', 'postgres', '-p', '35432', '-d', 'cratectl', '-c', statement]).strip()

        roles = postgres("SELECT rolsuper||'/'||rolbypassrls||'/'||rolinherit FROM pg_roles WHERE rolname='cratectl_app'")
        total, forced, owned = map(int, postgres(TABLES).split('|'))
        self.check('forced-rls', roles == 'false/false/false' and 0 < total == forced and owned == 0)
        schema = int(postgres('SELECT max(version) FROM cratectl_private.schema_migrations'))
        self.check('schema', schema == 18)
        model = self.compose('config')
        definitions = json.loads(model)['services']
        port, = definitions['registry']['ports']
        inputs = read_state(self.state / 'evaluation.json')
        self.check('safe-render', all(inputs[role] not in model for role in ('postgres', 'owner', 'runtime'))
                   and port['host_ip'] == '127.0.0.1' and str(port['published']) == '38443'
                   and int(port['target']) == 38443 and not definitions['postgres'].get('ports'))
        image_ids = set()
        for service in ('registry', 'worker'):
            info, = json.loads(self.run(service, ['docker', 'inspect', services[service]]))
            image_ids.add(info['Image'])
            variables = {item.split('=', 1)[0] for item in info['Config']['Env']}
            mounted = {Path(item['Destination']).name for item in info['Mounts']}
            self.check(service + '-scope', info['HostConfig']['ReadonlyRootfs'] and info['Config']['User'] != '0:0'
                       and not {'CRATECTL_OWNER_DSN', 'POSTGRES_PASSWORD', 'CRATECTL_DB_OWNER_PASSWORD'} & variables
                       and not {'admin.token', 'prepare.json'} & mounted and ('server.key' in mounted) == (service == 'registry'))
        require(len(image_ids) == 1, 'registry and worker must run the same image')
        image = self.run('image', ['docker', 'image', 'inspect', image_ids.pop(), '--format', '{{.Id}} {{.Os}}/{{.Architecture}}']).split()
        require(len(image) == 2 and image[1] == 'linux/' + self.architecture, 'native Compose runtime image required')
        self.check('private-cli-config', stat.S_IMODE(self.config.stat().st_mode) == 0o600)
        curl = ['curl', '-q', '--noproxy', '*', '--silent', '--show-error', '--fail']
        self.run('tls-refused', [*curl, URL + '/health/ready'], expected=60)
        self.run('tls-trusted', [*curl, '--cacert', self.install / 'ca.crt', URL + '/health/ready'])
        self.check('tls-trust', True)
        self.check('blank-installation', self.management('blank', 'repositories')['items'] == [])
        self.management('create', 'repositories', method='POST', payload={'name': 'packages', 'format': 'npm', 'require_review': True})
        configured = json.loads(self.run('npm-config', [self.cli, 'npm-config', '--config', self.config,
                                                       '--repository', 'packages', '--output', self.npm]))
        self.check('private-npm-config', configured['tls_verification'] is True and stat.S_IMODE(self.npm.stat().st_mode) == 0o600)
        package = self.work / 'package'
        package.mkdir(mode=0o700)
        private_save(package / 'package.json', json.dumps({'name': self.package, 'version': '1.0.0', 'license': 'MIT'}))
        (package / 'proof.txt').write_bytes(PAYLOAD)
        self.run('publish', ['npm', 'publish', '--ignore-scripts', '--access', 'public'], cwd=package, env=self.env)
        artifact, = self.management('published', 'repositories/packages/artifacts')['items']
        self.check('stock-publish', artifact['decision'] == 'unassessed' and re.fullmatch('[0-9a-f]{64}', artifact['digest']))
        self.check('review-refusal', self.install_package('unassessed', expected=None) is None)
        self.management('approve', 'repositories/packages/decisions', method='PUT',
                        payload={'path': artifact['path'], 'digest': artifact['digest'], 'decision': 'allowed'})
        self.check('approved-install', self.install_package('approved') == PAYLOAD)
        deadline = time.monotonic() + 30
        while True:
            jobs = self.management('jobs', 'jobs?limit=100')['items']
            if (jobs and all(job['state'] == 'succeeded' for job in jobs)) or time.monotonic() >= deadline:
                break
            time.sleep(.5)
        self.check('worker-receipts', {job['handler'] for job in jobs} == {'storage.integrity', 'event.project'}
                   and all(job['state'] == 'succeeded' for job in jobs))
        originals = {name: digest(self.install / name) for name in ('ca.crt', 'prepare.json')}
        self.compose('down')
        self.check('shutdown', not self.services())
        self.compose('up')
        self.check('fresh-install-after-restart', self.install_package('restarted') == PAYLOAD and
                   all(digest(self.install / name) == value for name, value in originals.items()))
        self.compose('down')
        volume = self.run('retained-volume', ['docker', 'volume', 'inspect', self.project + '_database', '--format',
                                              '{{index .Labels "com.docker.compose.project"}}']).strip()
        self.check('retained-volume', volume == self.project and not self.services())
        self.stopped = True
        require(self.checks == list(CHECKS), 'complete ordered Compose check inventory required')
        sdk = self.run('go-version', [go, 'version']).split()[2].removeprefix('go')
        return {'checks': self.checks, 'forced_rls_tenant_tables': forced, 'database_schema': schema,
                'binary_sha256': binaries, 'runtime_image_id': image[0], 'go_version': sdk,
                'compose_version': self.run('compose-version', ['docker', 'compose', 'version', '--short']).strip(),
                'npm_version': self.run('npm-version', ['npm', '--version'], env=self.env).strip()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', required=True, choices=('amd64', 'arm64'))
    parser.add_argument('--ci-report', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    os.chdir(ROOT)
    system = platform.system()
    arch = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64'}.get(platform.machine())
    labels = {'arm64': 'ARM64', 'amd64': 'X64'}
    require(arch == args.architecture and system in ('Linux', 'Darwin'), 'actual native architecture required')
    if args.ci_report:
        require(system == 'Linux' and os.environ.get('GITHUB_ACTIONS') == 'true'
                and os.environ.get('RUNNER_OS') == 'Linux' and os.environ.get('RUNNER_ARCH') == labels[arch]
                and re.fullmatch('[1-9][0-9]{0,17}', os.environ.get('GITHUB_RUN_ID', '')), 'actual GitHub Linux runner required')
    journey = Journey(arch)
    candidate = journey.run('source', ['git', 'rev-parse', 'HEAD']).strip()
    if args.ci_report:
        require(candidate == os.environ.get('GITHUB_SHA'), 'exact GitHub source required')
    try:
        qualified = journey.qualify(candidate)
        report = {'schema': 1, 'profile': 'cratectl-compose-evaluation-v1', 'candidate': candidate,
                  'run_id': os.environ.get('GITHUB_RUN_ID'), 'runner_os': system, 'runner_arch': labels[arch],
                  'status': 'passed', 'source_dirty': False, **qualified,
                  'source_sha256': {name: digest(ROOT / name) for name in SOURCE_PATHS},
                  'goal_complete': False, 'broad_readiness': False}
        if args.ci_report:
            safe_compose_contract(report)
            private_save(ROOT / '.cache/ci-compose-evaluation.json', json.dumps(report, indent=2) + '\n')
        private_save(journey.work / 'safe-summary.json', json.dumps(report, indent=2) + '\n')
        print(f'PASS: {len(CHECKS)} scoped Compose checks')
    except BaseException:
        if not journey.stopped and (journey.state / 'evaluation.json').is_file():
            try:
                journey.compose('down')
            except ValueError:
                print('Owned Compose shutdown also failed. See the private command logs.', file=sys.stderr)
        raise


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        raise SystemExit(f'Compose qualification failed: {error}') from None
