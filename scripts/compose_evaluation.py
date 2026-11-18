#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Launch a local, disposable cratectl evaluation with durable private state."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import tempfile
import time
from urllib.error import URLError
from urllib.request import build_opener, HTTPSHandler, ProxyHandler


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / 'deploy/compose'
POSTGRES = 'docker.io/library/postgres:16.15-alpine@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139'
PROJECT = re.compile(r'cratectl-[a-z0-9][a-z0-9-]{0,39}\Z')
TENANT = re.compile(r'[a-z][a-z0-9-]{0,62}\Z')


def command(*argv, capture=False, env=None, timeout=30):
    result = subprocess.run(argv, cwd=ROOT, env=env, text=True, check=True,
                            timeout=timeout, stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def private_directory(path):
    path.mkdir(mode=0o700, exist_ok=True)
    actual = path.lstat()
    if not stat.S_ISDIR(actual.st_mode) or actual.st_uid != os.geteuid() or actual.st_mode & 0o077:
        raise ValueError('Evaluation state must be owned by the current user with mode 0700')


def private_save(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.cratectl-', delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(data.encode('ascii'))
            file.flush()
            os.fsync(file.fileno())
            os.replace(temporary, path)
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            temporary.unlink(missing_ok=True)


def read_state(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as file:
        actual = os.fstat(file.fileno())
        if not stat.S_ISREG(actual.st_mode) or actual.st_uid != os.geteuid() or actual.st_mode & 0o077:
            raise ValueError('Evaluation state must be a private regular file')
        raw = file.read(1025)
    if len(raw) > 1024:
        raise ValueError('Evaluation state exceeds its size limit')
    return json.loads(raw)


def state_for(directory, action, tenant, candidate=None):
    state_file = directory / 'evaluation.json'
    try:
        state = read_state(state_file)
    except FileNotFoundError:
        if action != 'up':
            raise ValueError('Start this evaluation project with up first') from None
        state = {'candidate': candidate, 'tenant': tenant or 'evaluation',
                 **{role: secrets.token_hex(24) for role in ('postgres', 'owner', 'runtime')}}
        private_save(state_file, json.dumps(state) + '\n')
    if (type(state) is not dict or set(state) != {'candidate', 'tenant', 'postgres', 'owner', 'runtime'}
            or any(type(value) is not str for value in state.values())
            or not re.fullmatch(r'[a-f0-9]{40}', state['candidate']) or not TENANT.fullmatch(state['tenant'])
            or any(not re.fullmatch(r'[a-f0-9]{48}', state[role]) for role in ('postgres', 'owner', 'runtime'))):
        raise ValueError('Malformed private evaluation state')
    if (candidate and candidate != state['candidate']) or (tenant and tenant != state['tenant']):
        raise ValueError('Use the original source and tenant or choose a fresh evaluation project')
    return state


def prepare_inputs(directory, state):
    private_directory(directory / 'installation')
    private_directory(directory / 'pagination')
    private_save(directory / 'postgres.env', '\n'.join((
        'POSTGRES_PASSWORD=' + state['postgres'], 'CRATECTL_DB_OWNER_PASSWORD=' + state['owner'],
        'CRATECTL_DB_RUNTIME_PASSWORD=' + state['runtime'], '')))
    host = '@postgres:35432/cratectl?sslmode=disable\n'
    private_save(directory / 'init.env', 'CRATECTL_OWNER_DSN=postgres://cratectl_owner:' + state['owner'] + host
                 + 'CRATECTL_DSN=postgres://cratectl_app:' + state['runtime'] + host)


def prepare_client(directory):
    installation = directory / 'installation'
    config = {'version': 1, 'url': 'https://127.0.0.1:38443',
              'token_file': str(installation / 'admin.token'), 'ca_file': str(installation / 'ca.crt')}
    private_save(directory / 'client.json', json.dumps(config) + '\n')


def ready(directory):
    context = ssl.create_default_context(cafile=str(directory / 'installation/ca.crt'))
    client = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with client.open('https://127.0.0.1:38443/health/ready', timeout=2) as response:
                if response.status == 200:
                    return
        except (URLError, TimeoutError):
            pass
        time.sleep(.25)
    raise ValueError('TLS readiness did not reach HTTP 200 within 60 seconds')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('up', 'down', 'config'))
    parser.add_argument('--project', default='cratectl-evaluation')
    parser.add_argument('--tenant', help='First tenant for a new evaluation project (default evaluation)')
    args = parser.parse_args()
    if not PROJECT.fullmatch(args.project) or args.tenant and not TENANT.fullmatch(args.tenant):
        parser.error('Use a cratectl-* project and a tenant of lowercase letters, numbers and hyphens')
    if os.geteuid() == 0:
        parser.error('Run the evaluation as your unprivileged local user')

    candidate = None
    if args.action == 'up':
        if command('git', 'status', '--porcelain', capture=True):
            parser.error('Build the evaluation from a clean cratectl commit')
        candidate = command('git', 'rev-parse', 'HEAD', capture=True)

    context = command('docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}', capture=True)
    if not context.startswith('unix://') or not os.environ.get('DOCKER_HOST', 'unix://').startswith('unix://'):
        parser.error('The evaluation requires a local Docker Unix socket')
    engine = command('docker', 'info', '--format', '{{.OSType}}/{{.Architecture}}', capture=True)
    architecture = {'linux/x86_64': 'amd64', 'linux/amd64': 'amd64',
                    'linux/aarch64': 'arm64', 'linux/arm64': 'arm64'}.get(engine)
    if architecture is None:
        parser.error('Docker must use a Linux amd64 or arm64 engine')

    private_directory(ROOT / '.private')
    directory = ROOT / '.private' / args.project
    private_directory(directory)
    output = ROOT / '.cache' / args.project / ('linux-' + architecture)
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(directory / 'launcher.lock', flags, 0o600), 'rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = state_for(directory, args.action, args.tenant, candidate)
        env = {**os.environ, 'CRATECTL_COMPOSE_IMAGE': f'{args.project}:{state["candidate"]}-{architecture}',
               'CRATECTL_COMPOSE_PLATFORM': 'linux/' + architecture,
               'CRATECTL_COMPOSE_USER': f'{os.geteuid()}:{os.getegid()}',
               'CRATECTL_COMPOSE_POSTGRES': POSTGRES, 'CRATECTL_COMPOSE_TENANT': state['tenant'],
               'CRATECTL_COMPOSE_BUILD': str(output), 'CRATECTL_COMPOSE_STATE': str(directory),
               'CRATECTL_COMPOSE_POSTGRES_ENV': '/dev/null', 'CRATECTL_COMPOSE_INIT_ENV': '/dev/null'}
        # Some Compose releases resolve service env_file even during a render.
        # The renderer, image builder and runtime services receive empty files.
        postgres_env = {**env, 'CRATECTL_COMPOSE_POSTGRES_ENV': str(directory / 'postgres.env')}
        init_env = {**env, 'CRATECTL_COMPOSE_INIT_ENV': str(directory / 'init.env')}
        base = ('docker', 'compose', '--env-file', '/dev/null', '-f', str(DEPLOY / 'compose.yaml'), '-p', args.project)
        if args.action == 'config':
            command(*base, '--profile', 'bootstrap', 'config', '--no-env-resolution', '--format', 'json', env=env)
        elif args.action == 'down':
            command(*base, 'down', env=env, timeout=90)
        else:
            prepare_inputs(directory, state)
            output.mkdir(parents=True, exist_ok=True)
            for name in ('Dockerfile', '.dockerignore'):
                shutil.copyfile(DEPLOY / name, output / name)
            command('make', 'build', 'BINDIR=' + str(output), timeout=300,
                    env={**os.environ, 'GOOS': 'linux', 'GOARCH': architecture, 'CGO_ENABLED': '0'})
            command(*base, 'build', 'registry', env=env, timeout=300)
            command(*base, 'up', '-d', '--wait', '--wait-timeout', '75', 'postgres', env=postgres_env, timeout=90)
            command(*base, 'run', '--rm', '--no-deps', 'init', env=init_env, timeout=150)
            prepare_client(directory)
            command(*base, 'up', '-d', '--no-build', '--no-deps', 'registry', 'worker', env=env, timeout=90)
            ready(directory)
            print(f'cratectl is ready at https://127.0.0.1:38443. Client configuration is in {directory / "client.json"}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f'cratectl Compose evaluation failed: {error}') from None
