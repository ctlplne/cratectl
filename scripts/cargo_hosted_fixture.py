#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Replay authenticated stock Cargo on the fixture's real registry."""
import json
import re
import ssl
import struct
import urllib.error
import urllib.request
import tomllib


REPOSITORY = 'cratectl-cargo'
BASE_PACKAGE = 'cratectl-cargo-leaf'
ROOT_PACKAGE = 'cratectl-cargo-root'
VERSION = '1.0.0'


def evaluate_cargo(work, installation, authority, toolchain, environment, call, api, restart, sha):
    repo = '/api/v1/repositories/' + REPOSITORY
    base = authority + '/cargo/' + REPOSITORY
    index_url = 'sparse+' + base + '/index/'
    trust = ssl.create_default_context(cafile=str(installation / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))
    admin = (installation / 'admin.token').read_text().strip()
    reader = (work / 'reader.token').read_text().strip()
    other = (work / 'other.token').read_text().strip()
    checks = []

    def check(name, passed):
        if not passed:
            raise ValueError(name)
        checks.append(name)

    def request(endpoint, token=None, frame=None, method=None):
        headers = {} if token is None else {'Authorization': token}
        if frame is not None:
            headers['Content-Type'] = 'application/octet-stream'
        req = urllib.request.Request(base + endpoint, headers=headers, data=frame, method=method)
        try:
            with opener.open(req, timeout=10) as reply:
                data = reply.read((2 << 20) + 1)
                if len(data) > 2 << 20:
                    raise ValueError('Cargo fixture response exceeds its byte budget')
                return reply.status, data
        except urllib.error.HTTPError as err:
            err.close()
            return err.code, b''

    def index(name):
        return '/index/' + name[:2] + '/' + name[2:4] + '/' + name

    cargo, rustc = toolchain / 'cargo', toolchain / 'rustc'
    cargo_version = call('stock-cargo-version', cargo, '-V')[1].strip()
    rust_version = call('stock-rustc-version', rustc, '-Vv')[1]
    check('stock Cargo and rustc 1.100.0', bool(re.fullmatch(r'cargo 1\.100\.0 \([0-9a-f]+ [0-9-]+\)', cargo_version))
          and rust_version.startswith('rustc 1.100.0 '))
    shared_env = {k: v for k, v in environment.items() if not k.startswith(('CARGO_', 'RUST_', 'RUSTC', 'RUSTUP'))}
    shared_env.update(RUSTC=str(rustc), CARGO_HTTP_CAINFO=str(installation / 'ca.crt'), CARGO_NET_RETRY='0',
                      CARGO_HTTP_TIMEOUT='10', NO_PROXY='localhost,127.0.0.1', no_proxy='localhost,127.0.0.1',
                      CARGO_HTTP_PROXY='http://127.0.0.1:38443')

    def cargo_env(label, token):
        directory = work / label
        directory.mkdir(mode=0o700)
        (directory / 'config.toml').write_text('[registry]\nglobal-credential-providers = ["cargo:token"]\n'
                                               '[registries.cratectl]\nindex = ' + json.dumps(index_url) + '\n')
        env = dict(shared_env, CARGO_HOME=str(directory))
        if token is not None:
            env['CARGO_REGISTRIES_CRATECTL_TOKEN'] = token
        return directory, env

    def new_project(path, name, dependency=''):
        (path / 'src').mkdir(mode=0o700, parents=True)
        (path / 'src/lib.rs').write_text('// Inert registry download fixture.\n')
        (path / 'Cargo.toml').write_text(f'[package]\nname = "{name}"\nversion = "{VERSION}"\nedition = "2024"\n'
                                         'rust-version = "1.89"\nlicense = "MIT"\n'
                                         'description = "cratectl inert fixture"\n' + dependency)

    api('cargo-create', '/api/v1/repositories', 'POST', {
        'name': REPOSITORY, 'format': 'cargo', 'access': 'restricted', 'require_review': False,
    })
    check('registry discovery requires a tenant token and current repository grant',
          request('/index/config.json')[0] == 401 and request('/index/config.json', reader)[0] == 403
          and request('/index/config.json', other)[0] == 404)
    status, data = request('/index/config.json', admin)
    check('sparse config binds required auth, API and downloads to the same trusted authority',
          status == 200 and json.loads(data) == {'api': base, 'dl': base+'/download/{crate}/{version}', 'auth-required': True})
    api('cargo-grant-reader', repo+'/grants', 'PUT', {'actor': 'cratectl-reader', 'read': True, 'write': False})
    _, publisher = cargo_env('cargo-publisher-home', admin)
    published = {}
    for label, name, spec in (
        ('leaf', BASE_PACKAGE, '\n[features]\nwire = []\n'),
        ('root', ROOT_PACKAGE, '\n[dependencies]\nfixture-leaf = {package = "'+BASE_PACKAGE+
         '", version = "1.0", registry = "cratectl", optional = true, default-features = false, features = ["wire"]}\n'
         '[features]\nwire = ["dep:fixture-leaf"]\n'),
    ):
        directory = work / ('cargo-' + label)
        new_project(directory, name, spec)
        call('cargo-publish-' + label, cargo, 'publish', '--registry', 'cratectl', '--allow-dirty', '--no-verify',
             cwd=directory, environment=dict(publisher, CARGO_TARGET_DIR=str(directory/'target')), timeout=85)
        published[name] = directory / 'target' / 'package' / 'tmp-crate' / f'{name}-{VERSION}.crate'
    rows = api('cargo-artifacts', repo+'/artifacts')['items']
    artifacts = {row['metadata']['name']: row for row in rows}
    check('two stock publications retain exact unassessed bytes',
          set(artifacts) == set(published) and all(artifacts[name]['decision'] == 'unassessed'
          and artifacts[name]['digest'] == sha(archive) for name, archive in published.items()))
    status, data = request(index(ROOT_PACKAGE), reader)
    entry = json.loads(data)
    dep, = entry['deps']
    check('sparse index binds immutable checksum and same-registry renamed dependency',
          status == 200 and data.endswith(b'\n') and entry['cksum'] == artifacts[ROOT_PACKAGE]['digest']
          and entry['features'] == {'wire': ['dep:fixture-leaf']} and entry['rust_version'] == '1.89'
          and dep == {'name': 'fixture-leaf', 'req': '1.0', 'features': ['wire'], 'optional': True,
                      'default_features': False, 'kind': 'normal', 'package': BASE_PACKAGE})

    metadata = json.dumps({'name': BASE_PACKAGE, 'vers': VERSION}).encode()
    original = published[BASE_PACKAGE].read_bytes()
    frame = struct.pack('<I', len(metadata)) + metadata + struct.pack('<I', len(original)) + original
    checkpoint = api('cargo-before-replay', '/api/v1/audit/checkpoint')
    check('ordinary publication retry preserves a single journal effect and requires current write authority',
          request('/api/v1/crates/new', admin, frame, 'PUT')[0] == 200
          and request('/api/v1/crates/new', reader, frame, 'PUT')[0] == 403
          and api('cargo-after-replay', '/api/v1/audit/checkpoint') == checkpoint)

    api('cargo-set-review', repo+'/policy', 'PUT', {'require_review': True})
    download = '/download/' + ROOT_PACKAGE + '/' + VERSION
    check('unassessed index entries are hidden and direct byte delivery is denied',
          request(index(ROOT_PACKAGE), reader)[0] == 404 and request(download, reader)[0] == 403)
    consumer = work / 'cargo-consumer'
    new_project(consumer, 'cratectl-cargo-consumer', '\n[dependencies]\n'+ROOT_PACKAGE+
                ' = {version = "=1.0.0", registry = "cratectl", features = ["wire"]}\n')
    _, pending = cargo_env('cargo-pending-home', reader)
    code, output = call('cargo-pending-fetch', cargo, 'fetch', '--manifest-path', consumer/'Cargo.toml',
                        cwd=consumer, environment=pending, status=101)
    check('fresh stock Cargo cannot resolve an unassessed crate', code == 101 and 'no matching package named' in output)
    for label, name in (('leaf', BASE_PACKAGE), ('root', ROOT_PACKAGE)):
        a = artifacts[name]
        api('cargo-approve-'+label, repo+'/decisions', 'PUT',
            {'path': a['path'], 'digest': a['digest'], 'decision': 'allowed'})
    restart()
    cache, approved = cargo_env('cargo-approved-home', reader)
    call('cargo-approved-fetch', cargo, 'fetch', '--manifest-path', consumer/'Cargo.toml',
         cwd=consumer, environment=approved)
    lock = tomllib.loads((consumer/'Cargo.lock').read_text())
    exact = {row['name']: row for row in lock['package'] if 'source' in row}
    fetched = {archive.name: sha(archive) for archive in (cache/'registry/cache').glob('*/*.crate')}
    check('fresh stock Cargo resolves the transitive graph and downloads exact approved bytes after restart',
          set(exact) == set(published) and all(exact[name]['checksum'] == sha(archive) and
          exact[name]['source'] == index_url and fetched.get(archive.name) == sha(archive)
          for name, archive in published.items()))
    check('protected download still honors both grant revocation and tenant binding',
          request(download, other)[0] == 404 and request(download, reader)[0] == 200)
    api('cargo-revoke-grant', repo+'/grants', 'PUT', {'actor': 'cratectl-reader', 'read': False, 'write': False})
    check('revoked grant refuses current index and direct download even with a populated client cache',
          request(index(ROOT_PACKAGE), reader)[0] == request(download, reader)[0] == 403)
    return {'cargo': cargo_version, 'cargo_sha256': sha(cargo), 'rustc_sha256': sha(rustc), 'checks': checks,
            'archive_sha256': {name: sha(archive) for name, archive in published.items()}}
