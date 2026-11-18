#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Replay authenticated stock Cargo on the fixture's real registry."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import re
import ssl
import struct
import tarfile
import time
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
    writer = (work / 'writer.token').read_text().strip()
    maintainer = (work / 'maintainer.token').read_text().strip()
    other = (work / 'other.token').read_text().strip()
    checks = []

    def check(name, passed):
        if not passed:
            raise ValueError(name)
        checks.append(name)

    def request(endpoint, token=None, frame=None, method=None, content_type='application/octet-stream'):
        headers = {} if token is None else {'Authorization': token}
        if frame is not None:
            headers['Content-Type'] = content_type
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

    def publish_frame(name, version, archive):
        metadata = json.dumps({'name': name, 'vers': version}).encode()
        return struct.pack('<I', len(metadata)) + metadata + struct.pack('<I', len(archive)) + archive

    def inert_archive(name, version):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as bundle:
            manifest = f'[package]\nname = "{name}"\nversion = "{version}"\n'.encode()
            item = tarfile.TarInfo(f'{name}-{version}/Cargo.toml')
            item.size = len(manifest)
            bundle.addfile(item, io.BytesIO(manifest))
        return data.getvalue()

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

    def new_project(path, name, dependency='', version=VERSION):
        (path / 'src').mkdir(mode=0o700, parents=True)
        (path / 'src/lib.rs').write_text('// Inert registry download fixture.\n')
        (path / 'Cargo.toml').write_text(f'[package]\nname = "{name}"\nversion = "{version}"\nedition = "2024"\n'
                                         'rust-version = "1.89"\nlicense = "MIT"\n'
                                         'description = "cratectl inert fixture"\n' + dependency)

    api('cargo-create', '/api/v1/repositories', 'POST', {
        'name': REPOSITORY, 'format': 'cargo', 'access': 'restricted', 'require_review': False,
    })
    check('registry discovery requires a tenant token and current repository grant',
          request('/index/config.json')[0] == 401 and request('/index/config.json', reader)[0] == 403
          and request('/index/config.json', writer)[0] == 403
          and request('/index/config.json', other)[0] == 404)
    status, data = request('/index/config.json', admin)
    check('sparse config binds required auth, API and downloads to the same trusted authority',
          status == 200 and json.loads(data) == {'api': base, 'dl': base+'/download/{crate}/{version}', 'auth-required': True})
    api('cargo-grant-reader', repo+'/grants', 'PUT', {'actor': 'cratectl-reader', 'read': True, 'write': False})
    api('cargo-grant-writer', repo+'/grants', 'PUT', {'actor': 'cratectl-writer', 'read': True, 'write': True})
    _, publisher = cargo_env('cargo-publisher-home', writer)
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

    original = published[BASE_PACKAGE].read_bytes()
    frame = publish_frame(BASE_PACKAGE, VERSION, original)
    new_crate = '/api/v1/crates/new'
    checkpoint = api('cargo-before-replay', '/api/v1/audit/checkpoint')
    with ThreadPoolExecutor(max_workers=2) as executor:
        attempts = [executor.submit(request, new_crate, writer, frame, 'PUT') for _ in range(2)]
        outcomes = [result.result()[0] for result in attempts]
    check('concurrent publication retries preserve a single journal effect and require current write authority',
          outcomes == [200, 200]
          and request(new_crate, reader, frame, 'PUT')[0] == 403
          and api('cargo-after-replay', '/api/v1/audit/checkpoint') == checkpoint)

    def refused_coordinate(name, version):
        return request(new_crate, writer, publish_frame(name, version, inert_archive(name, version)), 'PUT')[0] == 409

    check('conflicting bytes, build metadata and hyphen-underscore aliases preserve retained coordinates',
          refused_coordinate(BASE_PACKAGE, VERSION) and refused_coordinate(BASE_PACKAGE, VERSION+'+new')
          and refused_coordinate(BASE_PACKAGE.replace('-', '_'), '2.0.0')
          and api('cargo-after-collisions', '/api/v1/audit/checkpoint') == checkpoint)

    package_endpoint = '/api/v1/crates/' + ROOT_PACKAGE + '/' + VERSION
    owners_endpoint = '/api/v1/crates/' + ROOT_PACKAGE + '/owners'
    owner_code, owner_data = request(owners_endpoint, writer)
    original_owner, = json.loads(owner_data)['users']
    leaf_owner, = json.loads(request('/api/v1/crates/' + BASE_PACKAGE + '/owners', writer)[1])['users']
    check('first publication assigns one stable tenant-local owner identity across crates',
          owner_code == 200 and original_owner == leaf_owner and original_owner['login'] == 'cratectl-writer'
          and type(original_owner['id']) is int and original_owner['id'] > 0)
    api('cargo-grant-maintainer', repo+'/grants', 'PUT', {'actor': 'cratectl-maintainer', 'read': True, 'write': True})
    denied_archive = inert_archive(ROOT_PACKAGE, '5.0.0')
    denied_publication = publish_frame(ROOT_PACKAGE, '5.0.0', denied_archive)
    check('repository write grant alone cannot publish, yank, or list owners for an owned crate',
          request(new_crate, maintainer, denied_publication, 'PUT')[0] == 403
          and request(package_endpoint+'/yank', maintainer, method='DELETE')[0] == 403
          and request(owners_endpoint, maintainer)[0] == 403 and request(owners_endpoint, other)[0] == 404)
    owner_command = (cargo, 'owner', '--registry', 'cratectl')
    call('stock-cargo-owner-add', *owner_command, '--add', 'cratectl-maintainer', ROOT_PACKAGE,
         cwd=work/'cargo-root', environment=publisher)
    _, owner_environment = cargo_env('cargo-maintainer-home', maintainer)
    _, owner_output = call('stock-cargo-owner-list', *owner_command, '--list', ROOT_PACKAGE,
                           cwd=work/'cargo-root', environment=owner_environment)
    owners = json.loads(request(owners_endpoint, maintainer)[1])['users']
    check('stock Cargo adds and lists an independently granted co-owner',
          all(owner['login'] in owner_output for owner in owners)
          and {owner['login'] for owner in owners} == {'cratectl-writer', 'cratectl-maintainer'}
          and len({owner['id'] for owner in owners}) == 2)
    api('cargo-restrict-maintainer', repo+'/grants', 'PUT', {'actor': 'cratectl-maintainer', 'read': True, 'write': False})
    check('owner membership cannot override a current repository write revocation',
          request(owners_endpoint, maintainer)[0] == 403
          and request(package_endpoint+'/yank', maintainer, method='DELETE')[0] == 403)
    api('cargo-restore-maintainer-grant', repo+'/grants', 'PUT', {'actor': 'cratectl-maintainer', 'read': True, 'write': True})
    call('stock-cargo-owner-remove', *owner_command, '--remove', 'cratectl-maintainer', ROOT_PACKAGE,
         cwd=work/'cargo-root', environment=publisher)
    change_owner = json.dumps({'users': ['cratectl-writer']}).encode()
    check('stock owner removal revokes crate mutations and the last owner remains protected',
          request(owners_endpoint, writer, change_owner, 'DELETE', 'application/json')[0] == 409
          and request(package_endpoint+'/yank', maintainer, method='DELETE')[0] == 403
          and json.loads(request(owners_endpoint, writer)[1])['users'] == [original_owner])

    api('cargo-set-review', repo+'/policy', 'PUT', {'require_review': True})
    probe_name = 'cratectl-cargo-incomplete'
    probe_archive = inert_archive(probe_name, VERSION)
    probe = publish_frame(probe_name, VERSION, probe_archive)
    checkpoint = api('cargo-before-short-frame', '/api/v1/audit/checkpoint')
    check('short publication frame leaves no retained reference or journal effect',
          request(new_crate, writer, probe[:-16], 'PUT')[0] == 400
          and api('cargo-after-short-frame', '/api/v1/audit/checkpoint') == checkpoint
          and all(row['metadata']['name'] != probe_name for row in api('cargo-no-short-reference', repo+'/artifacts')['items']))
    check('complete retry binds exactly the original frame bytes to an unassessed reference',
          request(new_crate, writer, probe, 'PUT')[0] == 200
          and any(row['metadata']['name'] == probe_name and row['decision'] == 'unassessed'
                  and row['digest'] == hashlib.sha256(probe_archive).hexdigest()
                  for row in api('cargo-complete-reference', repo+'/artifacts')['items']))
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
    check('the same tenant owner identity survives registry restart',
          json.loads(request(owners_endpoint, writer)[1])['users'] == [original_owner])
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

    reference = {key: artifacts[ROOT_PACKAGE][key] for key in ('path', 'digest')}
    lifecycle = repo + '/artifacts/lifecycle'
    api('cargo-hold', lifecycle, 'PUT', {**reference, 'action': 'hold', 'expected_revision': 0,
                                        'reason': 'Retain approved crate lifecycle evidence'})
    check('reader and active hold block yank without changing the index',
          request(package_endpoint + '/yank', reader, method='DELETE')[0] == 403
          and request(package_endpoint + '/yank', writer, method='DELETE')[0] == 409
          and json.loads(request(index(ROOT_PACKAGE), reader)[1])['yanked'] is False)
    api('cargo-release-hold', lifecycle, 'PUT', {**reference, 'action': 'release_hold', 'expected_revision': 1,
                                                'reason': 'Release the owned fixture hold'})
    yank = (cargo, 'yank', '--registry', 'cratectl', '--version', VERSION, ROOT_PACKAGE)
    original_entry = json.loads(request(index(ROOT_PACKAGE), reader)[1])
    call('stock-cargo-yank', *yank, cwd=work/'cargo-root', environment=publisher)
    status, yanked = request(index(ROOT_PACKAGE), reader)
    checkpoint = api('cargo-yank-checkpoint', '/api/v1/audit/checkpoint')
    check('stock Cargo yank changes only discovery and repeated yank leaves the journal unchanged',
          status == 200 and json.loads(yanked) == {**original_entry, 'yanked': True}
          and request(package_endpoint+'/yank', writer, method='DELETE')[0] == 200
          and api('cargo-yank-retry-checkpoint', '/api/v1/audit/checkpoint') == checkpoint)

    alternative = work/'cargo-unlocked'
    new_project(alternative, 'cratectl-cargo-unlocked', '\n[dependencies]\n'+ROOT_PACKAGE+
                ' = {version = "=1.0.0", registry = "cratectl", features = ["wire"]}\n')
    _, unlocked = cargo_env('cargo-unlocked-home', reader)
    _, output = call('cargo-yank-fresh-resolution', cargo, 'fetch', cwd=alternative, environment=unlocked, status=101)
    check('stock Cargo rejects a yanked version during fresh resolution', 'version 1.0.0 is yanked' in output)

    locked_cache, locked = cargo_env('cargo-locked-home', reader)
    call('cargo-yank-locked-fetch', cargo, 'fetch', '--locked', cwd=consumer, environment=locked)
    locked_archives = {archive.name: sha(archive) for archive in (locked_cache/'registry/cache').glob('*/*.crate')}
    check('stock Cargo lockfile still fetches both exact approved archives while yanked', locked_archives == fetched)
    call('stock-cargo-unyank', *yank, '--undo', cwd=work/'cargo-root', environment=publisher)
    restart()
    _, restored = cargo_env('cargo-unyanked-home', reader)
    call('cargo-unyank-fresh-resolution', cargo, 'fetch', cwd=alternative, environment=restored)
    check('stock Cargo unyank restores fresh resolution after restart with the original index entry',
          json.loads(request(index(ROOT_PACKAGE), reader)[1]) == original_entry)

    api('cargo-retain-deleted', lifecycle, 'PUT', {**reference, 'action': 'delete', 'expected_revision': 2,
                                                  'reason': 'Retain the original crate bytes during deletion'})
    check('common deletion removes discovery and blocks even exact pinned byte access',
          request(index(ROOT_PACKAGE), reader)[0] == request(download, reader)[0] == 404)
    api('cargo-restore-deleted', lifecycle, 'PUT', {**reference, 'action': 'restore', 'expected_revision': 3,
                                                   'reason': 'Restore the verified original crate bytes'})
    status, restored_bytes = request(download, reader)
    check('common restoration restores the original index and exact approved archive',
          status == 200 and restored_bytes == published[ROOT_PACKAGE].read_bytes()
          and json.loads(request(index(ROOT_PACKAGE), reader)[1]) == original_entry)

    search_endpoint = '/api/v1/crates?q=' + ROOT_PACKAGE + '&per_page=1'
    check('Cargo search requires current tenant and repository access',
          request(search_endpoint)[0] == 401 and request(search_endpoint, other)[0] == 404
          and request(search_endpoint+'&per_page=1', reader)[0] == 400)
    _, search_env = cargo_env('cargo-search-home', reader)

    def stock_search(label):
        _, text = call(label, cargo, 'search', '--registry', 'cratectl', '--limit', '1', ROOT_PACKAGE,
                       cwd=consumer, environment=search_env)
        return text

    version = '1.10.0'
    version_project = work/'cargo-root-new-version'
    new_project(version_project, ROOT_PACKAGE, version=version)
    version_target = version_project/'target'
    with ThreadPoolExecutor(max_workers=1) as executor:
        publication = executor.submit(call, 'cargo-publish-next-version', cargo, 'publish', '--registry',
                                      'cratectl', '--allow-dirty', '--no-verify', cwd=version_project,
                                      environment=dict(publisher, CARGO_TARGET_DIR=str(version_target)), timeout=85)
        for attempt in range(60):
            rows = api(f'cargo-await-new-version-{attempt}', repo+'/artifacts')['items']
            next_version = next((r for r in rows if r['metadata'].get('vers') == version
                                 and r['metadata'].get('name') == ROOT_PACKAGE), None)
            if next_version is not None:
                break
            if publication.done():
                publication.result()
            time.sleep(.16)
        if next_version is None:
            raise ValueError('stock publish did not stage the next version')
        check('stock Cargo search excludes a newer unassessed version and prints the approved description',
              next_version['decision'] == 'unassessed' and f'{ROOT_PACKAGE} = "1.0.0"' in stock_search('cargo-search-pending')
              and json.loads(request(search_endpoint, reader)[1])['crates'] ==
              [{'name': ROOT_PACKAGE, 'max_version': VERSION, 'description': 'cratectl inert fixture'}])
        api('cargo-approve-next-version', repo+'/decisions', 'PUT',
            {'path': next_version['path'], 'digest': next_version['digest'], 'decision': 'allowed'})
        publication.result()
    version_archive = version_target/'package'/'tmp-crate'/f'{ROOT_PACKAGE}-{version}.crate'
    index_versions = [json.loads(line) for line in request(index(ROOT_PACKAGE), reader)[1].splitlines()]
    check('stock Cargo search selects the newer approved authentic release',
          f'{ROOT_PACKAGE} = "{version}"' in stock_search('cargo-search-approved')
          and {v['vers']: v['cksum'] for v in index_versions} ==
          {VERSION: sha(published[ROOT_PACKAGE]), version: sha(version_archive)}
          and next_version['digest'] == sha(version_archive))
    next_yank = (cargo, 'yank', '--registry', 'cratectl', '--version', version, ROOT_PACKAGE)
    call('stock-cargo-yank-new-version', *next_yank, cwd=version_project, environment=publisher)
    check('stock Cargo search falls back to the preceding release while the latest is yanked',
          f'{ROOT_PACKAGE} = "{VERSION}"' in stock_search('cargo-search-yanked-latest'))
    call('stock-cargo-unyank-new-version', *next_yank, '--undo', cwd=version_project, environment=publisher)
    check('protected download still honors both grant revocation and tenant binding',
          request(download, other)[0] == 404 and request(download, reader)[0] == 200)
    api('cargo-revoke-grant', repo+'/grants', 'PUT', {'actor': 'cratectl-reader', 'read': False, 'write': False})
    check('revoked grant refuses current index and direct download even with a populated client cache',
          request(index(ROOT_PACKAGE), reader)[0] == request(download, reader)[0] == 403)
    api('cargo-revoke-writer', repo+'/grants', 'PUT', {'actor': 'cratectl-writer', 'read': True, 'write': False})
    check('revoked writer cannot replay publication or change yank state',
          request(new_crate, writer, frame, 'PUT')[0] == 403
          and request(package_endpoint+'/yank', writer, method='DELETE')[0] == 403)
    archives = {name: sha(archive) for name, archive in published.items()}
    archives[ROOT_PACKAGE + '-' + version] = sha(version_archive)
    return {'cargo': cargo_version, 'cargo_sha256': sha(cargo), 'rustc_sha256': sha(rustc), 'checks': checks,
            'archive_sha256': archives}
