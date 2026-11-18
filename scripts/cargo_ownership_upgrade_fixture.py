# SPDX-License-Identifier: BUSL-1.1
"""Stock Cargo ownership adoption across the reviewed schema 18 boundary."""
import json
import ssl
import urllib.request

from cargo_hosted_fixture import VERSION, cargo_home, new_project, stock_cargo_environment


BASELINE = '35c3708616c9847f6cd5636a6e86858eb82e571b'
NAME = 'cratectl-cargo-legacy'
MANAGEMENT = '/api/v1/repositories/' + NAME


def replay_legacy_cargo(work, installation, authority, toolchain, environment, call, api, upgrade, sha):
    cargo = toolchain / 'cargo'
    root = authority + '/cargo/' + NAME
    index_url = 'sparse+' + root + '/index/'
    shared = stock_cargo_environment(installation, toolchain / 'rustc', environment)
    writer = (work / 'writer.token').read_text().strip()
    maintainer = (work / 'maintainer.token').read_text().strip()
    admin = (installation / 'admin.token').read_text().strip()
    _, publish = cargo_home(work, 'legacy-publisher', index_url, shared, writer)
    _, owner = cargo_home(work, 'legacy-admin', index_url, shared, admin)
    _, unassigned = cargo_home(work, 'legacy-maintainer', index_url, shared, maintainer)
    trust = ssl.create_default_context(cafile=str(installation / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))
    checks = []

    def check(label, ok):
        if not ok:
            raise ValueError(label)
        checks.append(label)

    def read(path, token):
        request = urllib.request.Request(root + path, headers={'Authorization': token})
        with opener.open(request, timeout=10) as response:
            data = response.read((1 << 20) + 1)
            if len(data) > 1 << 20:
                raise ValueError('legacy Cargo proof exceeded its response byte budget')
            return data

    api('legacy-cargo-create', '/api/v1/repositories', 'POST',
        {'name': NAME, 'format': 'cargo', 'access': 'restricted', 'require_review': False})
    for actor in ('writer', 'maintainer'):
        api('legacy-cargo-grant-'+actor, MANAGEMENT+'/grants', 'PUT',
            {'actor': 'cratectl-'+actor, 'read': True, 'write': True})
    package = work/'legacy-cargo-package'
    new_project(package, NAME)
    target = package/'target'
    call('legacy-cargo-stock-publish', cargo, 'publish', '--registry', 'cratectl', '--allow-dirty', '--no-verify',
         cwd=package, environment=dict(publish, CARGO_TARGET_DIR=str(target)), timeout=85)
    archive = target/'package'/'tmp-crate'/f'{NAME}-{VERSION}.crate'
    digest = sha(archive)
    # Sparse index folders come from the first four lowercase name characters.
    index = '/index/' + NAME[:2] + '/' + NAME[2:4] + '/' + NAME
    original = read(index, writer)
    check('actual schema 18 stock publication binds the original archive digest', json.loads(original)['cksum'] == digest)
    journal = api('legacy-cargo-before-upgrade', '/api/v1/audit/checkpoint')
    migration = upgrade()
    check('schema 19 preserves the legacy crate index and exact tenant journal checkpoint',
          read(index, writer) == original and api('legacy-cargo-after-upgrade', '/api/v1/audit/checkpoint') == journal)
    owners = '/api/v1/crates/' + NAME + '/owners'
    yank = (cargo, 'yank', '--registry', 'cratectl', '--version', VERSION, NAME)
    check('existing crate starts without implicit ownership', json.loads(read(owners, writer))['users'] == [])
    call('legacy-cargo-writer-yank', *yank, cwd=package, environment=unassigned)
    call('legacy-cargo-writer-unyank', *yank, '--undo', cwd=package, environment=unassigned)
    check('existing repository writers retain legacy mutations before explicit adoption', read(index, writer) == original)
    owner_cmd = (cargo, 'owner', '--registry', 'cratectl', '--add', 'cratectl-writer', NAME)
    call('legacy-cargo-unowned-self-adoption-denied', *owner_cmd, cwd=package, environment=publish, status=101)
    call('legacy-cargo-admin-adopts', *owner_cmd, cwd=package, environment=owner)
    call('legacy-cargo-unowned-yank-denied', *yank, cwd=package, environment=unassigned, status=101)
    check('administrator adoption activates crate authority without altering its index',
          [o['login'] for o in json.loads(read(owners, writer))['users']] == ['cratectl-writer']
          and read(index, writer) == original)
    consumer = work/'legacy-cargo-consumer'
    new_project(consumer, 'cratectl-legacy-consumer', '\n[dependencies]\n'+NAME+
                ' = {version = "=1.0.0", registry = "cratectl"}\n')
    cache, consumer_env = cargo_home(work, 'legacy-consumer', index_url, shared, writer)
    call('legacy-cargo-stock-fetch', cargo, 'fetch', cwd=consumer, environment=consumer_env)
    matches = list((cache/'registry/cache').glob('*/*-1.0.0.crate'))
    check('fresh stock Cargo fetch after adoption preserves the exact historical bytes',
          len(matches) == 1 and sha(matches[0]) == digest)
    return {'baseline': BASELINE, 'archive_sha256': digest, 'checks': checks, 'migration': migration}
