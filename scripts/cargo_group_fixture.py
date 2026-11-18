# SPDX-License-Identifier: BUSL-1.1
"""Stock Cargo resolution through explicitly ordered hosted sources."""
import json
import ssl
import urllib.error
import urllib.request

from cargo_hosted_fixture import VERSION, cargo_home, new_project, stock_cargo_environment


FIRST, LOW, GROUP, EXPLICIT = ('cratectl-cargo-first', 'cratectl-cargo-lower',
                               'cratectl-cargo-group', 'cratectl-cargo-explicit')
SHARED = 'cratectl-cargo-group-unit'
LOW_ONLY = 'cratectl-cargo-group-lower-only'


def evaluate_groups(work, installation, authority, toolchain, environment, call, api, restart, sha):
    cargo = toolchain / 'cargo'
    shared = stock_cargo_environment(installation, toolchain / 'rustc', environment)
    admin = (installation / 'admin.token').read_text().strip()
    reader = (work / 'reader.token').read_text().strip()
    checks = []
    trust = ssl.create_default_context(cafile=str(installation / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))

    def check(label, passed):
        if not passed:
            raise ValueError(label)
        checks.append(label)

    def management(repo, suffix=''):
        return '/api/v1/repositories/' + repo + suffix

    def endpoint(repo, suffix=''):
        return authority + '/cargo/' + repo + suffix

    def access(label, repo, read):
        api(label, management(repo, '/grants'), 'PUT', {'actor': 'cratectl-reader', 'read': read, 'write': False})

    def request(repo, suffix, token=reader, method='GET'):
        headers = {} if token is None else {'Authorization': token}
        req = urllib.request.Request(endpoint(repo, suffix), headers=headers, method=method)
        try:
            with opener.open(req, timeout=10) as reply:
                data = reply.read((1 << 20) + 1)
                if len(data) > 1 << 20:
                    raise ValueError('Cargo group fixture response exceeds its byte budget')
                return reply.status, data
        except urllib.error.HTTPError as err:
            err.close()
            return err.code, b''

    def index(name):
        return '/index/' + name[:2] + '/' + name[2:4] + '/' + name

    def download(name):
        return '/download/' + name + '/' + VERSION

    for label, repo in (('first', FIRST), ('lower', LOW)):
        api('cargo-group-create-'+label, '/api/v1/repositories', 'POST',
            {'name': repo, 'format': 'cargo', 'access': 'restricted', 'require_review': False})
        access('cargo-group-reader-'+label, repo, True)
    for label, repo, settings in (
        ('ordered', GROUP, {'members': [FIRST, LOW]}),
        ('explicit', EXPLICIT, {'members': [FIRST, LOW], 'namespace_owners': {SHARED+'/': LOW}}),
    ):
        api('cargo-group-create-'+label, '/api/v1/repositories', 'POST',
            {'name': repo, 'format': 'cargo', 'mode': 'group', 'require_review': False,
             'access': 'restricted', 'settings': settings})
        access('cargo-group-reader-'+label, repo, True)

    def publish(label, repo, name):
        project = work/('cargo-group-publish-'+label)
        new_project(project, name)
        (project/'src/lib.rs').write_text('// Owned source bytes for '+label+'.\n')
        target = project/'target'
        _, env = cargo_home(work, 'cargo-group-publisher-'+label, 'sparse+'+endpoint(repo, '/index/'), shared, admin)
        call('stock-cargo-group-publish-'+label, cargo, 'publish', '--registry', 'cratectl', '--allow-dirty', '--no-verify',
             cwd=project, environment=dict(env, CARGO_TARGET_DIR=str(target)), timeout=85)
        return target/'package'/'tmp-crate'/f'{name}-{VERSION}.crate'

    preferred = publish('preferred', FIRST, SHARED)
    lower = publish('duplicate', LOW, SHARED)
    lower_only = publish('lower-only', LOW, LOW_ONLY)
    check('Cargo group config advertises authenticated reads and rejects publication',
          request(GROUP, '/index/config.json', None)[0] == 401
          and json.loads(request(GROUP, '/index/config.json')[1]) ==
          {'dl': endpoint(GROUP, '/download/{crate}/{version}'), 'auth-required': True}
          and request(GROUP, '/api/v1/crates/new', admin, 'PUT')[0] == 405 and sha(preferred) != sha(lower))

    def fetch(label, repo, name, expected=0):
        project = work/('cargo-group-consumer-'+label)
        new_project(project, 'cratectl-group-consumer', '\n[dependencies]\n'+name+
                    ' = {version = "=1.0.0", registry = "cratectl"}\n')
        cache, env = cargo_home(work, 'cargo-group-home-'+label, 'sparse+'+endpoint(repo, '/index/'), shared, reader)
        _, output = call('stock-cargo-group-fetch-'+label, cargo, 'fetch', cwd=project, environment=env, status=expected)
        archives = list((cache/'registry/cache').glob('*/*.crate'))
        return output, [sha(a) for a in archives]

    api('cargo-group-primary-review', management(FIRST, '/policy'), 'PUT', {'require_review': True})
    denied, denied_archives = fetch('pending', GROUP, SHARED, expected=101)
    check('first unassessed crate fences a lower duplicate for both index and stock resolution',
          request(GROUP, index(SHARED))[0] == 404 and request(GROUP, download(SHARED))[0] == 403
          and 'no matching package named' in denied and not denied_archives
          and request(LOW, download(SHARED))[1] == lower.read_bytes())
    check('stock Cargo selects the lower source for a name absent from the first member',
          fetch('absent', GROUP, LOW_ONLY)[1] == [sha(lower_only)])
    primary, = api('cargo-group-primary-artifact', management(FIRST, '/artifacts'))['items']
    api('cargo-group-approve-primary', management(FIRST, '/decisions'), 'PUT',
        {'path': primary['path'], 'digest': primary['digest'], 'decision': 'allowed'})
    check('stock Cargo uses the approved first source for both index and exact archive bytes',
          fetch('approved', GROUP, SHARED)[1] == [sha(preferred)]
          and json.loads(request(GROUP, index(SHARED))[1])['cksum'] == sha(preferred))
    api('cargo-group-root-review', management(GROUP, '/policy'), 'PUT', {'require_review': True})
    check('group review policy also applies when the selected member allows unassessed bytes',
          request(GROUP, index(LOW_ONLY))[0] == 404 and request(GROUP, download(LOW_ONLY))[0] == 403
          and request(LOW, download(LOW_ONLY))[0] == 200)
    access('cargo-group-remove-primary-reader', FIRST, False)
    check('loss of required member access fences the group before fallback',
          request(GROUP, index(SHARED))[0] == 403 and request(GROUP, download(SHARED))[0] == 403)
    access('cargo-group-restore-primary-reader', FIRST, True)
    life = management(FIRST, '/artifacts/lifecycle')
    reference = {key: primary[key] for key in ('path', 'digest')}
    api('cargo-group-delete-primary', life, 'PUT', {**reference, 'action': 'delete', 'expected_revision': 0,
                                                   'reason': 'Retain the preferred group reference'})
    check('retired preferred crate still fences the lower duplicate',
          request(GROUP, index(SHARED))[0] == request(GROUP, download(SHARED))[0] == 404)
    api('cargo-group-restore-primary', life, 'PUT', {**reference, 'action': 'restore', 'expected_revision': 1,
                                                    'reason': 'Restore the preferred exact bytes'})
    restart()
    check('fresh stock Cargo recovers the same preferred archive after restore and restart',
          fetch('restored', GROUP, SHARED)[1] == [sha(preferred)])
    check('an explicit namespace owner routes stock Cargo to the selected lower source',
          fetch('explicit', EXPLICIT, SHARED)[1] == [sha(lower)])
    return {'checks': checks, 'archive_sha256': {'group-preferred': sha(preferred), 'group-duplicate': sha(lower),
                                               'group-lower-only': sha(lower_only)}}
