# SPDX-License-Identifier: BUSL-1.1
"""Replay stock Composer against a governed digest-bound proxy."""

import hashlib
import json
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from cargo_proxy_fixture import origin_server
from composer_hosted_fixture import APP, LIBRARY, SELECTED, make_archive, stock_install

CATALOG_PATH = '/cratectl-composer-origin/catalog/'
ARCHIVE_PATH = '/cratectl-composer-origin/archives/'
ORIGIN = 'http://[::1]:38443'
CATALOG_ORIGIN = ORIGIN + CATALOG_PATH
ARCHIVE_ORIGIN = ORIGIN + ARCHIVE_PATH
REPOSITORY = 'cratectl-composer-checksum-proxy'


def evaluate_composer_proxy(work, installation, authority, environment, call, api, restart, sha, php, phar, credentials):
    scope = work / REPOSITORY
    scope.mkdir(mode=0o700)
    home = scope / 'home'
    home.mkdir(mode=0o700)
    checks = []

    def check(label, accepted):
        if not accepted:
            raise ValueError(label)
        checks.append(label)

    route = f'/composer/{REPOSITORY}/'
    management = f'/api/v1/repositories/{REPOSITORY}'
    policies = {'networks': ['::1/128'], 'authentication': 'bearer'}
    api('composer-proxy-create', '/api/v1/repositories', 'POST', {
        'name': REPOSITORY, 'format': 'composer', 'mode': 'proxy', 'access': 'restricted', 'require_review': True,
        'settings': {'upstream': {**policies, 'url': CATALOG_ORIGIN, 'credential_ref': 'cratectl-composer-index'},
                     'download_sources': [{**policies, 'url': ARCHIVE_ORIGIN, 'credential_ref': 'cratectl-composer-download'}],
                     'cache': {'fresh_seconds': 300, 'negative_seconds': 30, 'require_checksum': True}},
    })
    tokens = {name: (work / (name + '.token')).read_text().strip() for name in ('reader', 'other')}
    env = {key: value for key, value in environment.items() if not key.startswith('COMPOSER')}
    env.update(COMPOSER_HOME=str(home), COMPOSER_CAFILE=str(installation / 'ca.crt'), COMPOSER_NO_INTERACTION='1',
               COMPOSER_AUTH=json.dumps({'http-basic': {urlsplit(authority).netloc: {'username': 'token', 'password': tokens['reader']}}}))
    stock = [php, phar, '--no-interaction', '--no-ansi', '--no-scripts', '--no-plugins']
    project = {'name': 'cratectl/controlled-composer-proxy-consumer', 'require': {APP: '^1.3'},
               'repositories': [{'type': 'composer', 'url': authority + route}, {'packagist.org': False}],
               'config': {'preferred-install': 'dist', 'allow-plugins': False}}
    trust = ssl.create_default_context(cafile=str(installation / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))

    def request(relative, who='reader', force=False):
        url = authority + route + relative
        headers = {'Authorization': 'Bearer ' + tokens[who]}
        if force:
            headers['Cache-Control'] = 'no-cache'
        req = urllib.request.Request(url, headers=headers)
        try:
            with opener.open(req, timeout=10) as response:
                data = response.read((2 << 20) + 1)
                if response.url != url or len(data) > 2 << 20:
                    raise ValueError('owned Composer proxy response exceeded its bounds')
                return response.status, data
        except urllib.error.HTTPError as error:
            with error:
                return error.code, b''

    def run(label, *args, **options):
        return call('proxy-' + label, *args, **options)

    contents, entries = {}, {}
    for name, version in SELECTED:
        prefix, artifact = name.split('/', 1)
        content = f'Owned Composer proxy bytes for {name} {version}.\n'.encode()
        zipped = make_archive(name, version, content)
        digest = hashlib.sha256(zipped).hexdigest()
        legacy = hashlib.sha1(zipped).hexdigest()
        upstream = f'{artifact}/{version}.zip'
        relative = f'dist/{name}/{version}.zip?sha256={digest}'
        package_metadata = {'name': name, 'version': version, 'type': 'library',
                            'autoload': {'psr-4': {'Cratectl\\Fixture\\': 'src/'}}}
        if name == APP:
            package_metadata['require'] = {LIBRARY: '^2.1'}
        package_metadata['dist'] = {'type': 'zip', 'url': ARCHIVE_ORIGIN + upstream, 'shasum': legacy, 'sha256': digest}
        key = CATALOG_PATH + 'p2/' + prefix + '/' + artifact + '.json'
        contents[key] = json.dumps({'minified': 'composer/2.0', 'packages': {name: [package_metadata]}}).encode()
        contents[ARCHIVE_PATH + upstream] = zipped
        entries[name] = {'version': version, 'sha256': digest, 'sha1': legacy, 'relative': relative, 'content': content,
                         'retained': f'composer-cache/{digest}/dist/{name}/{version}.zip',
                         'upstream_metadata': package_metadata, 'upstream_catalog_path': key}

    def decide(label, entry, decision):
        api('composer-proxy-review-' + label, management + '/decisions', 'PUT',
            {'path': entry['retained'], 'digest': entry['sha256'], 'decision': decision})

    def consume(label, lock=None, *, denied=False):
        target = scope / label
        code, output, lock_path = stock_install(target, project, stock, env, run, lock)
        if denied:
            check('stock Composer refuses a locked proxy archive after digest denial', code != 0 and '403' in output and '/dist/' in output)
            return None
        if code != 0:
            markers = ('401', '403', '404', '502', 'certificate', 'transport', 'could not be resolved')
            observed = ', '.join(marker for marker in markers if marker in output) or 'client failure'
            raise ValueError(f'stock Composer proxy {label} returned {code} ({observed})')
        raw = lock_path.read_bytes()
        dependencies = {row['name']: row for row in json.loads(raw)['packages']}
        check('stock Composer locks the exact approved proxy dependency graph ' + label,
              set(dependencies) == set(entries) and all(
                  dependencies[name]['version'] == entry['version'] and dependencies[name]['dist'] ==
                  {'type': 'zip', 'url': authority + route + entry['relative'], 'reference': entry['sha256'], 'shasum': entry['sha1']}
                  for name, entry in entries.items()))
        check('stock Composer installs the exact proxy ZIPs and inert files ' + label,
              {sha(path) for path in (target / 'cache/files').rglob('*.zip')} == {row['sha256'] for row in entries.values()}
              and all((target / 'vendor' / name / 'src/owned.txt').read_bytes() == entry['content'] for name, entry in entries.items()))
        return raw

    origin_credentials = {label: 'Bearer ' + token for label, token in credentials.items()}
    with origin_server(origin_credentials, contents, index_path=CATALOG_PATH, name='cratectl-composer-origin') as controls:
        requests, mutex, offline, _, _ = controls
        check('restricted Composer proxy requires an explicit reader grant before upstream access',
              request('p2/' + APP + '.json')[0] == 403 and request('p2/' + APP + '.json', 'other')[0] == 404 and not requests)
        api('composer-proxy-grant', management + '/grants', 'PUT', {'actor': 'cratectl-reader', 'read': True, 'write': False})
        check('the repository hides unassessed metadata and gates exact archive intake',
              all(request('p2/' + name + '.json')[0] == 404 and request(entry['relative'])[0] == 403 for name, entry in entries.items()))
        with mutex:
            observed = list(requests)
        check('metadata and archives use separate approved credential scopes',
              len(observed) == 4 and all(authorized for _, authorized, _ in observed)
              and sum(path.startswith(CATALOG_PATH) for path, _, _ in observed) == 2
              and sum(path.startswith(ARCHIVE_PATH) for path, _, _ in observed) == 2)
        for position, entry in enumerate(entries.values()):
            decide(str(position), entry, 'allowed')
        check('reviewed discovery emits the local immutable distribution locators',
              all((authority + route + entry['relative']).encode() in request('p2/' + name + '.json')[1]
                  for name, entry in entries.items()) and request(entries[APP]['relative'].split('?')[0])[0] == 400)
        locked = consume('first')
        offline.set()
        restart()
        check('the locked graph installs after restart with the origin offline and zero further requests',
              consume('after-restart', locked) == locked and requests == observed)
        decide('denied-app', entries[APP], 'denied')
        check('current app denial hides its metadata while the dependency remains indexed',
              request('p2/' + APP + '.json')[0] == 404 and request('p2/' + LIBRARY + '.json')[0] == 200 and requests == observed)
        consume('denied', locked, denied=True)
        offline.clear()
        moved = entries[APP]
        with mutex:
            metadata = dict(moved['upstream_metadata'])
            metadata['dist'] = {**metadata['dist'], 'url': ORIGIN + '/cratectl-composer-unapproved/moved.zip'}
            contents[moved['upstream_catalog_path']] = json.dumps({'packages': {APP: [metadata]}}).encode()
        check('an advertised archive move outside approved authority stops metadata before a download',
              request('p2/' + APP + '.json', force=True)[0] == 502 and len(requests) == len(observed) + 1
              and requests[-1][0] == moved['upstream_catalog_path'] and requests[-1][1] is True)
    return {'checks': checks, 'archive_sha256': {name: entry['sha256'] for name, entry in entries.items()},
            'lock_sha256': hashlib.sha256(locked).hexdigest()}
