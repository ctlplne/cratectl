# SPDX-License-Identifier: BUSL-1.1
"""Replay stock Composer full text search and package-name discovery."""

import hashlib
import json
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from composer_hosted_fixture import make_archive

REPOSITORY = 'cratectl-composer-discovery'
MATCH = 'cratectl/discovery-tools'
NEIGHBOR = 'cratectl/discovery_tools'
HIDDEN = 'cratectl/discovery-hidden'
DESCRIPTION = 'Owned telescope utility for staged releases'


def evaluate_composer_search(work, installation, authority, environment, call, api, restart, php, phar):
    scope = work / REPOSITORY
    scope.mkdir(mode=0o700)
    home = scope / 'home'
    home.mkdir(mode=0o700)
    checks = []

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    route = f'/composer/{REPOSITORY}/'
    management = '/api/v1/repositories/' + REPOSITORY
    tokens = {'admin': (installation / 'admin.token').read_text().strip(),
              'reader': (work / 'reader.token').read_text().strip(),
              'other': (work / 'other.token').read_text().strip()}
    trust = ssl.create_default_context(cafile=str(installation / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))

    def request(relative, role='reader', contents=None):
        url = authority + route + relative
        req = urllib.request.Request(url, data=contents, method='PUT' if contents is not None else 'GET',
                                     headers={'Authorization': 'Bearer ' + tokens[role]})
        try:
            with opener.open(req, timeout=10) as response:
                data = response.read((2 << 20) + 1)
                if response.url != url or len(data) > 2 << 20:
                    raise ValueError('owned Composer discovery response exceeded its bounds')
                return response.status, data
        except urllib.error.HTTPError as error:
            with error:
                return error.code, b''

    api('composer-search-create', '/api/v1/repositories', 'POST',
        {'name': REPOSITORY, 'format': 'composer', 'access': 'restricted', 'require_review': True})
    check('Composer hosted discovery requires current repository and tenant access',
          request('search.json?q=telescope')[0] == 403 and request('list.json', 'other')[0] == 404)
    api('composer-search-grant', management + '/grants', 'PUT', {'actor': 'cratectl-reader', 'read': True, 'write': False})

    packages = {}
    for name, description in ((MATCH, DESCRIPTION), (NEIGHBOR, 'Owned plain archive example'), (HIDDEN, DESCRIPTION)):
        path = f'dist/{name}/1.0.0.zip'
        archive = make_archive(name, '1.0.0', f'Owned discovery byte fixture for {name}.\n'.encode(), description=description)
        if request(path, 'admin', archive)[0] != 201:
            raise ValueError('owned Composer search ZIP publication failed')
        digest = hashlib.sha256(archive).hexdigest()
        packages[name] = (path, digest)
        if name != HIDDEN:
            api('composer-search-allow-' + name.split('/')[1], management + '/decisions', 'PUT',
                {'path': path, 'digest': digest, 'decision': 'allowed'})

    env = {key: value for key, value in environment.items() if not key.startswith('COMPOSER')}
    env.update(COMPOSER_HOME=str(home), COMPOSER_CAFILE=str(installation / 'ca.crt'), COMPOSER_NO_INTERACTION='1',
               COMPOSER_AUTH=json.dumps({'http-basic': {urlsplit(authority).netloc: {'username': 'token', 'password': tokens['reader']}}}))
    stock = [php, phar, '--no-interaction', '--no-ansi', '--no-scripts', '--no-plugins', '--no-cache']
    project = {'name': 'cratectl/owned-composer-discovery-consumer', 'version': '1.0.0',
               'repositories': [{'type': 'composer', 'url': authority + route}, {'packagist.org': False}],
               'config': {'allow-plugins': False}}
    (scope / 'composer.json').write_text(json.dumps(project) + '\n')

    def search(label, *terms, options=()):
        _, output = call('composer-search-' + label, *stock, 'search', '--format=json', *options, *terms, cwd=scope, environment=env)
        rows = json.loads(output)
        if type(rows) is not list or any(type(row) is not dict or not isinstance(row.get('name'), str) for row in rows):
            raise ValueError('stock Composer returned an unexpected search result shape')
        return rows

    matches = search('text', 'telescope', 'utility', options=('--type=library',))
    check('stock Composer full text search uses the inspected archive description and current policy',
          [row['name'] for row in matches] == [MATCH] and matches[0].get('description') == DESCRIPTION)
    names = search('names', 'discovery', options=('--only-name',))
    check('stock Composer name search uses the governed native package list',
          {row['name'] for row in names} == {MATCH, NEIGHBOR} and len(names) == 2)
    check('Composer list wildcards preserve the literal underscore in an owned package name',
          request('list.json?filter=cratectl%2Fdiscovery_*') == (200, json.dumps({'packageNames': [NEIGHBOR]}, separators=(',', ':')).encode()))
    check('stock Composer package type search excludes unsupported package kinds',
          search('wrong-type', 'telescope', options=('--type=composer-plugin',)) == [])
    path, digest = packages[MATCH]
    api('composer-search-deny', management + '/decisions', 'PUT', {'path': path, 'digest': digest, 'decision': 'denied'})
    restart()
    check('fresh stock Composer discovery suppresses the revoked package after restart',
          search('after-restart', 'telescope') == []
          and [row['name'] for row in search('names-after-restart', 'discovery', options=('--only-name',))] == [NEIGHBOR])
    return {'checks': checks, 'archive_sha256': {name: item[1] for name, item in packages.items()}}
