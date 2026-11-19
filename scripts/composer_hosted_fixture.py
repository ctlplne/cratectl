# SPDX-License-Identifier: BUSL-1.1
"""Exercise exact hosted ZIP installation with a pinned stock Composer PHAR."""

import hashlib
import io
import json
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import zipfile

COMPOSER_VERSION = '2.11.2'
COMPOSER_SHA256 = 'dd158c0afd41d15fac89e1b4e47b5d42911fe316c3687cd5edac98319b25d028'
REPO = 'cratectl-composer-stock'
APP = 'cratectl/composer-app'
LIBRARY = 'cratectl/composer-lib'
COORDINATES = ((APP, '1.3.0'), (APP, '1.4.0'), (LIBRARY, '1.9.0'), (LIBRARY, '2.1.0'))
SELECTED = ((APP, '1.4.0'), (LIBRARY, '2.1.0'))
DEVELOPMENT = ((APP, 'dev-fixture'), (LIBRARY, 'dev-fixture'))
PRERELEASE = ((APP, '1.5.0-rc1'), (LIBRARY, '2.1.0'))
EXTRA_COORDINATES = (*DEVELOPMENT, PRERELEASE[0])


def make_archive(package, version, payload, *, description=''):
    metadata = {'name': package, 'version': version, 'type': 'library',
                'autoload': {'psr-4': {'Cratectl\\Fixture\\': 'src/'}}}
    if package == APP:
        metadata['require'] = {LIBRARY: 'dev-fixture' if version.startswith('dev-') else '^2.1'}
    if description:
        metadata['description'] = description
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path, data in (('composer.json', json.dumps(metadata, sort_keys=True).encode()), ('src/owned.txt', payload)):
            entry = zipfile.ZipInfo('cratectl-composer-fixture/' + path, date_time=(2026, 11, 19, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
    return buffer.getvalue()


def stock_install(target, project, stock, environment, run, lock=None):
    target.mkdir(mode=0o700)
    (target / 'composer.json').write_text(json.dumps(project) + '\n')
    lock_path = target / 'composer.lock'
    if lock is not None:
        lock_path.write_bytes(lock)
    sandbox = {**environment, 'COMPOSER_CACHE_DIR': str(target / 'cache')}
    operation = 'update' if lock is None else 'install'
    code, output = run('composer-' + target.name, *stock, operation, '--prefer-dist', '--no-progress', '--no-autoloader',
                       cwd=target, environment=sandbox, status=None, timeout=80)
    return code, output, lock_path


def evaluate_hosted_composer(work, installation, authority, environment, call, api, restart, sha, php, phar, *, grouped=False, versions=False):
    repository = REPO + '-group' if grouped else REPO
    scope = work / repository
    scope.mkdir(mode=0o700)
    checks = []

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    def run(label, *command, **options):
        return call(('group-' if grouped else '') + label, *command, **options)

    def manage(label, *parameters):
        return api(('group-' if grouped else '') + label, *parameters)

    check('the stock Composer PHAR matches the pinned publisher digest', sha(phar) == COMPOSER_SHA256)
    runtime = run('composer-php-version', php, '-r', 'echo PHP_VERSION;', cwd=scope)[1].strip()
    private_home = scope / 'home'
    private_home.mkdir(mode=0o700)
    env = {key: value for key, value in environment.items() if not key.startswith('COMPOSER')}
    env.update(COMPOSER_HOME=str(private_home), COMPOSER_CAFILE=str(installation / 'ca.crt'),
               COMPOSER_NO_INTERACTION='1', COMPOSER_ALLOW_SUPERUSER='0')
    stock = [php, phar, '--no-interaction', '--no-ansi', '--no-scripts', '--no-plugins']
    version = run('composer-version', *stock, '--version', cwd=scope, environment=env)[1]
    check('the native PHP runtime executes the pinned Composer version',
          re.fullmatch(r'8\.[0-9]{1,2}\.[0-9]{1,3}', runtime) is not None
          and f'Composer version {COMPOSER_VERSION} ' in version)

    management = '/api/v1/repositories/'
    route = f'/composer/{repository}/'
    base = authority + route
    sources = {APP: repository, LIBRARY: repository}
    config = {'format': 'composer', 'access': 'restricted', 'require_review': True}
    if grouped:
        sources = {APP: REPO + '-preferred', LIBRARY: REPO + '-lower'}
        for label, source in sources.items():
            manage('create-' + label.split('/')[1], management.rstrip('/'), 'POST', {**config, 'name': source})
        config.update(mode='group', settings={'members': list(sources.values())})
    manage('composer-create', management.rstrip('/'), 'POST', {**config, 'name': repository})
    tokens = {'admin': (installation / 'admin.token').read_text().strip(),
              'reader': (work / 'reader.token').read_text().strip(),
              'other': (work / 'other.token').read_text().strip()}
    trust = ssl.create_default_context(cafile=str(installation / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))

    def request(path, who='reader', method='GET', raw=None, *, source=repository):
        url = f'{authority}/composer/{source}/{path}'
        headers = {'Authorization': 'Bearer ' + tokens[who]}
        if raw is not None:
            headers['Content-Type'] = 'application/zip'
        req = urllib.request.Request(url, data=raw, headers=headers, method=method)
        try:
            with opener.open(req, timeout=10) as response:
                body = response.read((2 << 20) + 1)
                if response.url != url or len(body) > 2 << 20:
                    raise ValueError('owned Composer fixture response exceeded its bounds')
                return response.status, body
        except urllib.error.HTTPError as error:
            with error:
                return error.code, b''

    check('repository metadata requires the current scoped grant',
          request('packages.json')[0] == 403 and request('packages.json', 'other')[0] == 404)
    for source in dict.fromkeys((repository, *sources.values())):
        manage('grant-' + source, management + source + '/grants', 'PUT', {'actor': 'cratectl-reader', 'read': True, 'write': False})

    def locator(item):
        return item['path'] + '?sha256=' + item['sha256'] if grouped else item['path']

    def distribution(item):
        return {'type': 'zip', 'url': base + locator(item), 'reference': item['sha256'], 'shasum': item['sha1']}

    packages = {}

    def publish(name, ver):
        content = f'Owned inert distribution for {name} {ver}.\n'.encode()
        data = make_archive(name, ver, content)
        path = f'dist/{name}/{ver}.zip'
        packages[name, ver] = {'path': path, 'bytes': data, 'content': content,
                               'source': sources[name],
                               'sha256': hashlib.sha256(data).hexdigest(), 'sha1': hashlib.sha1(data).hexdigest()}
        if request(path, 'admin', 'PUT', data, source=sources[name])[0] != 201:
            raise ValueError('owned Composer ZIP publication failed')

    for name, ver in COORDINATES:
        publish(name, ver)
    check('the four owned stable ZIP coordinates publish unchanged', len(packages) == 4)
    selected = packages[SELECTED[0]]
    check('unknown manifests and changed immutable coordinates are refused',
          request('dist/cratectl/wrong/1.4.0.zip', 'admin', 'PUT', selected['bytes'], source=sources[APP])[0] == 400 and
          request(selected['path'], 'admin', 'PUT', make_archive(APP, '1.4.0', b'Owned different bytes.'), source=sources[APP])[0] == 409)
    check('unreviewed distributions remain hidden from Composer',
          request('p2/' + APP + '.json')[0] == 404 and request(locator(selected))[0] == 403)

    def decide(label, item, decision):
        manage('composer-review-' + label, management + item['source'] + '/decisions', 'PUT',
               {'path': item['path'], 'digest': item['sha256'], 'decision': decision})

    for number, item in enumerate(packages.values()):
        decide(str(number), item, 'allowed')
    if grouped:
        alternate = make_archive(APP, '1.4.0', b'Owned alternative lower member bytes.\n')
        collision = {'path': selected['path'], 'sha256': hashlib.sha256(alternate).hexdigest(), 'source': sources[LIBRARY]}
        if request(collision['path'], 'admin', 'PUT', alternate, source=collision['source'])[0] != 201:
            raise ValueError('owned lower Composer collision publication failed')
        decide('collision', collision, 'allowed')
        check('the read-only group requires digest-pinned downloads from the first owning member',
              request(collision['path'], source=collision['source']) == (200, alternate) and
              request(collision['path'], 'admin', 'PUT', alternate)[0] == 405 and
              request(collision['path'])[0] == 400 and request(locator(collision))[0] == 409)
    root_status, root = request('packages.json')
    app_status, metadata = request('p2/' + APP + '.json')
    check('Composer v2 advertises exact approved archive identities and native dependencies',
          root_status == app_status == 200 and json.loads(root)['metadata-url'] == route + 'p2/%package%.json'
          and {row['version']: row['dist'] for row in json.loads(metadata)['packages'][APP]} == {
              version: distribution(item)
              for (name, version), item in packages.items() if name == APP}
          and all(row['require'] == {LIBRARY: '^2.1'} for row in json.loads(metadata)['packages'][APP]))
    check('the registry delivers each original ZIP under current review',
          all(request(locator(item)) == (200, item['bytes']) for item in packages.values()))
    env['COMPOSER_AUTH'] = json.dumps({'http-basic': {urlsplit(authority).netloc:
                                         {'username': 'token', 'password': tokens['reader']}}})
    project = {'name': 'cratectl/owned-composer-consumer', 'require': {APP: '^1.3'},
               'repositories': [{'type': 'composer', 'url': base}, {'packagist.org': False}],
               'config': {'preferred-install': 'dist', 'allow-plugins': False}}

    def consume(label, lock=None, *, denied=None, graph=SELECTED, stability=None):
        target = scope / label
        config = project if stability is None else {**project, 'require': {APP: graph[0][1]}, 'minimum-stability': stability}
        cache = target / 'cache'
        operation = 'update' if lock is None else 'install'
        code, output, lock_path = stock_install(target, config, stock, env, run, lock)
        if denied is not None:
            check(denied, code != 0 and '403' in output and '/dist/' in output)
            return None
        if code != 0:
            markers = ('401', '403', '404', 'certificate', 'checksum', 'could not be resolved', 'requires', 'transport')
            seen = ', '.join(marker for marker in markers if marker in output) or 'client failure'
            raise ValueError(f'Composer {operation} returned {code} ({seen})')
        raw = lock_path.read_bytes()
        resolved = {row['name']: (row['version'], row['dist']) for row in json.loads(raw)['packages']}
        check('stock Composer selects and locks the exact scoped dependency graph ' + label,
              set(resolved) == {name for name, _ in graph} and
              all(resolved[name] == (ver, distribution(packages[name, ver]))
                  for name, ver in graph))
        check('stock Composer caches exact ZIPs and installs their inert contents ' + label,
              {sha(path) for path in (cache / 'files').rglob('*.zip')} == {packages[key]['sha256'] for key in graph}
              and all((target / 'vendor' / name / 'src/owned.txt').read_bytes() == packages[name, ver]['content']
                      for name, ver in graph))
        return raw

    locked = consume('first')
    restart()
    check('the native lockfile stays byte-identical after service restart', consume('after-restart', locked) == locked)
    decide('denied', selected, 'denied')
    check('policy removes the denied version and refuses direct retrieval',
          request(locator(selected))[0] == 403 and
          {row['version'] for row in json.loads(request('p2/' + APP + '.json')[1])['packages'][APP]} == {'1.3.0'})
    consume('denied-lock', locked, denied='stock Composer refuses to install a newly denied locked archive')
    report = {'checks': checks, 'composer_version': COMPOSER_VERSION, 'composer_sha256': COMPOSER_SHA256, 'php_version': runtime,
              'archive_sha256': {f'{name}@{version}': data['sha256'] for (name, version), data in packages.items()},
              'lock_sha256': hashlib.sha256(locked).hexdigest()}
    if grouped:
        check('the currently denied preferred archive prevents fallback to the lower member',
              request(collision['path'], source=collision['source']) == (200, alternate) and
              request(locator(collision))[0] == 403)
        report['collision_sha256'] = collision['sha256']
    if versions:
        baseline = len(checks)
        for name, ver in EXTRA_COORDINATES:
            publish(name, ver)
            decide(ver + '-' + name.split('/')[1], packages[name, ver], 'allowed')
        status, tagged_raw = request('p2/' + APP + '.json')
        dev_status, dev_raw = request('p2/' + APP + '~dev.json')
        check('Composer metadata keeps named development versions separate from numbered prereleases',
              status == dev_status == 200 and
              {(row['version'], row['version_normalized']) for row in json.loads(tagged_raw)['packages'][APP]} ==
              {('1.3.0', '1.3.0.0'), ('1.5.0-rc1', '1.5.0.0-RC1')} and
              [(row['version'], row['version_normalized']) for row in json.loads(dev_raw)['packages'][APP]] ==
              [('dev-fixture', 'dev-fixture')])
        dev_lock = consume('development', graph=DEVELOPMENT, stability='dev')
        rc_lock = consume('prerelease', graph=PRERELEASE, stability='RC')
        restart()
        check('the development lockfile stays byte-identical after service restart',
              consume('development-after-restart', dev_lock, graph=DEVELOPMENT, stability='dev') == dev_lock)
        dev_archive = packages[DEVELOPMENT[0]]
        decide('denied-development', dev_archive, 'denied')
        check('current policy removes only the denied development archive from discovery',
              request('p2/' + APP + '~dev.json')[0] == 404 and request(locator(dev_archive))[0] == 403
              and request('p2/' + APP + '.json')[0] == 200)
        consume('denied-development', dev_lock, graph=DEVELOPMENT, stability='dev',
                denied='stock Composer refuses to install a newly denied development archive')
        report['checks'] = checks[:baseline]
        report['version_forms'] = {'checks': checks[baseline:],
                                   'archive_sha256': {f'{name}@{ver}': packages[name, ver]['sha256'] for name, ver in EXTRA_COORDINATES},
                                   'development_lock_sha256': hashlib.sha256(dev_lock).hexdigest(),
                                   'prerelease_lock_sha256': hashlib.sha256(rc_lock).hexdigest()}
    return report
