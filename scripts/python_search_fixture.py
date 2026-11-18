# SPDX-License-Identifier: BUSL-1.1
"""Stock Twine upload and pip search on an isolated hosted index."""
import base64
import csv
import hashlib
import io
import json
import os
import urllib.parse
import zipfile

from cargo_proxy_fixture import origin_server


REPO = 'cratectl-python-search'
NAME = 'cratectl-python-search-demo'


def wheel(work, directory, version, summary, name=NAME):
    distribution = name.replace('-', '_')
    info = f'{distribution}-{version}.dist-info'
    path = work / directory
    path.mkdir()
    target = path / f'{distribution}-{version}-py3-none-any.whl'
    files = {
        f'{distribution}/__init__.py': b'# Inert hosted search fixture.\n',
        f'{info}/METADATA': f'Metadata-Version: 2.4\nName: {name}\nVersion: {version}\nSummary: {summary}\n\n'.encode(),
        f'{info}/WHEEL': b'Wheel-Version: 1.0\nGenerator: cratectl\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
    }
    rows = io.StringIO()
    writer = csv.writer(rows, lineterminator='\n')
    for filename, contents in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).rstrip(b'=').decode()
        writer.writerow((filename, 'sha256=' + digest, len(contents)))
    writer.writerow((f'{info}/RECORD', '', ''))
    files[f'{info}/RECORD'] = rows.getvalue().encode()
    with zipfile.ZipFile(target, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for filename, contents in files.items():
            archive.writestr(filename, contents)
    return target


def client_environment(environment):
    base = {key: value for key, value in environment.items() if not key.startswith(('PIP_', 'TWINE_', 'PYTHON'))}
    return dict(base, PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK='1', PIP_NO_INPUT='1', PIP_KEYRING_PROVIDER='disabled')


def reader_environment(work, label, authority, token, environment):
    netrc = work / ('python-search-' + label + '.netrc')
    host = urllib.parse.urlsplit(authority).hostname
    netrc.write_text(f'machine {host} login token password {token.read_text().strip()}\n')
    return dict(environment, NETRC=str(netrc))


def upload_wheel(label, path, python, trust, endpoint, token, environment, call, pypirc):
    twine_env = dict(environment, TWINE_USERNAME='token', TWINE_PASSWORD=token.read_text().strip())
    call('python-search-upload-' + label, python, '-I', '-m', 'twine', 'upload', '--non-interactive',
         '--disable-progress-bar', '--config-file', pypirc, '--cert', trust, '--repository-url', endpoint, path,
         environment=twine_env, timeout=40)


def pip_search(label, query, expected, python, trust, endpoint, client, call):
    return call('python-search-' + label, python, '-I', '-m', 'pip', 'search', '--index', endpoint + 'search',
                '--cert', trust, '--no-cache-dir', '--retries', '0', query, environment=client, status=expected)[1]


def evaluate_python_search(work, installation, authority, python, environment, call, api, restart, sha):
    checks = []

    def check(name, verified):
        if not verified:
            raise ValueError(name)
        checks.append(name)

    endpoint = f'{authority}/pypi/{REPO}/'
    management = '/api/v1/repositories/' + REPO
    other_config = work / 'other.json'
    for label, config in [('first', None), ('second', other_config)]:
        api('python-search-create-' + label, '/api/v1/repositories', 'POST',
            {'name': REPO, 'format': 'pypi', 'access': 'restricted', 'require_review': True}, config=config)
    grant = {'actor': 'cratectl-reader', 'read': True, 'write': False}
    api('python-search-grant', management + '/grants', 'PUT', grant)

    trust = str(installation / 'ca.crt')
    base_env = client_environment(environment)
    auth = {'writer': installation / 'admin.token', 'reader': work / 'reader.token', 'second': work / 'other.token'}
    clients = {label: reader_environment(work, label, authority, token, base_env) for label, token in auth.items()}
    pypirc = work / 'python-search.pypirc'
    pypirc.write_text('[distutils]\nindex-servers =\n')
    pip_version = call('python-search-pip-version', python, '-I', '-m', 'pip', '--version', environment=base_env)[1].split()[1]
    twine_version = call('python-search-twine-version', python, '-I', '-m', 'twine', '--version', environment=base_env)[1].split()[2]

    old_summary, new_summary = 'Differential metadata for the maintained release', 'Differential metadata for the newer release'
    other_summary = 'Differential metadata for the second tenant'
    a = wheel(work, 'python-search-old', '2.0', old_summary)
    b = wheel(work, 'python-search-new', '10.0', new_summary)
    c = wheel(work, 'python-search-other', '2.0', other_summary)
    for label, path, role in [('old', a, 'writer'), ('new', b, 'writer'), ('other', c, 'second')]:
        upload_wheel(label, path, python, trust, endpoint, auth[role], base_env, call, pypirc)

    def approve(label, path, config=None):
        api('python-search-approve-' + label, management + '/decisions', 'PUT',
            {'path': path.name, 'digest': sha(path), 'decision': 'allowed'}, config=config)

    def search(label, query, role='reader', expected=0):
        return pip_search(label, query, expected, python, trust, endpoint, clients[role], call)

    def matches(output, version, summary):
        return f'{NAME} ({version})' in output and summary in output and output.count(NAME) == 1

    pending = search('pending', NAME, expected=23)
    check('stock pip search hides hosted files awaiting review', NAME not in pending)
    approve('old', a)
    approve('other', c, other_config)
    check('stock pip normalizes the package name and returns the allowed original summary',
          matches(search('name', NAME.replace('-', '_').upper()), '2.0', old_summary))
    check('stock pip finds a package by its archive-derived summary',
          matches(search('summary', 'DIFFERENTIAL'), '2.0', old_summary))
    check('the independently authorized tenant sees its own package at the same coordinate',
          matches(search('other', NAME, role='second'), '2.0', other_summary))
    approve('new', b)
    check('stock pip search uses PEP 440 ordering for visible releases',
          matches(search('latest', NAME), '10.0', new_summary))
    api('python-search-yank', management + '/yanks', 'PUT',
        {'filename': b.name, 'yanked': True, 'reason': 'Prefer the maintained fixture version'})
    check('stock pip search only returns a release with a non-yanked visible file',
          matches(search('yanked', NAME), '2.0', old_summary))
    restart()
    downloaded = work / 'python-search-download'
    downloaded.mkdir()
    call('python-search-resolved-wheel', python, '-I', '-m', 'pip', 'download', '--index-url', endpoint + 'simple/',
         '--cert', trust, '--no-cache-dir', '--retries', '0', '--only-binary=:all:', '--no-deps',
         '--dest', downloaded, NAME + '==2.0', environment=clients['reader'])
    check('stock pip search and exact wheel download recover after restart',
          matches(search('restarted', NAME), '2.0', old_summary) and sha(downloaded / a.name) == sha(a))
    api('python-search-revoke', management + '/grants', 'PUT', {**grant, 'read': False})
    denied = search('revoked', NAME, expected=2)
    check('stock pip search respects revocation of its repository read grant',
          '403 Client Error' in denied and 'Forbidden' in denied and old_summary not in denied)
    return {'checks': checks, 'pip': pip_version, 'twine': twine_version, 'archive_sha256': [sha(path) for path in (a, b, c)]}


def evaluate_cached_python_search(work, installation, authority, python, environment, call, api, restart, sha):
    checks = []
    lower, proxy, group = ('cratectl-python-search-' + member for member in ('lower', 'proxy', 'group'))
    path = '/cratectl-python-search-origin/'
    origin = 'http://[::1]:38443' + path
    trust = str(installation / 'ca.crt')
    fallback = 'cratectl-python-search-fallback'
    version = '2.0'
    preferred_summary, lower_summary = 'Summary from the exact preferred wheel', 'Summary from the hosted fallback wheel'
    base_env = client_environment(environment)
    reader = reader_environment(work, 'cache-reader', authority, work / 'reader.token', base_env)

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    def endpoint(repo):
        return f'{authority}/pypi/{repo}/'

    def management(repo):
        return '/api/v1/repositories/' + repo

    def grant(repo, label, allowed=True):
        api('python-cache-search-grant-' + label, management(repo) + '/grants', 'PUT',
            {'actor': 'cratectl-reader', 'read': allowed, 'write': False})

    settings = {'upstream': {'url': origin + 'simple/', 'networks': ['::1/128']},
                'download_sources': [{'url': origin + 'packages/', 'networks': ['::1/128']}],
                'cache': {'fresh_seconds': 300, 'negative_seconds': 30, 'stale_seconds': 0},
                'python_index_format': 'json'}
    for repo, mode, review, configuration in (
            (lower, 'hosted', True, {}), (proxy, 'proxy', False, settings),
            (group, 'group', True, {'members': [proxy, lower]})):
        api('python-cache-search-create-' + mode, '/api/v1/repositories', 'POST',
            {'name': repo, 'format': 'pypi', 'mode': mode, 'access': 'restricted',
             'require_review': review, 'settings': configuration})
        grant(repo, mode)

    def approve(repo, label, archive):
        items = api('python-cache-search-inventory-' + label, management(repo) + '/artifacts')['items']
        artifact, = [item for item in items if item['digest'] == sha(archive) and item['metadata'].get('filename') == archive.name]
        api('python-cache-search-approve-' + label, management(repo) + '/decisions', 'PUT',
            {'path': artifact['path'], 'digest': artifact['digest'], 'decision': 'allowed'})

    for label, name in [('lower-copy', NAME), ('lower-only', fallback)]:
        archive = wheel(work, 'python-search-' + label, version, lower_summary, name=name)
        upload_wheel(label, archive, python, trust, endpoint(lower), installation / 'admin.token', base_env, call,
                     work / 'python-search.pypirc')
        approve(lower, label, archive)
    preferred = wheel(work, 'python-search-preferred', version, preferred_summary)
    catalog_path = path + 'simple/' + NAME + '/'
    package_path = path + 'packages/' + preferred.name
    document = {'meta': {'api-version': '1.1'}, 'name': NAME, 'files': [
        {'filename': preferred.name, 'url': origin + 'packages/' + preferred.name,
         'hashes': {'sha256': sha(preferred)}, 'size': preferred.stat().st_size, 'yanked': False},
    ]}
    content = {catalog_path: json.dumps(document).encode(), package_path: preferred.read_bytes()}
    media = {catalog_path: 'application/vnd.pypi.simple.v1+json', package_path: 'application/octet-stream'}

    def search(label, repo, query, expected=0):
        return pip_search('cached-' + label, query, expected, python, trust, endpoint(repo), reader, call)

    def index(label, repo, query, expected=0):
        return call('python-cache-search-index-' + label, python, '-I', '-m', 'pip', 'index', 'versions', query,
                    '--index-url', endpoint(repo) + 'simple/', '--cert', trust, '--no-cache-dir', '--retries', '0',
                    environment=reader, status=expected)[1]

    def expire(label):
        api('python-cache-search-expire-' + label, management(proxy) + '/cache', 'PUT', {'path': 'pypi-catalog/' + NAME})

    with origin_server({'index': '', 'download': ''}, content, content_types=media) as (requests, lock, _, _, _):
        absent_proxy = search('proxy-cold', proxy, NAME, expected=23)
        absent_group = search('group-cold', group, NAME, expected=23)
        check('cold Python search makes no upstream request and hides an unknown preferred source',
              NAME not in absent_proxy and NAME not in absent_group and not requests)
        index('catalog-only', proxy, NAME)
        check('Python search omits an index-only source and its lower filename collision',
              NAME not in search('group-catalog', group, NAME, expected=23))
        dest = work / 'python-cached-search-download'
        dest.mkdir()
        call('python-cache-search-fetch', python, '-I', '-m', 'pip', 'download', NAME + '==' + version,
             '--index-url', endpoint(proxy) + 'simple/', '--cert', trust, '--no-cache-dir', '--retries', '0',
             '--dest', dest, '--only-binary=:all:', '--no-deps', environment=reader)
        check('stock pip search recognizes the exact cached wheel and its embedded summary',
              sha(dest / preferred.name) == sha(preferred) and preferred_summary in search('archive', proxy, 'exact preferred'))
        check('mixed group review hides the pending preferred wheel and its lower collision',
              NAME not in search('group-pending', group, NAME, expected=23))
        approve(proxy, 'preferred', preferred)
        check('stock group search selects the approved cached wheel',
              preferred_summary in search('group-approved', group, NAME))
        index('confirmed-absence', group, fallback)
        check('a current proxy absence permits stock discovery of a different hosted project',
              lower_summary in search('confirmed-absence', group, fallback))
        document['files'][0]['yanked'] = 'Owned fixture upstream withdrawal'
        with lock:
            content[catalog_path] = json.dumps(document).encode()
        expire('yanked')
        index('yanked', proxy, NAME, expected=1)
        check('current upstream yanks hide a preferred cached wheel without selecting its lower collision',
              NAME not in search('yanked', group, NAME, expected=23))
        document['files'][0]['yanked'] = False
        with lock:
            content[catalog_path] = json.dumps(document).encode()
        expire('unyanked')
        index('unyanked', proxy, NAME)
        restart()
        with lock:
            count = len(requests)
        result = search('restarted', group, NAME)
        with lock:
            count_unchanged = count == len(requests)
        check('restored catalog discovery survives restart without contacting the origin during search',
              preferred_summary in result and count_unchanged)
        expire('unknown')
        check('expired catalog authority fences both cached and lower search results',
              NAME not in search('expired', group, NAME, expected=23))
        grant(proxy, 'revoke', allowed=False)
        check('stock Python group search honors selected member grant changes',
              fallback not in search('grant-denied', group, fallback, expected=23))
    return {'checks': checks, 'preferred_archive_sha256': sha(preferred)}
