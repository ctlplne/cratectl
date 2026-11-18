# SPDX-License-Identifier: BUSL-1.1
"""Stock Twine upload and pip search on an isolated hosted index."""
import base64
import csv
import hashlib
import io
import os
import urllib.parse
import zipfile


REPO = 'cratectl-python-search'
NAME = 'cratectl-python-search-demo'


def wheel(work, directory, version, summary):
    distribution = NAME.replace('-', '_')
    info = f'{distribution}-{version}.dist-info'
    path = work / directory
    path.mkdir()
    target = path / f'{distribution}-{version}-py3-none-any.whl'
    files = {
        f'{distribution}/__init__.py': b'# Inert hosted search fixture.\n',
        f'{info}/METADATA': f'Metadata-Version: 2.4\nName: {NAME}\nVersion: {version}\nSummary: {summary}\n\n'.encode(),
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
    base_env = {key: value for key, value in environment.items() if not key.startswith(('PIP_', 'TWINE_', 'PYTHON'))}
    base_env.update(PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK='1', PIP_NO_INPUT='1', PIP_KEYRING_PROVIDER='disabled')
    auth = {'writer': installation / 'admin.token', 'reader': work / 'reader.token', 'second': work / 'other.token'}
    clients = {}
    host = urllib.parse.urlsplit(authority).hostname
    for label, token in auth.items():
        netrc = work / ('python-search-' + label + '.netrc')
        netrc.write_text(f'machine {host} login token password {token.read_text().strip()}\n')
        clients[label] = dict(base_env, NETRC=str(netrc))
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
        twine_env = dict(base_env, TWINE_USERNAME='token', TWINE_PASSWORD=auth[role].read_text().strip())
        call('python-search-upload-' + label, python, '-I', '-m', 'twine', 'upload', '--non-interactive',
             '--disable-progress-bar', '--config-file', pypirc, '--cert', trust, '--repository-url', endpoint, path,
             environment=twine_env, timeout=40)

    def approve(label, path, config=None):
        api('python-search-approve-' + label, management + '/decisions', 'PUT',
            {'path': path.name, 'digest': sha(path), 'decision': 'allowed'}, config=config)

    def search(label, query, role='reader', expected=0):
        return call('python-search-' + label, python, '-I', '-m', 'pip', 'search', '--index', endpoint + 'search',
                    '--cert', trust, '--no-cache-dir', '--retries', '0', query, environment=clients[role], status=expected)[1]

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
