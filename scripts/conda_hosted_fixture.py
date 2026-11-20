# SPDX-License-Identifier: BUSL-1.1
"""Resolve, download and link an inert hosted Conda graph with stock micromamba."""

from dataclasses import dataclass
import hashlib
import io
import json
import platform
import re
import ssl
import stat
import tarfile
import urllib.error
import urllib.request
from urllib.parse import urlsplit

VERSION = '2.9.0'
PINS = {
    'linux-64': '366cd9cd8be14df1ab8ed50352a82111082a36686b2d389fdb79a92c3fafb3e3',
    'linux-aarch64': '9f93b974adcb4d166996af969b6cd371287d1a3e52733704727884d9b74cb7a7',
    'osx-arm64': 'ec2a072f028e1a7cf20f3e2e74d5a8127cf5a5f27636375b5359811565f4e5be',
}
HOSTS = {('Linux', 'x86_64'): 'linux-64', ('Linux', 'aarch64'): 'linux-aarch64', ('Darwin', 'arm64'): 'osx-arm64'}
REPOSITORY = 'cratectl-conda-stock'
APP = 'cratectl-conda-app'
DEPENDENCY = 'cratectl-conda-data'
SPEC = DEPENDENCY + ' >=1.0,<2'


@dataclass(frozen=True)
class Fixture:
    subdir: str
    name: str
    version: str
    build_number: int
    payload: bytes

    @property
    def build(self):
        return f'fixture_{self.build_number}'

    @property
    def filename(self):
        return f'{self.name}-{self.version}-{self.build}.tar.bz2'

    @property
    def path(self):
        return f'{self.subdir}/{self.filename}'

    @property
    def payload_path(self):
        return f'share/cratectl/{self.name}.txt'

    def archive(self):
        index = {'name': self.name, 'version': self.version, 'build': self.build, 'build_number': self.build_number,
                 'subdir': self.subdir, 'depends': [SPEC] if self.name == APP else [], 'license': 'MIT'}
        if self.subdir == 'noarch':
            index['noarch'] = 'generic'
        paths = {'paths_version': 1, 'paths': [{'_path': self.payload_path, 'path_type': 'hardlink',
                                               'sha256': hashlib.sha256(self.payload).hexdigest(),
                                               'size_in_bytes': len(self.payload)}]}
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:bz2', format=tarfile.USTAR_FORMAT) as archive:
            for path, data in (('info/index.json', json.dumps(index, sort_keys=True).encode()),
                               ('info/files', (self.payload_path + '\n').encode()),
                               ('info/paths.json', json.dumps(paths, sort_keys=True).encode()),
                               (self.payload_path, self.payload)):
                member = tarfile.TarInfo(path)
                member.size = len(data)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(data))
        return buffer.getvalue()


def fixtures(native):
    foreign = 'linux-64' if native != 'linux-64' else 'linux-aarch64'
    return (Fixture(native, APP, '1.4.0', 3, b'Owned per-platform application bytes.\n'),
            Fixture('noarch', DEPENDENCY, '1.3.0', 1, b'Owned selected portable dependency bytes.\n'),
            Fixture('noarch', DEPENDENCY, '1.3.0', 0, b'Owned lower build bytes.\n'),
            Fixture('noarch', DEPENDENCY, '2.0.0', 0, b'Owned out-of-range dependency bytes.\n'),
            Fixture(foreign, APP, '1.4.0', 3, b'Owned alternate platform bytes.\n'))


def evaluate_conda(work, installation, authority, call, api, restart, sha, executable, *, grouped=False):
    native = HOSTS.get((platform.system(), platform.machine()))
    if native is None or sha(executable) != PINS[native]:
        raise ValueError('use the pinned stock micromamba binary for this native host')
    root = work / REPOSITORY
    root.mkdir(mode=0o700)
    checks = []

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    def isolated_environment(target):
        target.mkdir(mode=0o700)
        return {'PATH': '/usr/bin:/bin', 'HOME': str(target), 'MAMBA_ROOT_PREFIX': str(target / 'root'),
                'XDG_CONFIG_HOME': str(target / 'config'), 'XDG_CACHE_HOME': str(target / 'cache'),
                'LC_ALL': 'C', 'MAMBA_REPODATA_USE_ZST': 'false'}

    env = isolated_environment(root / 'version')
    runtime = call('conda-client-version', executable, '--no-rc', '--version', cwd=root, environment=env)[1].strip()
    check('the native stock micromamba version and release digest match', runtime == VERSION)
    management = '/api/v1/repositories/'
    api('conda-create', management.rstrip('/'), 'POST',
        {'name': REPOSITORY, 'format': 'conda', 'access': 'restricted', 'require_review': True})
    tokens = {'admin': (installation / 'admin.token').read_text().strip(),
              'reader': (work / 'reader.token').read_text().strip(),
              'other': (work / 'other.token').read_text().strip()}
    ca = installation / 'ca.crt'

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    trust = ssl.create_default_context(cafile=str(ca))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust), NoRedirect())

    def request(path, actor='reader', method='GET', body=None, *, repository=REPOSITORY):
        req = urllib.request.Request(authority + '/conda/' + repository + '/' + path, data=body, method=method,
                                     headers={'Authorization': 'Bearer ' + tokens[actor]})
        try:
            with opener.open(req, timeout=10) as response:
                data = response.read((128 << 10) + 1)
                if len(data) > (128 << 10):
                    raise ValueError('owned Conda response exceeded its fixture bound')
                return response.status, data, response.headers.get('X-Checksum-Sha256')
        except urllib.error.HTTPError as error:
            with error:
                return error.code, b'', None

    app, dependency, *alternatives = fixtures(native)
    packages = (app, dependency, *alternatives)
    bodies = {package.path: package.archive() for package in packages}
    digests = {path: hashlib.sha256(body).hexdigest() for path, body in bodies.items()}

    def view(subdir, filename='repodata.json'):
        status, raw, _ = request(f'{subdir}/{filename}')
        if status != 200:
            raise ValueError(f'owned Conda index request returned {status}')
        data = json.loads(raw)
        if data['info'] != {'subdir': subdir} or data['packages.conda'] != {} or data['repodata_version'] != 1:
            raise ValueError('owned Conda index returned an incompatible platform view')
        return data['packages']

    check('platform metadata requires the current repository and tenant grants',
          request(f'{native}/repodata.json')[0] == 403 and request(f'{native}/repodata.json', 'other')[0] == 404)
    api('conda-grant-reader', management + REPOSITORY + '/grants', 'PUT',
        {'actor': 'cratectl-reader', 'read': True, 'write': False})
    check('five exact platform and noarch coordinates publish original SHA-256 identities',
          all(request(path, 'admin', 'PUT', body) == (201, b'', digests[path]) for path, body in bodies.items()))
    check('unreviewed archives stay out of both indexes and cannot be downloaded',
          not view(native) and not view('noarch') and request(app.path)[0] == 403)
    check('the archive platform and immutable bytes must match the coordinate',
          request('win-64/' + app.filename, 'admin', 'PUT', bodies[app.path])[0] == 400
          and request(app.path, 'admin', 'PUT', Fixture(native, APP, '1.4.0', 3, b'Changed owned bytes.').archive())[0] == 409)

    def decide(label, package, decision):
        api('conda-review-' + label, management + REPOSITORY + '/decisions', 'PUT',
            {'path': package.path, 'digest': digests[package.path], 'decision': decision})

    for offset, package in enumerate(packages):
        decide(str(offset), package, 'allowed')
    native_view = view(native)
    portable_view = view('noarch')
    check('approved repodata binds each isolated platform, build, constraint and archive digest',
          set(native_view) == {app.filename} and set(portable_view) == {dependency.filename, *(p.filename for p in alternatives[:2])}
          and native_view[app.filename]['depends'] == [SPEC] and view(native, 'current_repodata.json') == native_view
          and all(view(p.subdir)[p.filename]['sha256'] == digests[p.path] for p in packages))
    check('the isolated reader receives exact approved archive bytes under trusted TLS',
          all(request(path)[:2] == (200, body) for path, body in bodies.items()))

    def consume(label, *, download_only=False, expected_failure=False, repository=REPOSITORY,
                graph=(app, dependency), expected_urls=None, snapshot=None):
        target = root / label
        environment = isolated_environment(target)
        scope = '/conda/' + repository
        if snapshot is not None:
            scope += '/snapshots/' + snapshot
        channel = authority + scope
        call('conda-auth-' + label, executable, '--no-rc', 'auth', 'login', channel, '--username', 'token', '--password-stdin',
             cwd=target, environment=environment, input_text=tokens['reader'] + '\n')
        auth = target / '.mamba/auth/authentication.json'
        if auth.is_symlink() or stat.S_IMODE(auth.stat().st_mode) != 0o600 or set(json.loads(auth.read_bytes())) != {urlsplit(channel).netloc + scope}:
            raise ValueError('stock micromamba did not keep credentials in the private channel scope')
        env_prefix = target / 'environment'
        option = ('--download-only',) if download_only else ()
        code, output = call('conda-consume-' + label, executable, '--no-rc', 'create', '--prefix', env_prefix,
                            '--override-channels', '--channel', channel, '--ssl-verify', ca, '--repodata-ttl', '0',
                            '--json', '--yes', *option, APP + '=1.4.0', cwd=target, environment=environment,
                            status=None, timeout=80)
        cache = target / 'root/pkgs'
        archives = [(file.name, sha(file)) for file in cache.rglob('*.tar.bz2')]
        installed = {file.stem for file in (env_prefix / 'conda-meta').glob('*.json')}
        linked_payload = any((env_prefix / p.payload_path).is_file() for p in graph)
        if expected_failure:
            solver_refused = 'could not solve' in output.lower() or '"solver_problems":' in output
            return code != 0 and solver_refused and not archives and not installed and not linked_payload
        if code:
            markers = ('certificate', 'repodata', 'Could not solve', 'checksum')
            statuses = set(re.findall(r'\bstatus:?\s+(401|403|404)\b', output, re.IGNORECASE))
            seen = ', '.join(sorted(statuses) + [marker for marker in markers if marker.lower() in output.lower()]) or 'client failure'
            raise ValueError(f'stock micromamba {label} returned {code} ({seen})')
        exact = {p.filename: hashlib.sha256(p.archive()).hexdigest() for p in graph}
        fetched = json.loads(output)['actions']['FETCH']
        expected_graph = {(p.name, p.version, p.build, p.subdir, exact[p.filename]) for p in graph}
        actual_graph = {(p['name'], p['version'], p['build_string'], p['subdir'], p['sha256']) for p in fetched}
        exact_fetch = len(archives) == len(fetched) == len(exact) and dict(archives) == exact and actual_graph == expected_graph
        if expected_urls is not None:
            urls = [urlsplit(p['url']) for p in fetched]
            published = {url._replace(netloc=url.netloc.rsplit('@', 1)[-1]).geturl() for url in urls}
            exact_fetch = exact_fetch and published == set(expected_urls)
        if download_only:
            return exact_fetch and not installed and not linked_payload
        return (exact_fetch and installed == {p.filename.removesuffix('.tar.bz2') for p in graph}
                and all((env_prefix / p.payload_path).read_bytes() == p.payload for p in graph))

    check('stock micromamba downloads the native graph and selects the newest compatible noarch build',
          consume('first', download_only=True))
    restart()
    check('fresh stock micromamba links the two exact inert archives after restart', consume('after-restart'))
    for package in (dependency, alternatives[0]):
        decide('deny-' + package.build, package, 'denied')
    check('current digest denial removes both compatible noarch builds and their bytes',
          set(view('noarch')) == {alternatives[1].filename} and request(dependency.path)[0] == 403)
    check('fresh stock micromamba refuses the graph after compatible build denial', consume('denied', expected_failure=True))
    report = {'client_version': runtime, 'client_sha256': PINS[native], 'subdir': native, 'checks': checks,
              'archive_sha256': digests, 'selected': {p.path: digests[p.path] for p in (app, dependency)}}
    if grouped:
        from conda_group_fixture import evaluate_conda_group

        report['group'] = evaluate_conda_group(native, authority, request, api, consume, restart)
    return report
