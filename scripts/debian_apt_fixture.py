# SPDX-License-Identifier: BUSL-1.1
"""Exercise signed hosted metadata and exact dependency downloads with stock APT."""

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import hashlib
from pathlib import Path
import re
import shutil
import ssl
import tempfile
import urllib.error
import urllib.request

REPO = 'cratectl-debian-stock'
APP = 'cratectl-apt-app'
DEPENDENCY = 'cratectl-apt-library'
VERSION = '1.0-1'


def evaluate_debian_apt(work, installation, authority, environment, call, api, restart, sha):
    scope = work / 'cratectl-debian-apt'
    scope.mkdir(mode=0o700)
    signer = Path(tempfile.mkdtemp(prefix='cratectl-apt-gpg-', dir=work.parent))
    signer_env = dict(environment, GNUPGHOME=str(signer))
    tools = {tool: shutil.which(tool) for tool in ('apt-get', 'dpkg-deb', 'dpkg', 'gpg', 'gpgconf')}
    checks = []

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    check('stock APT, dpkg and GnuPG are available', all(tools.values()))
    apt_version = call('apt-version', tools['apt-get'], '--version', cwd=scope)[1].splitlines()[0]
    architecture = call('dpkg-architecture', tools['dpkg'], '--print-architecture', cwd=scope)[1].strip()
    signer_version = call('apt-signer-version', tools['gpg'], '--version', cwd=scope, environment=signer_env)[1].splitlines()[0]
    check('stock APT has an observed native platform and apt-secure tools', architecture in ('amd64', 'arm64') and
          re.fullmatch(r'apt 2\.[0-9.]{2,16} \((?:amd64|arm64)\)', apt_version) is not None and
          apt_version.endswith(f'({architecture})') and re.fullmatch(r'gpg \(GnuPG\) 2\.[0-9.]{2,16}', signer_version) is not None)

    root = f'/apt/{REPO}/'
    management = f'/api/v1/repositories/{REPO}'
    api('apt-create', '/api/v1/repositories', 'POST', {'name': REPO, 'format': 'apt', 'access': 'restricted', 'require_review': True})
    tokens = {'admin': (installation / 'admin.token').read_text().strip(), 'reader': (work / 'reader.token').read_text().strip(),
              'other': (work / 'other.token').read_text().strip()}
    cafile = installation / 'ca.crt'
    trust = ssl.create_default_context(cafile=str(cafile))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))

    def request(path, who='reader', method='GET', data=None):
        endpoint = authority + root + path
        args = {'Authorization': 'Bearer ' + tokens[who]}
        if data is not None:
            args['Content-Type'] = 'application/octet-stream'
        req = urllib.request.Request(endpoint, method=method, data=data, headers=args)
        try:
            with opener.open(req, timeout=10) as response:
                body = response.read((2 << 20) + 1)
                if response.url != endpoint or len(body) > 2 << 20:
                    raise ValueError('owned APT fixture response exceeded its bounds')
                return response.status, body
        except urllib.error.HTTPError as error:
            with error:
                return error.code, b''

    check('APT metadata requires the scoped repository grant', request('Packages')[0] == 403 and request('Packages', 'other')[0] == 404)
    api('apt-grant', management + '/grants', 'PUT', {'actor': 'cratectl-reader', 'read': True, 'write': False})

    packages = {}
    for label, arch in ((APP, architecture), (DEPENDENCY, 'all')):
        staging = scope / (label + '-tree')
        control = staging / 'DEBIAN'
        control.mkdir(parents=True, mode=0o755)
        control.chmod(0o755)
        file = staging / 'usr/share' / label / 'owned.txt'
        file.parent.mkdir(parents=True, mode=0o755)
        file.write_text(f'Owned inert Debian archive for {label}.\n')
        fields = f'Package: {label}\nVersion: {VERSION}\nArchitecture: {arch}\nMaintainer: cratectl test <fixture@example.invalid>\n'
        if label == APP:
            fields += f'Depends: {DEPENDENCY} (= {VERSION})\n'
        (control / 'control').write_text(fields + 'Description: Inert Debian payload used for stock download\n')
        artifact = scope / (label + '.deb')
        code, output = call('apt-build-' + label, tools['dpkg-deb'], '--build', '--root-owner-group', '-Zgzip', staging, artifact,
                            cwd=scope, status=None)
        if code != 0:
            reason = 'control directory mode' if 'control directory has bad permissions' in output else 'archive build'
            raise ValueError(f'stock dpkg-deb failed {reason} for the owned {label} fixture with exit {code}')
        relative = f'pool/{label}/{VERSION}/{arch}/{label}.deb'
        packages[label] = (relative, artifact.read_bytes(), sha(artifact))
        check('stock dpkg emits an exact accepted Debian archive ' + label, request(relative, 'admin', 'PUT', packages[label][1])[0] == 201)
    check('unreviewed Debian archives and dependency metadata remain private', request('Packages') == (200, b'') and
          all(request(record[0])[0] == 403 for record in packages.values()))

    def decide(label, path, digest, decision):
        api('apt-review-' + label, management + '/decisions', 'PUT', {'path': path, 'digest': digest, 'decision': decision})

    for label, (relative, _, digest) in packages.items():
        decide(label, relative, digest, 'allowed')
    index = {}
    for name in ('Packages', 'Packages.gz'):
        status, body = request(name)
        index[name] = body
        if status != 200:
            raise ValueError('current Debian package index is unavailable')
    check('the signed-input package index retains the exact dependency and archive bindings',
          f'Depends: {DEPENDENCY} (= {VERSION})'.encode() in index['Packages'] and
          all(f'Filename: {path}\nSize: {len(body)}\nSHA256: {digest}'.encode() in index['Packages']
              for path, body, digest in packages.values()))
    release = scope / 'Release'
    now = datetime.now(timezone.utc).replace(microsecond=0)
    release.write_text('Origin: cratectl owned fixture\nLabel: cratectl owned fixture\n' +
                       f'Date: {format_datetime(now - timedelta(minutes=1), usegmt=True)}\n' +
                       f'Valid-Until: {format_datetime(now + timedelta(hours=2), usegmt=True)}\n' +
                       'Acquire-By-Hash: yes\nSHA256:\n' + ''.join(
                           f' {hashlib.sha256(raw).hexdigest()} {len(raw)} {name}\n' for name, raw in index.items()))
    identity = 'cratectl owned APT fixture <fixture@example.invalid>'
    keyfile = scope / 'trusted.gpg'
    signed = scope / 'InRelease'
    try:
        call('apt-generate-fixture-key', tools['gpg'], '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
             '--quick-generate-key', identity, 'rsa2048', 'sign', '1d', cwd=scope, environment=signer_env, timeout=45)
        call('apt-export-key', tools['gpg'], '--batch', '--output', keyfile, '--export', identity, cwd=scope, environment=signer_env)
        call('apt-sign-release', tools['gpg'], '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--local-user', identity,
             '--digest-algo', 'SHA256', '--output', signed, '--clearsign', release, cwd=scope, environment=signer_env)
    finally:
        call('apt-stop-owned-agent', tools['gpgconf'], '--homedir', signer, '--kill', 'gpg-agent', cwd=scope, environment=signer_env)
    envelope = signed.read_bytes()
    release_sha = sha(signed)
    check('external GnuPG signed the exact published Release input', request('InRelease', 'admin', 'PUT', envelope)[0] == 201)
    check('repository review applies to the retained InRelease digest', request('InRelease')[0] == 403)
    decide('release', 'InRelease', release_sha, 'allowed')
    check('the original InRelease and by-hash indexes serve exact bytes', request('InRelease') == (200, envelope) and
          all(request('by-hash/SHA256/' + hashlib.sha256(raw).hexdigest()) == (200, raw) for raw in index.values()))

    def apt_consumer(label, key, *, expected_failure=None):
        target = scope / label
        target.mkdir(mode=0o700)
        for folder in ('lists/partial', 'archives/partial', 'state', 'cache', 'logs', 'empty'):
            (target / folder).mkdir(parents=True, mode=0o700)
        sources = target / 'source.sources'
        sources.write_text(f'Types: deb\nURIs: {authority + root}\nSuites: ./\nSigned-By: {key}\n')
        config = target / 'apt.conf'
        (target / 'status').touch()
        (target / 'no-defaults').touch()
        auth = target / 'auth.conf'
        auth.write_text(f'machine {authority + root}\nlogin token\npassword {tokens["reader"]}\n')
        auth.chmod(0o600)
        paths = {'Dir::Etc::main': target / 'no-defaults', 'Dir::Etc::parts': target / 'empty', 'Dir::Etc::sourcelist': sources,
                 'Dir::Etc::sourceparts': target / 'empty', 'Dir::Etc::netrc': auth, 'Dir::Etc::netrcparts': target / 'empty',
                 'Dir::Etc::trustedparts': target / 'empty', 'Dir::Etc::trusted': target / 'empty/no-default-key.gpg',
                 'Dir::State': target / 'state', 'Dir::State::status': target / 'status', 'Dir::State::lists': target / 'lists',
                 'Dir::State::extended_states': target / 'state/extended_states', 'Dir::Cache': target / 'cache',
                 'Dir::Cache::archives': target / 'archives', 'Dir::Log': target / 'logs'}
        values = {**paths, 'Dir::Cache::pkgcache': '', 'Dir::Cache::srcpkgcache': '', 'Acquire::https::CaInfo': cafile,
                  'Acquire::ForceIPv4': 'true', 'Acquire::Languages': 'none', 'Acquire::Retries': '0', 'Acquire::https::Timeout': '10'}
        config.write_text(''.join(f'{name} "{value}";\n' for name, value in values.items()))
        env = dict(environment, APT_CONFIG=str(config))
        code, output = call('apt-update-' + label, tools['apt-get'], 'update', cwd=target, environment=env, status=None)
        if expected_failure is not None:
            check('stock APT refuses ' + label, code == 100 and expected_failure in output)
            return
        if code != 0:
            markers = ('401', '403', '404', '409', 'NO_PUBKEY', 'Certificate verification failed', 'Hash Sum mismatch',
                       'Permission denied', 'Could not get lock', 'Could not resolve', 'is not signed')
            observed = ', '.join(marker for marker in markers if marker in output) or 'update failure'
            raise ValueError(f'stock APT update failed with exit {code} and {observed}')
        check('stock APT verifies and indexes the signed repository ' + label, code == 0 and 'InRelease' in output)
        call('apt-download-' + label, tools['apt-get'], '--download-only', '--assume-yes', 'install', f'{APP}={VERSION}', cwd=target,
             environment=env, timeout=45)
        archives = list((target / 'archives').glob('*.deb'))
        check('stock APT resolves and downloads the exact application and dependency ' + label,
              len(archives) == 2 and {sha(path) for path in archives} == {item[2] for item in packages.values()})

    apt_consumer('first-consumer', keyfile)
    empty_keyfile = scope / 'untrusted.gpg'
    empty_keyfile.touch()
    apt_consumer('untrusted-signature', empty_keyfile, expected_failure='NO_PUBKEY')
    restart()
    apt_consumer('after-restart', keyfile)
    decide('revoke-application', packages[APP][0], packages[APP][2], 'denied')
    check('current policy fences stale signed metadata and the denied package', request('InRelease')[0] == 409 and request(packages[APP][0])[0] == 403)
    apt_consumer('retired-index', keyfile, expected_failure='409')
    return {'checks': checks, 'apt': apt_version, 'architecture': architecture, 'gpg': signer_version,
            'archive_sha256': {key: records[2] for key, records in packages.items()}, 'release_sha256': release_sha,
            'index_sha256': {key: hashlib.sha256(data).hexdigest() for key, data in index.items()}}
