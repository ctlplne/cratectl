# SPDX-License-Identifier: BUSL-1.1
"""Verify the registry's hosted search index with the stock ASF Indexer Reader."""

from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
from pathlib import Path
import socket
import ssl
import threading
import urllib.error
import urllib.request
import zipfile

from ci.maven_index_evidence import INDEXER_SHA256

INDEX = 'nexus-maven-repository-index'
REPO = 'cratectl-maven-index'
API = '/api/v1/repositories/' + REPO


def hosted_maven_index(work, app, authority, java, indexer, environment, call, api, restart, sha, *, cached=False):
    if sha(indexer) != INDEXER_SHA256:
        raise ValueError('the pinned Apache Indexer Reader 7.1.6 JAR is required')
    scope = work / 'maven-index'
    scope.mkdir(mode=0o700)
    cert = ssl.create_default_context(cafile=str(app / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=cert))
    tokens = {'admin': app / 'admin.token', 'reader': work / 'reader.token', 'other': work / 'other.token'}
    expected = {'name': REPO, 'format': 'maven', 'access': 'restricted', 'require_review': True}
    api('maven-index-open', '/api/v1/repositories', 'POST', expected)
    api('maven-index-other-open', '/api/v1/repositories', 'POST', expected, config=work / 'other.json')
    checks = []

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    def request(part, who='reader', method='GET', body=None, headers=None, *, repository=REPO):
        fields = {} if headers is None else dict(headers)
        fields['Authorization'] = 'Bearer ' + tokens[who].read_text().strip()
        if body is not None:
            fields['Content-Type'] = 'application/octet-stream'
        req = urllib.request.Request(authority + '/r/' + repository + '/' + part, method=method, data=body, headers=fields)
        try:
            with opener.open(req, timeout=8) as response:
                value = response.read((1 << 20) + 1)
                if len(value) > 1 << 20 or response.url != req.full_url:
                    raise ValueError('Maven index fixture exceeded its response conditions')
                return response.status, value, response.headers
        except urllib.error.HTTPError as error:
            with error:
                return error.code, b'', error.headers

    def grant(label, enabled):
        api('maven-index-grant-' + label, API + '/grants', 'PUT', {'actor': 'cratectl-reader', 'read': enabled, 'write': False})

    def decide(label, who, file, digest, value):
        api('maven-index-review-' + label, API + '/decisions', 'PUT', {'path': file, 'digest': digest, 'decision': value},
            config=work / 'other.json' if who == 'other' else app / 'client.json')

    def publish(label, who, artifact, version, payload):
        prefix = f'dev/ctlplne/{artifact}/{version}/{artifact}-{version}'
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as jar:
            jar.writestr(zipfile.ZipInfo('META-INF/MANIFEST.MF'), b'Manifest-Version: 1.0\r\n\r\n')
            jar.writestr(zipfile.ZipInfo('fixture.txt'), payload)
        jar = archive.getvalue()
        pom = (f'<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
               f'<groupId>dev.ctlplne</groupId><artifactId>{artifact}</artifactId><version>{version}</version></project>').encode()
        for ext, value in (('jar', jar), ('pom', pom)):
            if request(prefix + '.' + ext, who, 'PUT', value)[0] != 201:
                raise ValueError('owned Maven archive publication failed: ' + label)
        fields = {'group': 'dev.ctlplne', 'artifact': artifact, 'version': version, 'digest': hashlib.sha256(jar).hexdigest(), 'size': len(jar)}
        return prefix, fields, hashlib.sha256(pom).hexdigest()

    java = java.resolve()
    version = call('maven-index-java-version', java, '--version', environment=environment)[1].splitlines()[0]
    if '21.' not in version:
        raise ValueError('use the reviewed JDK 21 runtime')
    source = Path(__file__).resolve().parent / 'fixtures/maven-index/MavenIndexStock.java'
    gz = '.index/' + INDEX + '.gz'

    def index(label, who, repository=REPO):
        destination = scope / label
        destination.mkdir(mode=0o700)
        for suffix in ('.properties', '.gz'):
            status, body, headers = request('.index/' + INDEX + suffix, who, repository=repository)
            if status != 200 or headers.get('Cache-Control') != 'private, no-store':
                raise ValueError('authenticated Maven index download failed')
            (destination / (INDEX + suffix)).write_bytes(body)
        digest = sha(destination / (INDEX + '.gz'))
        properties = (destination / (INDEX + '.properties')).read_text()
        if 'cratectl.index.sha256=' + digest + '\n' not in properties or request(gz + '.sha256', who, repository=repository)[:2] != (200, digest.encode()):
            raise ValueError('the Maven index and checksum representations differ')
        _, output = call('maven-index-stock-' + label, java, '--class-path', indexer, source, destination, repository,
                         environment=environment, timeout=25)
        return output.splitlines(), digest, headers.get('ETag')

    def expected_row(record):
        return '\t'.join(str(record[field]) for field in ('group', 'artifact', 'version', 'digest', 'size'))

    first, one, pom_one = publish('first', 'admin', 'cratectl-lib', '1.0.0', b'Owned first version\n')
    second, two, pom_two = publish('second', 'admin', 'cratectl-lib', '2.0.0', b'Owned second version\n')
    outsider, isolated, other_pom = publish('same-coordinate', 'other', 'cratectl-lib', '1.0.0', b'Owned independent tenant\n')
    check('an ungranted same-tenant reader is forbidden from the native index', request(gz)[0] == 403)
    grant('allow', True)
    decide('first-jar', 'admin', first + '.jar', one['digest'], 'allowed')
    check('stock Maven Indexer reads an empty full index while the POM awaits review', index('pending-pom', 'reader')[0] == [])
    decide('first-pom', 'admin', first + '.pom', pom_one, 'allowed')
    check('stock Maven Indexer finds only the first fully admitted release', index('one-release', 'reader')[0] == [expected_row(one)])
    for label, who, prefix, jar, pom in (('later', 'admin', second, two['digest'], pom_two),
                                        ('independent', 'other', outsider, isolated['digest'], other_pom)):
        decide(label + '-jar', who, prefix + '.jar', jar, 'allowed')
        decide(label + '-pom', who, prefix + '.pom', pom, 'allowed')
    same, archive_sha, etag = index('two-releases', 'reader')
    check('stock Maven Indexer preserves both version and digest identities in repository order', same == [expected_row(one), expected_row(two)])
    check('stock Maven Indexer holds independent same-coordinate tenant inventories',
          index('other-tenant', 'other')[0] == [expected_row(isolated)] and isolated['digest'] != one['digest'])
    restart()
    status, restored, _ = request(second + '.jar')
    check('the stock index and its exact JAR bytes recover after registry restart',
          index('after-restart', 'reader') == (same, archive_sha, etag) and status == 200 and hashlib.sha256(restored).hexdigest() == two['digest'])
    decide('deny-first-pom', 'admin', first + '.pom', pom_one, 'denied')
    check('current POM denial removes that coordinate from the stock full index', index('after-denial', 'reader')[0] == [expected_row(two)])
    grant('revoke', False)
    check('a conditional native index request honors read grant revocation', request(gz, headers={'If-None-Match': etag})[0] == 403)
    report = {'checks': checks, 'reader': '7.1.6', 'reader_sha256': sha(indexer), 'java': version, 'archive_sha256': archive_sha,
              'jar_sha256': [item['digest'] for item in (one, two, isolated)]}
    if cached:
        report['cached'] = cached_maven_index(second, two['digest'], pom_two, expected_row(two), index, request, api, restart)
    return report


@contextmanager
def maven_index_origin(files):
    class Origin(ThreadingHTTPServer):
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requests.append(self.path)
            data = files.get(self.path)
            if data is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Cache-Control', 'max-age=180')
            self.end_headers()
            self.wfile.write(data)

    requests = []
    with Origin(('::1', 38443), Handler) as origin:
        thread = threading.Thread(target=origin.serve_forever, name='cratectl-maven-index-origin')
        thread.start()
        try:
            yield requests
        finally:
            origin.shutdown()
            thread.join(5)
            if thread.is_alive():
                raise ValueError('owned Maven index origin did not stop')


def cached_maven_index(coordinate, jar_digest, pom_digest, row, index, request, api, restart):
    repository = 'cratectl-maven-index-cached'
    endpoint = '/api/v1/repositories/' + repository
    origin = '/cratectl-maven-index-origin/'
    checks = []
    files = {}
    for extension, digest in (('.jar', jar_digest), ('.pom', pom_digest)):
        source = coordinate + extension
        status, body, _ = request(source, 'admin')
        if status != 200 or hashlib.sha256(body).hexdigest() != digest:
            raise ValueError('the controlled Maven origin requires the exact hosted fixture bytes')
        files[origin + source] = body
        files[origin + source + '.sha256'] = digest.encode()

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    def pull(extension, digest):
        status, raw, _ = request(coordinate + extension, repository=repository)
        return status == 200 and hashlib.sha256(raw).hexdigest() == digest

    with maven_index_origin(files) as requests:
        api('maven-index-create-proxy', '/api/v1/repositories', 'POST', {'name': repository, 'format': 'maven', 'mode': 'proxy',
            'settings': {'upstream': {'url': 'http://[::1]:38443' + origin, 'networks': ['::1/128']},
                         'cache': {'fresh_seconds': 180, 'negative_seconds': 30, 'require_checksum': True}}})

        def visible(phase, expected):
            before = len(requests)
            rows, digest, _ = index('cached-' + phase, 'reader', repository)
            return rows == expected and before == len(requests), digest

        check('stock Maven Indexer reads a cold proxy index without contacting its origin', visible('cold', [])[0] and not requests)
        check('an exact cached JAR alone cannot advertise a release without its POM',
              pull('.jar', jar_digest) and visible('jar-only', [])[0])
        check('stock Maven Indexer lists the exact checksum-validated pair without an upstream search',
              pull('.pom', pom_digest) and visible('complete', [row])[0]
              and all(origin + coordinate + extension + '.sha256' in requests for extension in ('.jar', '.pom')))
        api('maven-index-expire-proxy-pom', endpoint + '/cache', 'PUT', {'path': coordinate + '.pom'})
        check('an invalidated POM hides the cached release without consulting the origin', visible('invalidated', [])[0])
        check('an explicit POM fetch restores the current stock index record', pull('.pom', pom_digest) and visible('revalidated', [row])[0])
        restart()
        recovered, archive_sha = visible('restart', [row])
        check('stock cached Maven discovery and exact JAR bytes survive restart', recovered and pull('.jar', jar_digest))
        api('maven-index-deny-cached-pom', endpoint + '/decisions', 'PUT',
            {'path': coordinate + '.pom', 'digest': pom_digest, 'decision': 'denied'})
        check('current POM policy hides the cached pair without a source result leak', visible('denied', [])[0])
        groups = grouped_maven_index(coordinate, jar_digest, pom_digest, row, files, origin, requests, index, request, api)
        return {'checks': checks, 'archive_sha256': archive_sha, 'jar_sha256': jar_digest, 'pom_sha256': pom_digest, 'groups': groups}


def grouped_maven_index(coordinate, jar_digest, pom_digest, row, files, origin, requests, index, request, api):
    preferred = 'cratectl-maven-index-preferred'
    jar_repo = 'cratectl-maven-index-jar'
    pom_repo = 'cratectl-maven-index-pom'
    group = 'cratectl-maven-index-group'
    missing = '/cratectl-maven-index-absent/'
    endpoint = '/api/v1/repositories/' + preferred
    checks = []

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    def repository(label, name, **fields):
        api('maven-index-group-create-' + label, '/api/v1/repositories', 'POST', {'name': name, 'format': 'maven', **fields})

    repository('preferred', preferred, mode='proxy', access='restricted', settings={
        'upstream': {'url': 'http://[::1]:38443' + missing, 'networks': ['::1/128']},
        'cache': {'fresh_seconds': 180, 'negative_seconds': 120, 'require_checksum': True}})
    repository('jar', jar_repo)
    repository('pom', pom_repo)
    repository('group', group, mode='group', settings={'members': [preferred, jar_repo, pom_repo]})
    for ext, owner in (('.jar', jar_repo), ('.pom', pom_repo)):
        path = coordinate + ext
        if request(path, 'admin', 'PUT', files[origin + path], repository=owner)[0] != 201:
            raise ValueError('cannot seed the split hosted Maven group release')

    def grant(label, allow):
        api('maven-index-group-grant-' + label, endpoint + '/grants', 'PUT', {'actor': 'cratectl-reader', 'read': allow, 'write': False})

    def read(phase, expected):
        before = len(requests)
        rows, digest, _ = index('group-' + phase, 'reader', group)
        return rows == expected and before == len(requests), digest

    def pull(extension, digest):
        status, body, _ = request(coordinate + extension, repository=group)
        return status == 200 and hashlib.sha256(body).hexdigest() == digest and missing + coordinate + extension in requests

    check('an ungranted preferred source hides the ordered Maven group coordinate', read('ungranted', [])[0])
    grant('allow', True)
    check('unknown preferred source state fences an ordered Maven index without an origin request', read('cold', [])[0])
    check('a current JAR absence alone cannot admit an ordered Maven release', pull('.jar', jar_digest) and read('jar-only', [])[0])
    admitted = pull('.pom', pom_digest)
    visible, archive_sha = read('admitted', [row])
    check('stock Maven Indexer reads a group release from independently selected JAR and POM members', admitted and visible)
    grant('revoke', False)
    check('revoking the consulted preferred source grant removes the group release', read('revoked', [])[0])
    grant('restore', True)
    check('restoring the grant and current absence restores discovery with zero origin reads', read('restored', [row])[0])
    api('maven-index-group-expire-pom', endpoint + '/cache', 'PUT', {'path': coordinate + '.pom'})
    check('expired preferred POM absence fences group indexing without contacting the origin', read('expired', [])[0])
    return {'checks': checks, 'archive_sha256': archive_sha}
