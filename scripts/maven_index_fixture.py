# SPDX-License-Identifier: BUSL-1.1
"""Verify the registry's hosted search index with the stock ASF Indexer Reader."""

import hashlib
import io
from pathlib import Path
import ssl
import urllib.error
import urllib.request
import zipfile


INDEXER_SHA256 = '7aebdcebb934f1e4f1b9583348a8a0cb4881862ac7263b40e5122b7c5ec1c3aa'
INDEX = 'nexus-maven-repository-index'
REPO = 'cratectl-maven-index'
API = '/api/v1/repositories/' + REPO


def hosted_maven_index(work, app, authority, java, indexer, environment, call, api, restart, sha):
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

    def request(part, who='reader', method='GET', body=None, headers=None):
        fields = {} if headers is None else dict(headers)
        fields['Authorization'] = 'Bearer ' + tokens[who].read_text().strip()
        if body is not None:
            fields['Content-Type'] = 'application/octet-stream'
        req = urllib.request.Request(authority + '/r/' + REPO + '/' + part, method=method, data=body, headers=fields)
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

    def index(label, who):
        destination = scope / label
        destination.mkdir(mode=0o700)
        for suffix in ('.properties', '.gz'):
            status, body, headers = request('.index/' + INDEX + suffix, who)
            if status != 200 or headers.get('Cache-Control') != 'private, no-store':
                raise ValueError('authenticated Maven index download failed')
            (destination / (INDEX + suffix)).write_bytes(body)
        digest = sha(destination / (INDEX + '.gz'))
        properties = (destination / (INDEX + '.properties')).read_text()
        if 'cratectl.index.sha256=' + digest + '\n' not in properties or request(gz + '.sha256', who)[:2] != (200, digest.encode()):
            raise ValueError('the Maven index and checksum representations differ')
        _, output = call('maven-index-stock-' + label, java, '--class-path', indexer, source, destination, REPO,
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
    return {'checks': checks, 'reader': '7.1.6', 'reader_sha256': sha(indexer), 'java': version, 'archive_sha256': archive_sha,
            'jar_sha256': [item['digest'] for item in (one, two, isolated)]}
