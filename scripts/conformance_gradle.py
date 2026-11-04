# SPDX-License-Identifier: BUSL-1.1
"""Native Gradle publication/resolution over the common real registry harness.

Run through conformance.py gradle. This alternative JVM client is a separate
profile from the existing baseline-format campaign, like Docker/Podman clients.
"""
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import urllib.error
import urllib.request
import zipfile

from bounded_client import run_owned_client
from ci.gradle_evidence import FIXTURES

GROUP = 'dev.cratectl.gradleproof'
GROUP_PATH = GROUP.replace('.', '/')


def publication_references(artifact, version, contents, rows):
    """Bind owned publisher output to exact retained paths, including snapshots.

    A snapshot's unique JAR identifies its timestamp/build; the POM and module
    must use that same timestamp. Equal POM bytes from an older publication
    cannot substitute for the current publication's POM reference.
    """
    if len(rows) > 100 or set(contents) != {'jar', 'pom', 'module'}:
        raise AssertionError('Gradle publication reference input exceeds the owned profile')
    prefix = GROUP_PATH + '/' + artifact + '/' + version + '/'
    stem = prefix + artifact + '-' + version
    if version.endswith('-SNAPSHOT'):
        pattern = re.escape(prefix + artifact + '-' + version.removesuffix('SNAPSHOT')) + r'\d{8}\.\d{6}-[1-9]\d{0,5}\.jar'
        jars = [row for row in rows if re.fullmatch(pattern, row['path']) and
                row['digest'] == hashlib.sha256(contents['jar']).hexdigest()]
        if len(jars) != 1:
            raise AssertionError('Gradle snapshot must identify one exact timestamped JAR')
        stem = jars[0]['path'].removesuffix('.jar')
    references = {}
    for ext, value in contents.items():
        matches = [row for row in rows if row['path'] == stem + '.' + ext]
        if len(matches) != 1 or matches[0]['digest'] != hashlib.sha256(value).hexdigest() or matches[0]['size'] != len(value):
            raise AssertionError('Gradle publication reference differs from publisher bytes: ' + ext)
        references[ext] = matches[0]
    return references


def hosted(h):
    check, req = h.check, h.req
    pin = json.loads((h.ROOT / 'docs/qualification/jvm-clients.json').read_text())['gradle']
    distribution = h.ROOT / ('.cache/gradle-' + pin['version'] + '-bin.zip')
    client = h.ROOT / ('.cache/gradle-' + pin['version'] + '/bin/gradle')
    check('pinned real Gradle client is installed', client.is_file() and distribution.is_file())
    with distribution.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    check('Gradle distribution is the pinned official immutable bytes', digest == pin['sha256'])
    work = h.PRIVATE / 'gradle'
    work.mkdir(mode=0o700)
    fixture_source = h.ROOT / 'scripts/fixtures/gradle-client'
    jdk = h.ROOT / '.cache/jdk-21.0.13+9/Contents/Home'
    release_bytes = (jdk / 'release').read_bytes()
    check('Gradle JDK release metadata is bounded', len(release_bytes) <= 65536)
    release = {key: value.strip('"') for line in release_bytes.decode().splitlines() if '=' in line for key, value in [line.split('=', 1)]}
    check('Gradle uses the pinned real Java runtime build', release.get('JAVA_RUNTIME_VERSION') in (pin['java'], pin['java'] + '-LTS'))
    check('Gradle JDK release identifies the actual native platform', release.get('OS_NAME') == 'Linux' and release.get('OS_ARCH') == {'x86_64': 'x86_64', 'aarch64': 'aarch64'}[platform.machine()])
    contract = {'profile': 'publication-wire-v2', 'version': pin['version'], 'distribution_sha256': digest,
                'launcher_sha256': hashlib.sha256(client.read_bytes()).hexdigest(),
                'java_version': release['JAVA_RUNTIME_VERSION'],
                'java_launcher_sha256': hashlib.sha256((jdk / 'bin/java').read_bytes()).hexdigest(),
                'java_release_sha256': hashlib.sha256(release_bytes).hexdigest(),
                'fixture_source_sha256': hashlib.sha256(b''.join((fixture_source / n).read_bytes() for n in ['settings.gradle', 'build.gradle'])).hexdigest(),
                'fixture_sha256': {}, 'reference_sha256': {}, 'wire_sha256': {},
                'completed': [], 'phase': 'client_identity', 'diagnostics': []}
    h.result['gradle_contract'] = contract

    def command(project, home, args=(), token='reader', repo='gradle-hosted', fail=False):
        home.mkdir(mode=0o700, exist_ok=True)
        environment = dict(h.env, GRADLE_USER_HOME=str(home),
                           JAVA_HOME=str(h.ROOT / '.cache/jdk-21.0.13+9/Contents/Home'),
                           JAVA_OPTS='-Xmx512m -XX:MaxMetaspaceSize=384m')
        argv = [client, '--no-daemon', '--no-configuration-cache', '--console=plain', '--max-workers=2',
                '-Dorg.gradle.jvmargs=-Xmx512m -XX:MaxMetaspaceSize=384m',
                '-PrepositoryURL=' + h.BASE + '/r/' + repo + '/',
                '-PcredentialFile=' + str(h.PRIVATE / (token + '.token')), *args]
        code, output = run_owned_client(argv, project, environment)
        for value in h.tokens.values():
            output = output.replace(value, '[REDACTED]')
        h.commands.append({'argv': [str(a).replace(str(h.PRIVATE), 'PRIVATE') for a in argv],
                           'exit': code, 'output': output[-12000:], 'expected_failure': fail})
        if fail:
            check('stock Gradle rejects the forbidden resolution/publication ' + project.name, code != 0)
        else:
            if code != 0:
                patterns={'http_401':r'\b401\b','http_403':r'\b403\b','http_404':r'\b404\b',
                          'fixture_compilation':r'Could not compile|Could not find method|startup failed',
                          'variant_selection':r'No matching variant|compatible variant',
                          'dependency_resolution':r'Could not resolve|Could not find',
                          'publication':r'Could not PUT|Failed to publish',
                          'verification':r'Dependency verification failed|checksum',
                          'jvm':r'Unsupported class file|Could not create the Java Virtual Machine'}
                contract['diagnostics']=sorted(k for k,v in patterns.items() if re.search(v,output,re.I))
            check('stock Gradle completes ' + project.name, code == 0)
        return output

    def project(label):
        directory = work / label
        directory.mkdir(mode=0o700)
        for name in ['settings.gradle', 'build.gradle']:
            shutil.copy2(fixture_source / name, directory / name)
        return directory

    identity = project('identity')
    version = command(identity, work / 'identity-home', ['--version'])
    check('actual Gradle version and Java launcher match the pinned profile',
          ('Gradle ' + pin['version']) in version and re.search(r'Launcher JVM:\s+21\.', version) is not None)
    check('actual Gradle JVM runs natively on this Linux runner', platform.system() == 'Linux' and
          re.search(r'OS:\s+Linux[^\n]*\b' + {'x86_64': 'amd64', 'aarch64': 'aarch64'}[platform.machine()] + r'\b', version) is not None)
    contract['completed'].append('client_identity')

    h.repository('gradle-hosted', 'maven', review=True, access='restricted')
    h.repository('gradle-hosted', 'maven', 'other')
    check('grant the intended native Gradle reader', req('/api/v1/repositories/gradle-hosted/grants', method='PUT',
          data={'actor': 'reader', 'read': True, 'write': False}, key=h.uuid.uuid4().hex)[0] == 200)
    writer_file = h.PRIVATE / 'gradle-writer.token'
    h.run([h.BIN / 'cratectld', 'provision', '--tenant', h.tenants['admin'], '--actor', 'gradle-writer', '--role', 'writer', '--token-file', writer_file])
    h.tokens['gradle-writer'] = writer_file.read_text().strip()
    check('grant only the intended native Gradle writer', req('/api/v1/repositories/gradle-hosted/grants', method='PUT',
          data={'actor': 'gradle-writer', 'read': True, 'write': True}, key=h.uuid.uuid4().hex)[0] == 200)
    published = {}

    def publish(label, artifact, version, token='gradle-writer', repo='gradle-hosted', marker=None, read_repo=None):
        directory = project('publish-' + label)
        resources = directory / 'src/main/resources'
        resources.mkdir(parents=True)
        (resources / 'owned.txt').write_text(marker or label)
        args = ['publish', '-PartifactName=' + artifact, '-PpublicationVersion=' + version,
                '-PpublishDependency=' + str(artifact == 'gradle-app').lower(), '-PpublicationURL=' + h.BASE + '/r/' + repo + '/']
        command(directory, work / 'publisher-home', args, token, read_repo or repo)
        files = {'jar': directory / ('build/libs/' + artifact + '-' + version + '.jar'),
                 'pom': directory / 'build/publications/mavenJava/pom-default.xml',
                 'module': directory / 'build/publications/mavenJava/module.json'}
        check('stock Gradle produced all three publication representations ' + label, all(p.is_file() for p in files.values()))
        with zipfile.ZipFile(files['jar']) as archive:
            check('owned Gradle JAR has only inert resources ' + label,
                  set(archive.namelist()) == {'META-INF/', 'META-INF/MANIFEST.MF', 'owned.txt'} and archive.read('owned.txt').decode() == (marker or label))
        contents = {ext: p.read_bytes() for ext, p in files.items()}
        for ext, value in contents.items():
            check('owned Gradle publication stays within the fixture budget ' + label + ' ' + ext, len(value) <= 1 << 20)
            contract['fixture_sha256'][label + '_' + ext] = hashlib.sha256(value).hexdigest()
        references = publication_references(artifact, version, contents, inventory(repo, 'other' if token == 'other' else 'admin'))
        check('exact retained Gradle paths, digests and sizes match the publication ' + label, len(references) == 3)
        for ext, reference in references.items():
            contract['reference_sha256'][label + '_' + ext] = reference['digest']
        published[label] = {'artifact': artifact, 'version': version, 'contents': contents, 'references': references, 'repo': repo}
        return directory, args

    def inventory(repo, token='admin'):
        code, body, _ = req('/api/v1/repositories/' + repo + '/artifacts?limit=100', token)
        data = json.loads(body)
        check('bounded complete Gradle repository inventory ' + repo, code == 200 and not data.get('next'))
        return data['items']

    def wire(label, token='reader', denied=False):
        publication = published[label]
        for ext, reference in publication['references'].items():
            url = h.BASE + '/r/' + publication['repo'] + '/' + reference['path']
            request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + h.tokens[token]})
            try:
                response = urllib.request.urlopen(request, timeout=15)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                body = response.read((1 << 20) + 1)
                check('raw Gradle readback remains on the exact owned URL and within budget ' + label + ' ' + ext,
                      response.geturl() == url and len(body) <= 1 << 20)
                if denied:
                    check('raw Gradle publication is denied before review ' + label + ' ' + ext, response.code == 403)
                else:
                    check('raw Gradle HTTP bytes equal publisher bytes and retained digest ' + label + ' ' + ext,
                          response.code == 200 and body == publication['contents'][ext] and
                          hashlib.sha256(body).hexdigest() == reference['digest'])
                    contract['wire_sha256'][label + '_' + ext] = hashlib.sha256(body).hexdigest()

    def decision(repo, artifact, version, value):
        prefix = GROUP_PATH + '/' + artifact + '/' + version + '/'
        rows = [a for a in inventory(repo) if a['path'].startswith(prefix)]
        check('decision identifies retained Gradle references', bool(rows))
        for a in rows:
            check('current common policy applies to Gradle reference', req('/api/v1/repositories/' + repo + '/decisions', method='PUT',
                  data={'path': a['path'], 'digest': a['digest'], 'decision': value}, key=h.uuid.uuid4().hex)[0] == 200)

    contract['phase'] = 'publication'
    publish('dependency', 'gradle-dep', '1.0.0')
    decision('gradle-hosted', 'gradle-dep', '1.0.0', 'allowed')
    publisher, publish_args = publish('application_1', 'gradle-app', '1.0.0')
    publish('application_2', 'gradle-app', '2.0.0')
    publish('other_dependency', 'gradle-dep', '1.0.0', 'other')
    publish('other_application_1', 'gradle-app', '1.0.0', 'other')
    contract['completed'].append('publication')

    def consume(label, version, expected=None, token='reader', repo='gradle-hosted', metadata='default'):
        directory = project('consume-' + label)
        output = command(directory, work / ('consumer-home-' + label),
                         ['resolveProof', '-PconsumeVersion=' + version, '-PmetadataMode=' + metadata], token, repo, expected is None)
        files = sorted((directory / 'build/proof').glob('*.jar'))
        if expected is None:
            check('rejected Gradle resolution supplies no artifact set ' + label, not files and re.search(r'\b(?:401|403|404)\b', output) is not None)
            return
        want = {published[name]['artifact'] + '-' + published[name]['version'] + '.jar': published[name]['contents']['jar'] for name in expected}
        check('stock Gradle resolves the complete exact transitive set ' + label,
              {p.name: p.read_bytes() for p in files} == want)

    contract['phase'] = 'review'
    consume('unassessed', '1.0.0')
    wire('application_1', denied=True)

    # Metadata used for dynamic resolution has an independent current decision.
    for row in inventory('gradle-hosted'):
        check('approve only the recorded exact Gradle reference', req('/api/v1/repositories/gradle-hosted/decisions', method='PUT',
              data={'path': row['path'], 'digest': row['digest'], 'decision': 'allowed'}, key=h.uuid.uuid4().hex)[0] == 200)
    for label in ['dependency', 'application_1', 'application_2']:
        wire(label)
    for label in ['other_dependency', 'other_application_1']:
        wire(label, 'other')
    consume('hosted-module', '1.0.0', ['application_1', 'dependency'], metadata='module')
    consume('hosted-pom', '2.0.0', ['application_2', 'dependency'], metadata='pom')
    consume('tenant-collision', '1.0.0', ['other_application_1', 'other_dependency'], token='other')
    contract['completed'].append('review_and_tenants')
    output = command(publisher, work / 'reader-publisher-home', publish_args, token='reader', fail=True)
    check('native Gradle publication enforces the read-only credential', re.search(r'\b403\b', output) is not None)
    contract['completed'].append('reader_publication_denied')

    contract['phase'] = 'proxy_group'
    h.repository('gradle-proxy', 'maven', mode='proxy', settings={'upstream': {'url': h.BASE + '/r/gradle-hosted/', 'networks': ['127.0.0.1/32'], 'credential_ref': 'gradle-self'}, 'cache': {'fresh_seconds': 60, 'negative_seconds': 2, 'stale_seconds': 0, 'allow_no_store': True, 'require_checksum': True}})
    h.repository('gradle-local', 'maven')
    h.repository('gradle-group', 'maven', mode='group', settings={'members': ['gradle-local', 'gradle-proxy']})
    publish('local_application_3', 'gradle-app', '3.0.0', repo='gradle-local', read_repo='gradle-group')
    wire('local_application_3')
    consume('group-module', '2.0.0', ['application_2', 'dependency'], repo='gradle-group', metadata='module')
    consume('group-range', '[1.0,4.0)', ['local_application_3', 'dependency'], repo='gradle-group')
    check('Gradle proxy uses checksum-validated durable publications', all(a['metadata'].get('upstream_checksum') == 'sha256_verified' for a in inventory('gradle-proxy')))
    contract['completed'].append('proxy_group')

    contract['phase'] = 'policy'
    decision('gradle-proxy', 'gradle-app', '2.0.0', 'denied')
    consume('denied-group', '2.0.0', repo='gradle-group')
    decision('gradle-proxy', 'gradle-app', '2.0.0', 'allowed')
    h.stop(); h.start()
    consume('restarted-group', '2.0.0', ['application_2', 'dependency'], repo='gradle-group')
    contract['completed'].append('policy_and_restart')

    contract['phase'] = 'snapshots'
    publish('snapshot_first', 'gradle-app', '4.0-SNAPSHOT', repo='gradle-local', read_repo='gradle-group')
    wire('snapshot_first')
    consume('snapshot-first', '4.0-SNAPSHOT', ['snapshot_first', 'dependency'], repo='gradle-group')
    publish('snapshot_second', 'gradle-app', '4.0-SNAPSHOT', repo='gradle-local', read_repo='gradle-group')
    wire('snapshot_second')
    # The new snapshot must not overwrite the immutable prior timestamped files.
    wire('snapshot_first')
    consume('snapshot-second', '4.0-SNAPSHOT', ['snapshot_second', 'dependency'], repo='gradle-group')
    check('new stock Gradle snapshot publication preserves a distinct exact payload', published['snapshot_first']['contents']['jar'] != published['snapshot_second']['contents']['jar'])
    contract['completed'].append('snapshots')

    contract['phase'] = 'revocation'
    h.run([h.BIN / 'cratectld', 'revoke', '--token-file', writer_file])
    rejected = command(publisher, work / 'revoked-publisher-home', publish_args, token='gradle-writer', fail=True)
    check('stock Gradle publication rejects the revoked writer credential', re.search(r'\b401\b', rejected) is not None)
    h.run([h.BIN / 'cratectld', 'revoke', '--token-file', h.PRIVATE / 'reader.token'])
    consume('revoked-reader', '1.0.0')
    consume('other-tenant-after-revocation', '1.0.0', ['other_application_1', 'other_dependency'], token='other')
    contract['completed'].append('revocation')
    check('all owned Gradle fixture identities are retained', set(contract['fixture_sha256']) == {name + '_' + ext for name in FIXTURES for ext in ['jar', 'pom', 'module']})
    contract['phase'] = 'complete'
