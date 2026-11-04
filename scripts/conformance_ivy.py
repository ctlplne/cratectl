# SPDX-License-Identifier: BUSL-1.1
"""Stock Ant/Ivy publisher and fresh transitive consumers; real common store."""
import hashlib
import json
import platform
import re
import shutil
import urllib.error
import urllib.request
import xml.etree.ElementTree as XML
import zipfile

from bounded_client import run_owned_client
from ci.ivy_evidence import FIXTURES

GROUP = 'dev.cratectl.ivyproof'
GROUP_PATH = GROUP.replace('.', '/')


def descriptor(artifact, version, dependency=None, publish=True):
    root = XML.Element('ivy-module', version='2.0')
    XML.SubElement(root, 'info', organisation=GROUP, module=artifact, revision=version, status='release')
    configurations = XML.SubElement(root, 'configurations')
    XML.SubElement(configurations, 'conf', name='default', visibility='public')
    if publish:
        publications = XML.SubElement(root, 'publications')
        for ext in ['jar', 'pom']:
            XML.SubElement(publications, 'artifact', name=artifact, type=ext, ext=ext, conf='default')
    if dependency:
        dependencies = XML.SubElement(root, 'dependencies')
        XML.SubElement(dependencies, 'dependency', org=GROUP, name=dependency[0], rev=dependency[1], conf='default->default')
    return XML.tostring(root, encoding='utf-8', xml_declaration=True)


def hosted(h):
    check, req = h.check, h.req
    pin = json.loads((h.ROOT / 'docs/qualification/jvm-clients.json').read_text())['ivy']
    ant = h.ROOT / ('.cache/apache-ant-' + pin['ant_version'] + '/bin/ant')
    ivy = h.ROOT / ('.cache/apache-ivy-' + pin['version'] + '/ivy-' + pin['version'] + '.jar')
    jdk = h.ROOT / '.cache/jdk-21.0.13+9/Contents/Home'
    check('real pinned Ant/Ivy clients are installed', ant.is_file() and ivy.is_file())
    archives = {}
    for name, version, expected in [('ivy', pin['version'], pin['sha512']), ('ant', pin['ant_version'], pin['ant_sha512'])]:
        archive = h.ROOT / ('.cache/apache-' + name + '-' + version + '-bin.tar.gz')
        with archive.open('rb') as source:
            digest = hashlib.file_digest(source, 'sha512').hexdigest()
        check('official pinned distribution bytes match ' + name, digest == expected)
        archives[name + '_distribution_sha512'] = digest
    release_bytes = (jdk / 'release').read_bytes()
    check('Ivy JDK metadata is bounded', len(release_bytes) <= 65536)
    release = {key: value.strip('"') for line in release_bytes.decode().splitlines() if '=' in line for key, value in [line.split('=', 1)]}
    check('Ivy uses the exact native pinned Java runtime', release.get('JAVA_RUNTIME_VERSION') in ('21.0.13+9', '21.0.13+9-LTS') and
          platform.system() == 'Linux' and release.get('OS_NAME') == 'Linux' and release.get('OS_ARCH') == {'x86_64': 'x86_64', 'aarch64': 'aarch64'}[platform.machine()])
    source = h.ROOT / 'scripts/fixtures/ivy-client'
    contract = {'profile':'maven-release-v1', 'version': pin['version'], 'ant_version': pin['ant_version'], **archives,
                'java_version': release['JAVA_RUNTIME_VERSION'],
                'java_launcher_sha256': hashlib.sha256((jdk / 'bin/java').read_bytes()).hexdigest(),
                'java_release_sha256': hashlib.sha256(release_bytes).hexdigest(),
                'ivy_launcher_sha256': hashlib.sha256(ivy.read_bytes()).hexdigest(),
                'ant_launcher_sha256': hashlib.sha256(ant.read_bytes()).hexdigest(),
                'ant_library_sha256': hashlib.sha256((ant.parent.parent / 'lib/ant.jar').read_bytes()).hexdigest(),
                'fixture_source_sha256': hashlib.sha256(b''.join((source / n).read_bytes() for n in ['build.xml', 'ivysettings.xml'])).hexdigest(),
                'fixture_sha256': {}, 'reference_sha256': {}, 'wire_sha256': {}, 'completed': [], 'phase': 'client_identity', 'diagnostics': []}
    h.result['ivy_contract'] = contract
    work = h.PRIVATE / 'ivy'; work.mkdir(mode=0o700)

    def project(label):
        directory = work / label; directory.mkdir(mode=0o700)
        for name in ['build.xml', 'ivysettings.xml']:
            shutil.copy2(source / name, directory / name)
        return directory

    def command(directory, target, token='reader', repo='ivy-hosted', read_repo=None, extra=(), fail=False):
        environment = dict(h.env, JAVA_HOME=str(jdk), ANT_OPTS='-Xmx512m -XX:MaxMetaspaceSize=384m')
        argv = [ant, '-noinput', '-lib', ivy, '-DivyCache=' + str(directory / 'cache'),
                '-Divy.default.ivy.user.dir=' + str(directory / 'ivy-home'),
                '-DcredentialFile=' + str(h.PRIVATE / (token + '.token')),
                '-DrepositoryURL=' + h.BASE + '/r/' + (read_repo or repo) + '/',
                '-DpublicationURL=' + h.BASE + '/r/' + repo + '/', *extra, target]
        code, output = run_owned_client(argv, directory, environment)
        for value in h.tokens.values(): output = output.replace(value, '[REDACTED]')
        h.commands.append({'argv': [str(a).replace(str(h.PRIVATE), 'PRIVATE') for a in argv], 'exit': code, 'output': output[-12000:], 'expected_failure': fail})
        if not fail and code:
            contract['diagnostics'] = sorted(k for k, pattern in {'http_401': r'\b401\b', 'http_403': r'\b403\b', 'http_404': r'\b404\b', 'resolution': r'unresolved dependency|not found|impossible to resolve', 'publication': r'publish failed|impossible to publish|PUT', 'fixture': r'failed to create task|doesn.t support|problem.*settings'}.items() if re.search(pattern, output, re.I))
        check('stock Ant/Ivy ' + ('rejects ' if fail else 'completes ') + directory.name, (code != 0) if fail else (code == 0))
        return output

    identity = project('identity')
    check('actual Ant version matches the pinned client', ('Apache Ant(TM) version ' + pin['ant_version']) in command(identity, '-version'))
    code, output = run_owned_client([jdk / 'bin/java', '-Xmx256m', '-jar', ivy, '-version'], identity, dict(h.env))
    check('actual Ivy version matches the pinned client', code == 0 and ('Apache Ivy ' + pin['version']) in output)
    contract['completed'].append('client_identity')
    h.repository('ivy-hosted', 'maven', review=True, access='restricted')
    h.repository('ivy-hosted', 'maven', 'other')
    check('grant only the intended Ivy reader', req('/api/v1/repositories/ivy-hosted/grants', method='PUT', data={'actor':'reader','read':True,'write':False}, key=h.uuid.uuid4().hex)[0] == 200)
    writer = h.PRIVATE / 'ivy-writer.token'
    h.run([h.BIN / 'cratectld', 'provision', '--tenant', h.tenants['admin'], '--actor', 'ivy-writer', '--role', 'writer', '--token-file', writer])
    h.tokens['ivy-writer'] = writer.read_text().strip()
    check('grant only the intended Ivy writer', req('/api/v1/repositories/ivy-hosted/grants', method='PUT', data={'actor':'ivy-writer','read':True,'write':True}, key=h.uuid.uuid4().hex)[0] == 200)
    published = {}

    def inventory(repo, token='admin'):
        code, body, _ = req('/api/v1/repositories/' + repo + '/artifacts?limit=100', token)
        data = json.loads(body)
        check('bounded complete Ivy inventory ' + repo, code == 200 and not data.get('next') and len(data['items']) <= 100)
        return data['items']

    def publish(label, artifact, version, token='ivy-writer', repo='ivy-hosted', read_repo=None):
        directory = project('publish-' + label)
        resources = directory / 'resources'; resources.mkdir()
        (resources / 'owned.txt').write_text(label)
        (directory / 'ivy.xml').write_bytes(descriptor(artifact, version, ('ivy-dep','1.0.0') if artifact == 'ivy-app' else None))
        extra = ['-DartifactName=' + artifact, '-DpublicationVersion=' + version]
        command(directory, 'publish', token, repo, read_repo, extra)
        contents = {ext:(directory / ('build/' + artifact + '-' + version + '.' + ext)).read_bytes() for ext in ['jar','pom']}
        with zipfile.ZipFile(directory / ('build/' + artifact + '-' + version + '.jar')) as archive:
            check('Ivy archive contains only inert owned resources ' + label, set(archive.namelist()) == {'META-INF/', 'META-INF/MANIFEST.MF', 'owned.txt'} and archive.read('owned.txt').decode() == label)
        rows = inventory(repo, 'other' if token == 'other' else 'admin')
        paths = {}
        for ext, value in contents.items():
            key = label + '_' + ext; path = GROUP_PATH + '/' + artifact + '/' + version + '/' + artifact + '-' + version + '.' + ext
            matches = [row for row in rows if row['path'] == path]; digest = hashlib.sha256(value).hexdigest()
            check('Ivy publication is bounded and matches exact retained bytes ' + key, len(value) <= 1 << 20 and len(matches) == 1 and matches[0]['digest'] == digest and matches[0]['size'] == len(value))
            contract['fixture_sha256'][key] = digest; contract['reference_sha256'][key] = matches[0]['digest']; paths[ext] = path
        published[label] = {'artifact':artifact,'version':version,'contents':contents,'paths':paths,'repo':repo}
        return directory, extra

    def decision(repo, artifact, version, value):
        prefix = GROUP_PATH + '/' + artifact + '/' + version + '/'
        rows = [r for r in inventory(repo) if r['path'].startswith(prefix)]
        check('Ivy policy identifies current references', bool(rows))
        for row in rows:
            check('current common policy governs Ivy reference', req('/api/v1/repositories/' + repo + '/decisions', method='PUT', data={'path':row['path'],'digest':row['digest'],'decision':value}, key=h.uuid.uuid4().hex)[0] == 200)

    def wire(label, token='reader', denied=False):
        row = published[label]
        for ext, path in row['paths'].items():
            url = h.BASE + '/r/' + row['repo'] + '/' + path
            request = urllib.request.Request(url, headers={'Authorization':'Bearer ' + h.tokens[token]})
            try:
                response = urllib.request.urlopen(request, timeout=15)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                body = response.read((1 << 20) + 1); code = response.code
                check('Ivy readback stays on its exact owned URL and within budget', response.geturl() == url and len(body) <= 1 << 20)
            check('raw Ivy bytes enforce review ' + label + ext if denied else 'raw Ivy HTTP bytes match publisher/reference ' + label + ext,
                  code == 403 if denied else code == 200 and body == row['contents'][ext])
            if not denied: contract['wire_sha256'][label + '_' + ext] = hashlib.sha256(body).hexdigest()

    def consume(label, version, expected=None, token='reader', repo='ivy-hosted', denied_status=403):
        directory = project('consume-' + label)
        (directory / 'ivy.xml').write_bytes(descriptor('consumer', '1.0.0', ('ivy-app',version), publish=False))
        output = command(directory, 'consume', token, repo, fail=expected is None)
        files = sorted((directory / 'proof').glob('*.jar'))
        if expected is None:
            check('denied stock Ivy resolution has no artifact set ' + label, not files)
            path = '/r/' + repo + '/' + GROUP_PATH + '/ivy-app/' + version + '/ivy-app-' + version + '.pom'
            check('independent same-credential HTTP denial explains Ivy failure ' + label, req(path, token)[0] == denied_status)
        else:
            check('stock Ivy resolves the complete exact transitive bytes ' + label, {p.name:p.read_bytes() for p in files} == {published[n]['artifact'] + '-' + published[n]['version'] + '.jar':published[n]['contents']['jar'] for n in expected})

    contract['phase'] = 'publication'
    publish('dependency','ivy-dep','1.0.0'); decision('ivy-hosted','ivy-dep','1.0.0','allowed')
    publisher, extra = publish('application_1','ivy-app','1.0.0')
    publish('application_2','ivy-app','2.0.0')
    publish('other_dependency','ivy-dep','1.0.0','other')
    publish('other_application_1','ivy-app','1.0.0','other')
    contract['completed'].append('publication')
    contract['phase'] = 'review'
    consume('unassessed','1.0.0'); wire('application_1',denied=True)
    for row in inventory('ivy-hosted'):
        check('approve exact retained Ivy reference', req('/api/v1/repositories/ivy-hosted/decisions',method='PUT',data={'path':row['path'],'digest':row['digest'],'decision':'allowed'},key=h.uuid.uuid4().hex)[0] == 200)
    for label in ['dependency','application_1','application_2']: wire(label)
    for label in ['other_dependency','other_application_1']: wire(label,'other')
    consume('hosted','1.0.0',['application_1','dependency'])
    consume('hosted-update','2.0.0',['application_2','dependency'])
    consume('tenant-collision','1.0.0',['other_application_1','other_dependency'],'other')
    contract['completed'].append('review_and_tenants')
    rejected = command(publisher,'publish','reader',extra=extra,fail=True)
    app = published['application_1']
    check('read-only Ivy credential cannot PUT its exact generated POM', req('/r/ivy-hosted/' + app['paths']['pom'],'reader','PUT',app['contents']['pom'],headers={'Content-Type':'application/xml'})[0] == 403)
    contract['completed'].append('reader_publication_denied')
    contract['phase'] = 'proxy_group'
    h.repository('ivy-proxy','maven',mode='proxy',settings={'upstream':{'url':h.BASE+'/r/ivy-hosted/','networks':['127.0.0.1/32'],'credential_ref':'ivy-self'},'cache':{'fresh_seconds':60,'negative_seconds':2,'stale_seconds':0,'allow_no_store':True,'require_checksum':True}})
    h.repository('ivy-local','maven')
    h.repository('ivy-group','maven',mode='group',settings={'members':['ivy-local','ivy-proxy']})
    publish('local_application_3','ivy-app','3.0.0',repo='ivy-local',read_repo='ivy-group'); wire('local_application_3')
    consume('group','2.0.0',['application_2','dependency'],repo='ivy-group')
    consume('group-range','[1.0,4.0)',['local_application_3','dependency'],repo='ivy-group')
    cached = inventory('ivy-proxy')
    check('Ivy proxy retains checksum-validated bytes', len(cached) >= 4 and all(row['metadata'].get('upstream_checksum') == 'sha256_verified' for row in cached))
    contract['completed'].append('proxy_group')
    contract['phase'] = 'policy'
    decision('ivy-proxy','ivy-app','2.0.0','denied'); consume('denied-group','2.0.0',repo='ivy-group')
    decision('ivy-proxy','ivy-app','2.0.0','allowed'); h.stop(); h.start()
    consume('restarted-group','2.0.0',['application_2','dependency'],repo='ivy-group')
    contract['completed'].append('policy_and_restart')
    contract['phase'] = 'revocation'
    h.run([h.BIN/'cratectld','revoke','--token-file',writer])
    rejected = command(publisher,'publish','ivy-writer',extra=extra,fail=True)
    check('revoked Ivy credential cannot PUT its exact generated POM', req('/r/ivy-hosted/' + app['paths']['pom'],'ivy-writer','PUT',app['contents']['pom'],headers={'Content-Type':'application/xml'})[0] == 401)
    h.run([h.BIN/'cratectld','revoke','--token-file',h.PRIVATE/'reader.token'])
    consume('revoked-reader','1.0.0',denied_status=401)
    consume('other-tenant-after-revocation','1.0.0',['other_application_1','other_dependency'],'other')
    contract['completed'].append('revocation')
    check('all twelve Ivy representations have independent byte binding', set(contract['fixture_sha256']) == {n+'_'+ext for n in FIXTURES for ext in ['jar','pom']} and contract['fixture_sha256'] == contract['reference_sha256'] == contract['wire_sha256'])
    contract['phase']='complete'
