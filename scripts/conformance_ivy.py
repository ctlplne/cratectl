# SPDX-License-Identifier: BUSL-1.1
"""Stock Ant/Ivy publisher and fresh transitive consumers; real common store."""
import hashlib
import json
import platform
import re
import shutil
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as XML
import zipfile

from bounded_client import run_owned_client
from ci.ivy_evidence import FIXTURES, METADATA_CASES, METADATA_REPRESENTATIONS, SNAPSHOT_CASES, SNAPSHOT_FIXTURES, CACHE_STAGES
from ivy_metadata_fixture import MODULES, consumer_descriptor, filename, pom, publisher_descriptor

GROUP = 'dev.cratectl.ivyproof'
GROUP_PATH = GROUP.replace('.', '/')


def ant_invocation(ant_home, ivy, jdk, environment):
    """Invoke the official bootstrap JAR without host shell/config substitution."""
    clean = {k:v for k,v in environment.items() if k not in {
        'ANT_ARGS','ANT_OPTS','JAVACMD','JAVA_OPTS','JAVA_TOOL_OPTIONS',
        'JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','CLASSPATH_OVERRIDE'}}
    clean.update(ANT_HOME=str(ant_home), JAVA_HOME=str(jdk))
    return [jdk / 'bin/java', '-Xmx512m', '-XX:MaxMetaspaceSize=384m', '-XX:ActiveProcessorCount=2',
            '-Dant.home=' + str(ant_home), '-classpath', ant_home / 'lib/ant-launcher.jar',
            'org.apache.tools.ant.launch.Launcher', '-nouserlib', '-noclasspath', '-lib', ivy, '-noinput'], clean


def changing_settings(data):
    """Change only the owned retained-cache consumer's snapshot read policy."""
    root = XML.fromstring(data)
    readers = root.findall('resolvers/ibiblio')
    if len(readers) != 1:
        raise ValueError('Retained-cache proof requires one explicit Maven reader')
    readers[0].set('checkmodified', 'true')
    readers[0].set('changingPattern', '.*-SNAPSHOT')
    readers[0].set('changingMatcher', 'regexp')
    return XML.tostring(root, encoding='utf-8', xml_declaration=True)


def cached_snapshot_bytes(cache):
    """Read the bounded original POMs and JARs from the actual Ivy cache."""
    paths = {'app_jar':'ivy-app/jars/ivy-app-1.1-SNAPSHOT.jar',
             'app_pom':'ivy-app/ivy-1.1-SNAPSHOT.xml.original',
             'dependency_jar':'ivy-dep/jars/ivy-dep-1.0.0.jar',
             'dependency_pom':'ivy-dep/ivy-1.0.0.xml.original'}
    result = {}
    for name, relative in paths.items():
        path = cache / GROUP / relative
        if any(p.is_symlink() for p in [path, cache, *path.parents[:len(path.relative_to(cache).parts)-1]]):
            raise ValueError('Ivy cache proof cannot follow linked paths')
        if not path.is_file():
            raise ValueError('Ivy cache representation must be a regular file')
        with path.open('rb') as source:
            data = source.read((1 << 20) + 1)
        if len(data) > 1 << 20:
            raise ValueError('Ivy cache representation exceeds the owned fixture budget')
        result[name] = data
    return result


def descriptor(artifact, version, dependency=None, publish=True, description=None, changing=False):
    root = XML.Element('ivy-module', version='2.0')
    info = XML.SubElement(root, 'info', organisation=GROUP, module=artifact, revision=version, status='release')
    if description is not None:
        XML.SubElement(info, 'description').text = description
    configurations = XML.SubElement(root, 'configurations')
    XML.SubElement(configurations, 'conf', name='default', visibility='public')
    if publish:
        publications = XML.SubElement(root, 'publications')
        for ext in ['jar', 'pom']:
            XML.SubElement(publications, 'artifact', name=artifact, type=ext, ext=ext, conf='default')
    if dependency:
        dependencies = XML.SubElement(root, 'dependencies')
        item = XML.SubElement(dependencies, 'dependency', org=GROUP, name=dependency[0], rev=dependency[1], conf='default->default')
        if changing:
            item.set('changing', 'true')
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
    contract = {'profile':'maven-snapshot-cache-v4', 'version': pin['version'], 'ant_version': pin['ant_version'], **archives,
                'java_version': release['JAVA_RUNTIME_VERSION'],
                'java_launcher_sha256': hashlib.sha256((jdk / 'bin/java').read_bytes()).hexdigest(),
                'java_release_sha256': hashlib.sha256(release_bytes).hexdigest(),
                'ivy_launcher_sha256': hashlib.sha256(ivy.read_bytes()).hexdigest(),
                'ant_launcher_sha256': hashlib.sha256(ant.read_bytes()).hexdigest(),
                'ant_bootstrap_sha256': hashlib.sha256((ant.parent.parent / 'lib/ant-launcher.jar').read_bytes()).hexdigest(),
                'ant_runtime_version': None,
                'ant_legacy_runtime_version': None,
                'ant_library_sha256': hashlib.sha256((ant.parent.parent / 'lib/ant.jar').read_bytes()).hexdigest(),
                'fixture_source_sha256': hashlib.sha256(b''.join((source / n).read_bytes() for n in ['build.xml', 'ivysettings.xml']) +
                                                        (h.ROOT/'scripts/ivy_metadata_fixture.py').read_bytes()).hexdigest(),
                'fixture_sha256': {}, 'reference_sha256': {}, 'wire_sha256': {}, 'completed': [], 'phase': 'client_identity', 'diagnostics': []}
    contract['checksum_clients_completed'] = []
    contract['metadata_cases_completed'] = []
    contract['snapshot_cases_completed'] = []
    contract['cache_completed'] = []
    contract['cache_reused'] = False
    contract['cache_sha256'] = {}
    h.result['ivy_contract'] = contract
    work = h.PRIVATE / 'ivy'; work.mkdir(mode=0o700)

    def project(label):
        directory = work / label; directory.mkdir(mode=0o700)
        for name in ['build.xml', 'ivysettings.xml']:
            shutil.copy2(source / name, directory / name)
        return directory

    def command(directory, target, token='reader', repo='ivy-hosted', read_repo=None, extra=(), fail=False, checksum_algorithms='SHA-256,sha1,md5'):
        argv, environment = ant_invocation(ant.parent.parent, ivy, jdk, h.env)
        argv += ['-DivyCache=' + str(directory / 'cache'),
                '-DchecksumAlgorithms=' + checksum_algorithms,
                '-Divy.default.ivy.user.dir=' + str(directory / 'ivy-home'),
                '-DcredentialFile=' + str(h.PRIVATE / (token + '.token')),
                '-DrepositoryURL=' + h.BASE + '/r/' + (read_repo or repo) + '/',
                '-DpublicationURL=' + h.BASE + '/r/' + repo + '/', *extra, target]
        code, output = run_owned_client(argv, directory, environment)
        for value in h.tokens.values(): output = output.replace(value, '[REDACTED]')
        h.commands.append({'argv': [str(a).replace(str(h.PRIVATE), 'PRIVATE') for a in argv], 'exit': code, 'output': output[-12000:], 'expected_failure': fail})
        if not fail and code:
            contract['diagnostics'] = sorted(k for k, pattern in {'http_401': r'\b401\b', 'http_403': r'\b403\b', 'http_404': r'\b404\b', 'resolution': r'unresolved dependency|not found|impossible to resolve', 'publication': r'publish failed|impossible to publish|PUT', 'fixture': r'failed to create task|doesn.t support|problem.*settings', 'checksum_algorithm': r'Unknown checksum algorithm'}.items() if re.search(pattern, output, re.I))
        check('stock Ant/Ivy ' + ('rejects ' if fail else 'completes ') + directory.name, (code != 0) if fail else (code == 0))
        return output

    identity = project('identity')
    # Read-only replay of the original launcher selection. A future runner may
    # ship the same Ant version, so this observation never substitutes for the
    # pinned bootstrap assertion below or forces a particular host version.
    legacy_environment = dict(h.env, JAVA_HOME=str(jdk), ANT_OPTS='-Xmx512m -XX:MaxMetaspaceSize=384m')
    legacy_code, legacy_output = run_owned_client([ant, '-noinput', '-lib', ivy, '-version'], identity, legacy_environment)
    legacy_observed = re.search(r'^Apache Ant\(TM\) version (\d{1,2}\.\d{1,3}\.\d{1,3})(?:\s|$)', legacy_output, re.M)
    if legacy_code == 0 and legacy_observed:
        contract['ant_legacy_runtime_version'] = legacy_observed.group(1)
    ant_version = command(identity, '-version')
    observed = re.search(r'^Apache Ant\(TM\) version (\d{1,2}\.\d{1,3}\.\d{1,3})(?:\s|$)', ant_version, re.M)
    contract['ant_runtime_version'] = observed.group(1) if observed else None
    if contract['ant_runtime_version'] != pin['ant_version']:
        contract['diagnostics'] = ['ant_identity']
    check('actual Ant version matches the pinned client', contract['ant_runtime_version'] == pin['ant_version'])
    _, java_environment = ant_invocation(ant.parent.parent, ivy, jdk, h.env)
    code, output = run_owned_client([jdk / 'bin/java', '-Xmx256m', '-jar', ivy, '-version'], identity, java_environment)
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
        (directory / 'ivy.xml').write_bytes(descriptor(artifact, version, ('ivy-dep','1.0.0') if artifact == 'ivy-app' else None,
                                                    description=label if label in ['snapshot_first','snapshot_second'] else None))
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

    def wire(label, token='reader', denied=False, denied_status=403):
        row = published[label]
        representations = [(ext,path,row['contents'][ext],True) for ext,path in row['paths'].items()]
        for ext,path in row['paths'].items():
            for suffix, function in [('SHA-256',hashlib.sha256),('SHA-384',hashlib.sha384),('SHA-512',hashlib.sha512)]:
                representations.append((ext+'_'+suffix,path+'.'+suffix,function(row['contents'][ext]).hexdigest().encode(),False))
        for ext, path, expected, payload in representations:
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
                  code == denied_status if denied else code == 200 and body == expected)
            if not denied and payload: contract['wire_sha256'][label + '_' + ext] = hashlib.sha256(body).hexdigest()

    def consume(label, version, expected=None, token='reader', repo='ivy-hosted', denied_status=403, checksum_algorithms='SHA-256,sha1,md5'):
        directory = project('consume-' + label)
        (directory / 'ivy.xml').write_bytes(descriptor('consumer', '1.0.0', ('ivy-app',version), publish=False))
        output = command(directory, 'consume', token, repo, fail=expected is None, checksum_algorithms=checksum_algorithms)
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
    contract['checksum_clients_completed'].append('SHA-256')
    consume('hosted-sha384','1.0.0',['application_1','dependency'],checksum_algorithms='SHA-384')
    contract['checksum_clients_completed'].append('SHA-384')
    consume('hosted-sha512','1.0.0',['application_1','dependency'],checksum_algorithms='SHA-512')
    contract['checksum_clients_completed'].append('SHA-512')
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
    contract['phase'] = 'metadata'

    # Native Ivy publishes the exact prepared POM graph and inert JAR variants.
    # No uploaded build rule or class is ever executed by a consumer.
    for label, (artifact, version, representations) in MODULES.items():
        check('reviewed metadata representation inventory ' + label, representations == METADATA_REPRESENTATIONS[label])
        directory = project('metadata-publish-' + label)
        build = directory / 'build'; build.mkdir()
        (directory / 'ivy.xml').write_bytes(publisher_descriptor(artifact,version,representations))
        contents = {}
        for representation in representations:
            target = build / filename(artifact,version,representation)
            if representation == 'pom':
                target.write_bytes(pom(label))
            else:
                with zipfile.ZipFile(target,'w') as archive:
                    archive.writestr('META-INF/',b'')
                    archive.writestr('META-INF/MANIFEST.MF',b'Manifest-Version: 1.0\r\n\r\n')
                    archive.writestr('owned.txt',(label + ':' + representation).encode())
                with zipfile.ZipFile(target) as archive:
                    check('metadata JAR is inert owned resources ' + label + representation,
                          set(archive.namelist()) == {'META-INF/','META-INF/MANIFEST.MF','owned.txt'} and
                          archive.read('owned.txt') == (label + ':' + representation).encode())
            contents[representation] = target.read_bytes()
        command(directory,'publish-prepared','ivy-writer',extra=['-DpublicationVersion='+version])
        rows = inventory('ivy-hosted'); paths = {}
        for representation, value in contents.items():
            path = GROUP_PATH+'/'+artifact+'/'+version+'/'+filename(artifact,version,representation)
            matches = [r for r in rows if r['path'] == path]; digest = hashlib.sha256(value).hexdigest()
            check('metadata publication retains exact native-uploaded bytes ' + label + representation,
                  len(value)<=1<<20 and len(matches)==1 and matches[0]['digest']==digest and matches[0]['size']==len(value))
            key = label+'_'+representation
            contract['fixture_sha256'][key] = digest; contract['reference_sha256'][key] = matches[0]['digest']; paths[representation] = path
        published[label] = {'artifact':artifact,'version':version,'contents':contents,'paths':paths,'repo':'ivy-hosted'}
        # Keep the parent unassessed until a real child consumer proves denial.
        if label != 'parent': decision('ivy-hosted',artifact,version,'allowed')

    def metadata_consume(label, expected=None, dependencies=None, mapping='default->default', classifier=False,
                         exclude=False, repo='ivy-hosted', denied_path=None, denied_status=403):
        directory = project('metadata-consume-' + label)
        (directory/'ivy.xml').write_bytes(consumer_descriptor(dependencies or [('ivy-metadata-app','1.0.0')],mapping,classifier,exclude))
        command(directory,'consume',repo=repo,fail=expected is None)
        files = sorted((directory/'proof').glob('*.jar'))
        check('metadata consumer output stays bounded ' + label, len(files)<=16 and all(p.stat().st_size<=1<<20 for p in files))
        if expected is None:
            check('denied metadata resolution has no retrieved artifact set ' + label, not files)
            check('same-credential HTTP confirms exact metadata denial ' + label,
                  bool(denied_path) and req('/r/'+repo+'/'+denied_path,'reader')[0]==denied_status)
        else:
            exact = {filename(published[n]['artifact'],published[n]['version'],representation):published[n]['contents'][representation]
                     for n,representation in expected}
            check('native metadata graph resolves exact complete byte set ' + label, {p.name:p.read_bytes() for p in files}==exact)

    parent_path = published['parent']['paths']['pom']
    base = [('metadata_app','jar'),('dependency','jar'),('bridge_2','jar')]
    metadata_consume('unassessed-parent',denied_path=parent_path)
    decision('ivy-hosted','ivy-parent','1.0.0','allowed')
    for label in MODULES: wire(label)
    metadata_consume('parent-managed',base)
    contract['metadata_cases_completed'].append('parent_pom')
    classified_path = published['metadata_app']['paths']['tests_jar']
    def classifier_decision(value):
        check('current common policy governs classified JAR',req('/api/v1/repositories/ivy-hosted/decisions',method='PUT',
              data={'path':classified_path,'digest':contract['fixture_sha256']['metadata_app_tests_jar'],'decision':value},key=h.uuid.uuid4().hex)[0]==200)
    classifier_decision('denied')
    metadata_consume('denied-classifier',classifier=True,denied_path=classified_path)
    metadata_consume('default-with-classifier-denied',base)
    classifier_decision('allowed')
    metadata_consume('classified',[('metadata_app','tests_jar'),('dependency','jar'),('bridge_2','jar')],classifier=True)
    contract['metadata_cases_completed'].append('classifier')
    metadata_consume('optional-configuration',base+[('optional_dependency','jar')],mapping='default->default,optional')
    metadata_consume('test-configuration',base+[('test_dependency','jar')],mapping='default->default,test')
    contract['metadata_cases_completed'].append('configurations')
    # The default set already proves POM exclusion of bridge-two's choice2;
    # the separate controls below prove it exists and would otherwise resolve.
    metadata_consume('bridge-control',[('bridge_2','jar'),('choice_2','jar')],dependencies=[('ivy-bridge-two','1.0.0')])
    contract['metadata_cases_completed'].append('pom_exclusion')
    bridges = [('ivy-bridge-one','1.0.0'),('ivy-bridge-two','1.0.0')]
    metadata_consume('client-exclusion',[('bridge_1','jar'),('bridge_2','jar'),('choice_1','jar')],dependencies=bridges,exclude=True)
    contract['metadata_cases_completed'].append('client_exclusion')
    metadata_consume('latest-conflict',[('bridge_1','jar'),('bridge_2','jar'),('choice_2','jar')],dependencies=bridges)
    contract['metadata_cases_completed'].append('latest_conflict')
    metadata_consume('group-parent',base,repo='ivy-group')
    decision('ivy-proxy','ivy-parent','1.0.0','denied')
    metadata_consume('cached-parent-denied',repo='ivy-group',denied_path=parent_path)
    decision('ivy-proxy','ivy-parent','1.0.0','allowed')
    contract['metadata_cases_completed'].append('cached_parent_policy')
    h.stop(); h.start()
    metadata_consume('metadata-restart',base,repo='ivy-group')
    metadata_consume('classified-restart',[('metadata_app','tests_jar'),('dependency','jar'),('bridge_2','jar')],classifier=True,repo='ivy-group')
    contract['metadata_cases_completed'].append('metadata_restart')
    check('every native metadata case completed',contract['metadata_cases_completed']==METADATA_CASES)
    contract['completed'].append('metadata')
    contract['phase'] = 'snapshots'
    h.repository('ivy-snapshot-immutable','maven')
    h.repository('ivy-snapshots','maven',review=True,access='restricted',settings={'maven_snapshot_policy':'redeploy_nonunique'})
    for actor,write in [('reader',False),('ivy-writer',True)]:
        check('grant only intended native snapshot actor '+actor,req('/api/v1/repositories/ivy-snapshots/grants',method='PUT',data={'actor':actor,'read':True,'write':write},key=h.uuid.uuid4().hex)[0]==200)
    h.repository('ivy-snapshot-group','maven',mode='group',settings={'members':['ivy-snapshots','ivy-proxy']})
    snapshot_version='1.1-SNAPSHOT'
    publish('default_snapshot','ivy-app',snapshot_version,repo='ivy-snapshot-immutable',read_repo='ivy-group')
    wire('default_snapshot')

    def snapshot_publisher(label,version=snapshot_version):
        directory=project(label);resources=directory/'resources';resources.mkdir();(resources/'owned.txt').write_text(label)
        (directory/'ivy.xml').write_bytes(descriptor('ivy-app',version,('ivy-dep','1.0.0')))
        return directory,['-DartifactName=ivy-app','-DpublicationVersion='+version]

    rejected_snapshot,rejected_snapshot_extra=snapshot_publisher('immutable-snapshot-replacement')
    command(rejected_snapshot,'publish','ivy-writer','ivy-snapshot-immutable','ivy-group',rejected_snapshot_extra,fail=True)
    wire('default_snapshot')
    contract['snapshot_cases_completed'].append('default_immutable')
    publish('snapshot_first','ivy-app',snapshot_version,repo='ivy-snapshots',read_repo='ivy-group')
    decision('ivy-snapshots','ivy-app',snapshot_version,'allowed');wire('snapshot_first')
    consume('snapshot-first',snapshot_version,['snapshot_first','dependency'],repo='ivy-snapshot-group')
    warm = project('consume-retained-snapshot')
    (warm/'ivysettings.xml').write_bytes(changing_settings((warm/'ivysettings.xml').read_bytes()))
    (warm/'ivy.xml').write_bytes(descriptor('consumer','1.0.0',('ivy-app',snapshot_version),publish=False,changing=True))
    cache = warm/'cache';cache.mkdir()
    check('retained Ivy cache begins without project coordinates',not(cache/GROUP).exists())
    cache_identity=(cache.stat().st_dev,cache.stat().st_ino)
    marker=cache/'cratectl-owned-cache-proof';marker.write_bytes(b'owned cache remains in place\n')

    def warm_bytes(label):
        local=cached_snapshot_bytes(cache)
        expected={'app_'+ext:published[label]['contents'][ext] for ext in ['jar','pom']}
        expected.update({'dependency_'+ext:published['dependency']['contents'][ext]for ext in ['jar','pom']})
        proof={p.name:p.read_bytes() for p in (warm/'proof').glob('*.jar')}
        check('retained Ivy cache, original POMs and retrieved dependency bytes match '+label,
              local==expected and proof=={'ivy-app-1.1-SNAPSHOT.jar':expected['app_jar'],'ivy-dep-1.0.0.jar':expected['dependency_jar']})
        for name,data in local.items():
            key=label+'_'+name.removeprefix('app_') if name.startswith('app_') else name
            contract['cache_sha256'][key]=hashlib.sha256(data).hexdigest()

    command(warm,'consume-changing',repo='ivy-snapshot-group')
    warm_bytes('snapshot_first');contract['cache_completed'].append('initial_resolution')
    module=cache/GROUP/'ivy-app';module_identity=(module.stat().st_dev,module.stat().st_ino)
    module_marker=module/'cratectl-owned-module-proof';module_marker.write_bytes(b'owned snapshot module remains in place\n')

    def same_cache():
        return ((cache.stat().st_dev,cache.stat().st_ino)==cache_identity
                and (module.stat().st_dev,module.stat().st_ino)==module_identity
                and marker.read_bytes()==b'owned cache remains in place\n'
                and module_marker.read_bytes()==b'owned snapshot module remains in place\n')

    publish('snapshot_second','ivy-app',snapshot_version,repo='ivy-snapshots',read_repo='ivy-group')
    first_snapshot=published['snapshot_first'];second_snapshot=published['snapshot_second']
    check('native repeat publication changes actual snapshot JAR bytes',first_snapshot['contents']['jar']!=second_snapshot['contents']['jar'])
    check('native changing snapshot POMs identify distinct actual publications',
          first_snapshot['contents']['pom']!=second_snapshot['contents']['pom']
          and b'snapshot_first' in first_snapshot['contents']['pom'] and b'snapshot_second' in second_snapshot['contents']['pom'])
    contract['snapshot_cases_completed'].append('opt_in_redeploy')
    for ext in ['jar','pom']:
        changed=first_snapshot['contents'][ext]!=second_snapshot['contents'][ext]
        check('current review follows each exact changed snapshot representation '+ext,
              req('/r/ivy-snapshots/'+second_snapshot['paths'][ext],'reader')[0]==(403 if changed else 200))
    blocked,unused=snapshot_publisher('snapshot-unassessed-consumer')
    (blocked/'ivy.xml').write_bytes(descriptor('consumer','1.0.0',('ivy-app',snapshot_version),publish=False))
    command(blocked,'consume',repo='ivy-snapshot-group',fail=True)
    check('unassessed native snapshot consumer has no complete artifact set',not list((blocked/'proof').glob('*.jar')))
    check('same-credential HTTP explains native snapshot review denial',req('/r/ivy-snapshot-group/'+second_snapshot['paths']['jar'],'reader')[0]==403)
    contract['snapshot_cases_completed'].append('review_reset')
    decision('ivy-snapshots','ivy-app',snapshot_version,'allowed');wire('snapshot_second')
    consume('snapshot-second',snapshot_version,['snapshot_second','dependency'],repo='ivy-snapshot-group')
    contract['snapshot_cases_completed'].append('fresh_resolution')
    check('Ivy refresh starts with the original snapshot still cached',cached_snapshot_bytes(cache)['app_jar']==first_snapshot['contents']['jar'])
    command(warm,'consume-changing',repo='ivy-snapshot-group')
    contract['cache_reused']=same_cache()
    check('Ivy changing snapshot refresh retains the same cache and module',contract['cache_reused'])
    warm_bytes('snapshot_second');contract['cache_completed'].append('updated_resolution')
    lifecycle='/api/v1/repositories/ivy-snapshots/artifacts/lifecycle'

    def snapshot_hold(action):
        for ext in ['jar','pom']:
            path=second_snapshot['paths'][ext]
            code,body,_=req(lifecycle+'?path='+urllib.parse.quote(path,safe=''))
            state=json.loads(body);check('read current exact snapshot lifecycle '+ext,code==200 and state['digest']==hashlib.sha256(second_snapshot['contents'][ext]).hexdigest())
            check('apply native snapshot preservation '+action+ext,req(lifecycle,method='PUT',data={'path':path,'digest':state['digest'],'expected_revision':state['revision'],'action':action,'reason':'Owned native snapshot preservation proof'},key=h.uuid.uuid4().hex)[0]==200)

    snapshot_hold('hold')
    held_snapshot,held_extra=snapshot_publisher('held-snapshot-replacement')
    command(held_snapshot,'publish','ivy-writer','ivy-snapshots','ivy-group',held_extra,fail=True)
    wire('snapshot_second');snapshot_hold('release_hold')
    contract['snapshot_cases_completed'].append('held_replacement')
    code,body,_=req('/api/v1/repositories/ivy-snapshots/configuration');configuration=json.loads(body)
    check('native snapshot policy reads current hosted revision',code==200 and configuration['source_revision']==0)
    settings=configuration['settings'];settings['maven_snapshot_policy']='immutable'
    check('disable native snapshot replacement with revision checked policy',req('/api/v1/repositories/ivy-snapshots/configuration',method='PUT',data={'expected_revision':0,'settings':settings,'reason':'Stop further nonunique snapshot replacement'},key=h.uuid.uuid4().hex)[0]==200)
    command(held_snapshot,'publish','ivy-writer','ivy-snapshots','ivy-group',held_extra,fail=True)
    wire('snapshot_second');consume('snapshot-disabled-policy',snapshot_version,['snapshot_second','dependency'],repo='ivy-snapshot-group')
    contract['snapshot_cases_completed'].append('disable_policy')
    h.stop();h.start();consume('snapshot-restart',snapshot_version,['snapshot_second','dependency'],repo='ivy-snapshot-group')
    command(warm,'consume-changing',repo='ivy-snapshot-group')
    check('Ivy restart retains the existing snapshot cache',same_cache())
    warm_bytes('snapshot_second');contract['cache_completed'].append('restart')
    check('every native Ivy retained-cache stage completed',contract['cache_completed']==CACHE_STAGES)
    contract['completed'].append('warm_cache')
    contract['snapshot_cases_completed'].append('restart')
    revoked_snapshot,revoked_snapshot_extra=snapshot_publisher('revoked-fresh-snapshot','9.0-SNAPSHOT')
    command(revoked_snapshot,'prepare','ivy-writer','ivy-snapshots','ivy-group',revoked_snapshot_extra)
    # The prepared POM keeps its real dependency graph. The publisher descriptor
    # describes only these owned outputs, so revocation is tested at native PUT
    # rather than being satisfied by an earlier dependency-read failure.
    (revoked_snapshot/'ivy.xml').write_bytes(publisher_descriptor('ivy-app','9.0-SNAPSHOT',('jar','pom')))
    contract['phase'] = 'revocation'
    h.run([h.BIN/'cratectld','revoke','--token-file',writer])
    command(revoked_snapshot,'publish-prepared','ivy-writer','ivy-snapshots','ivy-group',revoked_snapshot_extra,fail=True)
    revoked_snapshot_path=GROUP_PATH+'/ivy-app/9.0-SNAPSHOT/'
    check('revoked native snapshot writer cannot PUT its exact prepared fresh POM',req('/r/ivy-snapshots/'+revoked_snapshot_path+'ivy-app-9.0-SNAPSHOT.pom','ivy-writer','PUT',(revoked_snapshot/'build/ivy-app-9.0-SNAPSHOT.pom').read_bytes(),headers={'Content-Type':'application/xml'})[0]==401)
    check('revoked native snapshot publication retains no partial version',not any(r['path'].startswith(revoked_snapshot_path) for r in inventory('ivy-snapshots')))
    rejected = command(publisher,'publish','ivy-writer',extra=extra,fail=True)
    check('revoked Ivy credential cannot PUT its exact generated POM', req('/r/ivy-hosted/' + app['paths']['pom'],'ivy-writer','PUT',app['contents']['pom'],headers={'Content-Type':'application/xml'})[0] == 401)
    h.run([h.BIN/'cratectld','revoke','--token-file',h.PRIVATE/'reader.token'])
    consume('revoked-reader','1.0.0',denied_status=401)
    wire('application_1',denied=True,denied_status=401)
    metadata_consume('revoked-metadata',denied_path=published['metadata_app']['paths']['pom'],denied_status=401)
    consume('revoked-snapshot-reader',snapshot_version,repo='ivy-snapshot-group',denied_status=401)
    contract['snapshot_cases_completed'].append('revocation')
    check('every native snapshot case completed',contract['snapshot_cases_completed']==SNAPSHOT_CASES)
    contract['completed'].append('snapshots')
    consume('other-tenant-after-revocation','1.0.0',['other_application_1','other_dependency'],'other')
    contract['completed'].append('revocation')
    expected_bindings = {n+'_'+ext for n in FIXTURES+SNAPSHOT_FIXTURES for ext in ['jar','pom']} | {n+'_'+ext for n,extensions in METADATA_REPRESENTATIONS.items() for ext in extensions}
    check('all thirty-four Ivy representations have independent byte binding', len(expected_bindings)==34 and set(contract['fixture_sha256']) == expected_bindings and contract['fixture_sha256'] == contract['reference_sha256'] == contract['wire_sha256'])
    contract['phase']='complete'
