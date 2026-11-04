# SPDX-License-Identifier: BUSL-1.1
"""Stock SBT1/2 publication and fresh consumers against the governed store."""
import hashlib
import json
import platform
import re
import shutil
import urllib.error
import urllib.request
import zipfile

from bounded_client import run_owned_client
from ci.sbt_evidence import FIXTURES
from sbt_fixture import GROUP,build_definition,check_runtime_config,configure_runtime,copy_seed,invocation,seed_manifest

GROUP_PATH=GROUP.replace('.','/')


def hosted(h,series):
    check,req=h.check,h.req
    pin=json.loads((h.ROOT/'docs/qualification/jvm-clients.json').read_text())[series]
    distribution=h.ROOT/('.cache/sbt-'+pin['version']+'.tgz')
    launcher=h.ROOT/('.cache/sbt-'+pin['version']+'/bin/sbt-launch.jar')
    jdk=h.ROOT/'.cache/jdk-21.0.13+9/Contents/Home'
    check('real pinned SBT distribution and launcher exist',distribution.is_file() and launcher.is_file())
    with distribution.open('rb') as source: digest=hashlib.file_digest(source,'sha256').hexdigest()
    check('SBT distribution has exact reviewed bytes',digest==pin['sha256'])
    release_bytes=(jdk/'release').read_bytes();check('SBT Java metadata stays bounded',len(release_bytes)<=65536)
    release={k:v.strip('"') for line in release_bytes.decode().splitlines() if '=' in line for k,v in [line.split('=',1)]}
    check('SBT uses the actual pinned native Linux Java',platform.system()=='Linux' and release.get('JAVA_RUNTIME_VERSION') in ['21.0.13+9','21.0.13+9-LTS'] and release.get('OS_NAME')=='Linux' and release.get('OS_ARCH')=={'x86_64':'x86_64','aarch64':'aarch64'}[platform.machine()])
    contract={'profile':'maven-release-v1','series':series,'version':pin['version'],'runtime_version':None,
              'java_version':release['JAVA_RUNTIME_VERSION'],'distribution_sha256':digest,
              'launcher_sha256':hashlib.sha256(launcher.read_bytes()).hexdigest(),
              'java_launcher_sha256':hashlib.sha256((jdk/'bin/java').read_bytes()).hexdigest(),
              'java_release_sha256':hashlib.sha256(release_bytes).hexdigest(),
              'fixture_source_sha256':hashlib.sha256((h.ROOT/'scripts/sbt_fixture.py').read_bytes()).hexdigest(),
              'bootstrap_cache':None,'bootstrap_boot':None,'fixture_sha256':{},'reference_sha256':{},'wire_sha256':{},
              'completed':[],'phase':'bootstrap','diagnostics':[]}
    h.result['sbt_contract']=contract
    work=h.PRIVATE/series;work.mkdir(mode=0o700)
    seed=work/'tool-seed';seed.mkdir(mode=0o700)
    runtime=work/'runtime';runtime.mkdir(mode=0o700)
    configure_runtime(runtime)
    seed_identity=None

    def project(label,bootstrap=False):
        directory=work/label;directory.mkdir(mode=0o700)
        (directory/'project').mkdir(mode=0o700)
        (directory/'project/build.properties').write_text('sbt.version='+pin['version']+'\n')
        (directory/'build.sbt').write_text(build_definition(series,bootstrap))
        (directory/'publication').mkdir(mode=0o700)
        resources=directory/'resources';resources.mkdir(mode=0o700);(resources/'owned.txt').write_text(label)
        return directory

    def command(directory,task,artifact='consumer',version='1.0.0',dependency=None,token='reader',repo='sbt-hosted',fail=False,bootstrap=False,publication_repo=None):
        cache=seed if bootstrap else directory/('cache-'+str(len(h.commands)))
        if not bootstrap: copy_seed(seed,cache,seed_identity)
        repositories=directory/('repositories-'+str(len(h.commands)))
        repository='https://repo.maven.apache.org/maven2/' if bootstrap else h.BASE+'/r/'+repo+'/'
        repositories.write_text('[repositories]\ncratectl: '+repository+'\n');repositories.chmod(0o600)
        properties={'cratectl.group':'dev.cratectl.toolbootstrap' if bootstrap else GROUP,'cratectl.artifact':artifact,
                    'cratectl.version':version,'cratectl.repository':repository,'cratectl.cache':cache,
                    'cratectl.publication':repository if bootstrap else h.BASE+'/r/'+(publication_repo or repo)+'/'}
        if not bootstrap:
            credential=directory/('credential-'+str(len(h.commands))+'.properties')
            value=h.tokens[token]
            # Provisioned tokens are single-line ASCII; never put one in argv or a URL.
            check('SBT credential fits its private properties representation',bool(value) and value.isascii() and not any(c in value for c in '\r\n\\'))
            credential.write_text('realm=cratectl\nhost=127.0.0.1\nuser=token\npassword='+value+'\n');credential.chmod(0o600)
            properties['cratectl.credentials']=credential
            if dependency:properties.update({'cratectl.dependencyArtifact':dependency[0],'cratectl.dependencyVersion':dependency[1]})
        argv,environment=invocation(jdk,launcher,runtime,cache,repositories,h.env,properties,task,series)
        try:
            code,output=run_owned_client(argv,directory,environment,timeout=300 if bootstrap else 120)
        finally:
            # Each command gets independent cache bytes. Proof/publication files
            # survive outside this owned disposable cache; the seed never changes.
            if not bootstrap:shutil.rmtree(cache)
        check_runtime_config(runtime)
        for value in h.tokens.values():output=output.replace(value,'[REDACTED]')
        h.commands.append({'argv':[str(a).replace(str(h.PRIVATE),'PRIVATE') for a in argv],'exit':code,'output':output[-12000:],'expected_failure':fail})
        if code and not fail:
            patterns={'http_401':r'\b401\b','http_403':r'\b403\b','http_404':r'\b404\b','fixture_compilation':r'compilation failed|not found:|type mismatch|Not a valid',
                      'dependency_resolution':r'unresolved|not found|Error downloading|ResolveException','publication':r'publish|PUT','checksum':r'checksum','jvm':r'Unsupported class|Virtual Machine|OutOfMemory'}
            contract['diagnostics']=sorted(k for k,v in patterns.items() if re.search(v,output,re.I))
        check('stock '+series+(' rejects ' if fail else ' completes ')+directory.name,(code!=0) if fail else (code==0))
        return output

    bootstrap=project('tool-bootstrap',bootstrap=True)
    observed=command(bootstrap,'packageBin;makePom;show sbtVersion',artifact='owned-tool-bootstrap',version='0.0.0',bootstrap=True)
    versions=re.findall(r'(?m)^\[info\]\s+([12]\.\d{1,3}\.\d{1,3})\s*$',observed)
    contract['runtime_version']=versions[-1] if versions else None
    check('actual observed SBT runtime matches the pinned series',contract['runtime_version']==pin['version'])
    seed_identity=seed_manifest(seed)
    boot_identity=seed_manifest(runtime/'boot')
    check('actual SBT boot libraries have a nonempty bounded identity',boot_identity['files']>0 and boot_identity['bytes']>0)
    contract['bootstrap_cache']=seed_identity
    contract['bootstrap_boot']=boot_identity
    contract['phase']='client_identity';contract['completed'].append('client_identity')
    h.repository('sbt-hosted','maven',review=True,access='restricted')
    h.repository('sbt-hosted','maven','other')
    check('grant only intended native SBT reader',req('/api/v1/repositories/sbt-hosted/grants',method='PUT',data={'actor':'reader','read':True,'write':False},key=h.uuid.uuid4().hex)[0]==200)
    writer=h.PRIVATE/'sbt-writer.token'
    h.run([h.BIN/'cratectld','provision','--tenant',h.tenants['admin'],'--actor','sbt-writer','--role','writer','--token-file',writer]);h.tokens['sbt-writer']=writer.read_text().strip()
    check('grant only intended native SBT writer',req('/api/v1/repositories/sbt-hosted/grants',method='PUT',data={'actor':'sbt-writer','read':True,'write':True},key=h.uuid.uuid4().hex)[0]==200)
    published={}

    def inventory(repo,token='admin'):
        code,body,_=req('/api/v1/repositories/'+repo+'/artifacts?limit=100',token);data=json.loads(body)
        check('bounded complete SBT retained inventory '+repo,code==200 and not data.get('next') and len(data['items'])<=100)
        return data['items']

    def publish(label,artifact,version,token='sbt-writer',repo='sbt-hosted',read_repo=None):
        directory=project('publish-'+label)
        dependency=('sbt-dep','1.0.0') if artifact=='sbt-app' else None
        # The read source remains explicit even when publishing to a local group member.
        command(directory,'publish',artifact,version,dependency,token,read_repo or repo,publication_repo=repo)
        contents={ext:(directory/('publication/'+artifact+'-'+version+'.'+ext)).read_bytes() for ext in ['jar','pom']}
        with zipfile.ZipFile(directory/('publication/'+artifact+'-'+version+'.jar')) as archive:
            names=set(archive.namelist())
            check('SBT publication contains only owned inert resources '+label,
                  {'META-INF/MANIFEST.MF','owned.txt'}<=names<= {'META-INF/','META-INF/MANIFEST.MF','owned.txt'} and archive.read('owned.txt').decode()=='publish-'+label)
        rows=inventory(repo,'other' if token=='other' else 'admin');paths={}
        for ext,value in contents.items():
            path=GROUP_PATH+'/'+artifact+'/'+version+'/'+artifact+'-'+version+'.'+ext;matches=[r for r in rows if r['path']==path];digest=hashlib.sha256(value).hexdigest()
            check('SBT publisher bytes equal exact retained path/digest/size '+label+ext,len(value)<=1<<20 and len(matches)==1 and matches[0]['digest']==digest and matches[0]['size']==len(value))
            contract['fixture_sha256'][label+'_'+ext]=digest;contract['reference_sha256'][label+'_'+ext]=matches[0]['digest'];paths[ext]=path
        published[label]={'artifact':artifact,'version':version,'contents':contents,'paths':paths,'repo':repo}
        return directory,dependency

    def decision(repo,artifact,version,value):
        prefix=GROUP_PATH+'/'+artifact+'/'+version+'/'
        rows=[r for r in inventory(repo) if r['path'].startswith(prefix)]
        check('SBT current policy identifies exact retained representations',bool(rows))
        for row in rows:check('SBT reference follows common current policy',req('/api/v1/repositories/'+repo+'/decisions',method='PUT',data={'path':row['path'],'digest':row['digest'],'decision':value},key=h.uuid.uuid4().hex)[0]==200)

    def wire(label,token='reader',denied_status=None):
        row=published[label]
        for ext,path in row['paths'].items():
            url=h.BASE+'/r/'+row['repo']+'/'+path
            request=urllib.request.Request(url,headers={'Authorization':'Bearer '+h.tokens[token]})
            try:response=urllib.request.urlopen(request,timeout=15)
            except urllib.error.HTTPError as error:response=error
            with response:
                body=response.read((1<<20)+1)
                check('SBT HTTP readback uses exact owned URL and bounded body',response.geturl()==url and len(body)<=1<<20)
                check('SBT exact raw byte/policy observation '+label+ext,response.code==denied_status if denied_status else response.code==200 and body==row['contents'][ext])
                if not denied_status:contract['wire_sha256'][label+'_'+ext]=hashlib.sha256(body).hexdigest()

    def consume(label,version,expected=None,token='reader',repo='sbt-hosted',denied_status=403):
        directory=project('consume-'+label)
        command(directory,'verifyOwned',dependency=('sbt-app',version),token=token,repo=repo,fail=expected is None)
        files=sorted((directory/'proof').glob('*.jar'))
        check('SBT proof file set stays bounded',len(files)<=16 and all(p.stat().st_size<=1<<20 for p in files))
        if expected is None:
            check('denied SBT resolution has no complete artifact set '+label,not files)
            path=GROUP_PATH+'/sbt-app/'+version+'/sbt-app-'+version+'.pom'
            check('same-credential HTTP explains native SBT denial '+label,req('/r/'+repo+'/'+path,token)[0]==denied_status)
        else:
            check('SBT resolves the complete exact transitive bytes '+label,{p.name:p.read_bytes() for p in files}=={published[n]['artifact']+'-'+published[n]['version']+'.jar':published[n]['contents']['jar'] for n in expected})

    contract['phase']='publication'
    publish('dependency','sbt-dep','1.0.0');decision('sbt-hosted','sbt-dep','1.0.0','allowed')
    publish('application_1','sbt-app','1.0.0')
    publish('application_2','sbt-app','2.0.0')
    publish('other_dependency','sbt-dep','1.0.0','other');publish('other_application_1','sbt-app','1.0.0','other')
    contract['completed'].append('publication');contract['phase']='review'
    consume('unassessed','1.0.0');wire('application_1',denied_status=403)
    for row in inventory('sbt-hosted'):
        check('approve exact native SBT reference',req('/api/v1/repositories/sbt-hosted/decisions',method='PUT',data={'path':row['path'],'digest':row['digest'],'decision':'allowed'},key=h.uuid.uuid4().hex)[0]==200)
    for label in ['dependency','application_1','application_2']:wire(label)
    for label in ['other_dependency','other_application_1']:wire(label,'other')
    consume('hosted','1.0.0',['application_1','dependency']);consume('updated','2.0.0',['application_2','dependency'])
    consume('tenant-collision','1.0.0',['other_application_1','other_dependency'],'other')
    contract['completed'].append('review_and_tenants')
    reader_publisher=project('reader-forbidden-publication')
    command(reader_publisher,'publish','sbt-app','4.0.0',('sbt-dep','1.0.0'),'reader',fail=True)
    reader_path=GROUP_PATH+'/sbt-app/4.0.0/sbt-app-4.0.0.pom'
    reader_pom=(reader_publisher/'publication/sbt-app-4.0.0.pom').read_bytes()
    check('reader cannot PUT its exact fresh SBT generated POM',req('/r/sbt-hosted/'+reader_path,'reader','PUT',reader_pom,headers={'Content-Type':'application/xml'})[0]==403)
    check('reader native publication retains no partial version',not any(r['path'].startswith(GROUP_PATH+'/sbt-app/4.0.0/') for r in inventory('sbt-hosted')))
    contract['completed'].append('reader_publication_denied');contract['phase']='proxy_group'
    h.repository('sbt-proxy','maven',mode='proxy',settings={'upstream':{'url':h.BASE+'/r/sbt-hosted/','networks':['127.0.0.1/32'],'credential_ref':'sbt-self'},'cache':{'fresh_seconds':60,'negative_seconds':2,'stale_seconds':0,'allow_no_store':True,'require_checksum':True}})
    h.repository('sbt-local','maven');h.repository('sbt-group','maven',mode='group',settings={'members':['sbt-local','sbt-proxy']})
    # The local app's dependency remains on its sole configured group read source;
    # publication and consumption use separate named resolver properties below.
    publish('local_application_3','sbt-app','3.0.0',repo='sbt-local',read_repo='sbt-group')
    wire('local_application_3')
    consume('group','2.0.0',['application_2','dependency'],repo='sbt-group')
    consume('group-range','[1.0,4.0)',['local_application_3','dependency'],repo='sbt-group')
    cached=inventory('sbt-proxy');check('SBT proxy retains checksum-verified bytes',len(cached)>=4 and all(r['metadata'].get('upstream_checksum')=='sha256_verified' for r in cached))
    contract['completed'].append('proxy_group');contract['phase']='policy'
    decision('sbt-proxy','sbt-app','2.0.0','denied');consume('denied-group','2.0.0',repo='sbt-group')
    decision('sbt-proxy','sbt-app','2.0.0','allowed');h.stop();h.start();consume('restarted-group','2.0.0',['application_2','dependency'],repo='sbt-group')
    contract['completed'].append('policy_and_restart');contract['phase']='revocation'
    revoked_publisher=project('revoked-writer-publication')
    command(revoked_publisher,'packageBin;makePom','sbt-app','5.0.0',('sbt-dep','1.0.0'),'sbt-writer')
    h.run([h.BIN/'cratectld','revoke','--token-file',writer])
    command(revoked_publisher,'publish','sbt-app','5.0.0',('sbt-dep','1.0.0'),'sbt-writer',fail=True)
    revoked_path=GROUP_PATH+'/sbt-app/5.0.0/sbt-app-5.0.0.pom'
    revoked_pom=(revoked_publisher/'publication/sbt-app-5.0.0.pom').read_bytes()
    check('revoked writer cannot PUT exact fresh SBT POM',req('/r/sbt-hosted/'+revoked_path,'sbt-writer','PUT',revoked_pom,headers={'Content-Type':'application/xml'})[0]==401)
    check('revoked writer native publication retains no partial version',not any(r['path'].startswith(GROUP_PATH+'/sbt-app/5.0.0/') for r in inventory('sbt-hosted')))
    h.run([h.BIN/'cratectld','revoke','--token-file',h.PRIVATE/'reader.token']);consume('revoked-reader','1.0.0',denied_status=401);wire('application_1',denied_status=401)
    consume('other-tenant-after-revocation','1.0.0',['other_application_1','other_dependency'],'other')
    contract['completed'].append('revocation')
    expected={n+'_'+e for n in FIXTURES for e in ['jar','pom']}
    check('all twelve SBT representations have independent byte binding',set(contract['fixture_sha256'])==expected and contract['fixture_sha256']==contract['reference_sha256']==contract['wire_sha256'])
    contract['phase']='complete'
