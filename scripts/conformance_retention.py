#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned schema-6 upgrade and stock-client retained retirement/recovery."""
import argparse,datetime,hashlib,json,os,socket,subprocess,time,urllib.error,urllib.parse,urllib.request,uuid
from pathlib import Path

parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT);RUN=uuid.uuid4().hex[:10]
PRIVATE=ROOT/'.private/retention-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
OLD=ROOT/'.cache/schedule-final-production/cratectld';NEW=ROOT/'bin/cratectld';CLI=ROOT/'bin/cratectl';ORAS=ROOT/'.cache/bin/oras';BASE='http://127.0.0.1:38443'
env=dict(os.environ);tokens={};checks=[];commands=[];processes={};logs={}
def identity(binary):
    out={}
    for line in subprocess.check_output([ROOT/'.cache/go/bin/go','version','-m',binary],text=True).splitlines():
        parts=line.strip().split('\t')
        if len(parts)==2 and parts[0]=='build'and '='in parts[1]:key,value=parts[1].split('=',1);out[key]=value
    return out
scope=['cmd','internal','scripts','web','api','go.mod','go.sum','Makefile'];candidate=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
result={'run':RUN,'candidate':candidate,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*scope]).strip()),'checks':checks,'commands':commands,'build_identity':{str(p.relative_to(ROOT)):identity(p)for p in [OLD,NEW,CLI]},'artifact_digests':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in [OLD,NEW,CLI,ORAS]},'topology':'Native macOS arm64, retained qualified schema-6 binary then schema-7 registry/worker, PostgreSQL 16.15 forced RLS and restricted runtime; stock ORAS and management CLI. Explicit HTTP loopback 38443. Registry/worker environments omit the owner DSN.','limits':['Named canonical OCI manifest age/newest/tag/hold/reference retirement only. No physical erasure, last-access selection, automatic scheduling or reclaimed storage.','Hosted/proxy/group native consumption, current authority and exact retained-byte restore within this owned fixture. Other rules/formats, providers/platforms, fault/clock/scale and production recovery remain required.','Controlled maintenance stops old processes before migration; rolling compatibility and consistent backup/restore remain open.']}
result['build_source_matches_candidate']=all(result['build_identity'][str(p.relative_to(ROOT))].get('vcs.revision')==candidate and result['build_identity'][str(p.relative_to(ROOT))].get('vcs.modified')=='false'for p in [NEW,CLI])
def check(label,condition):
    if not condition:raise AssertionError(label)
    checks.append(label)
def private(name,value):
    p=PRIVATE/name;p.write_bytes(value if isinstance(value,bytes)else json.dumps(value).encode());p.chmod(0o600);return p
def run(argv,extra=None,input_bytes=None,ok=True,cwd=PRIVATE):
    e=dict(env);e.update(extra or {})
    if Path(str(argv[0])).name in ['oras','cratectl']:
        for key in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']:e.pop(key,None)
    p=subprocess.run([str(a)for a in argv],env=e,input=input_bytes,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90)
    text=p.stdout.decode(errors='replace')
    for value in tokens.values():text=text.replace(value,'[REDACTED]')
    commands.append({'argv':[str(a).replace(str(PRIVATE),'PRIVATE')for a in argv],'exit':p.returncode,'expected_failure':not ok,'output':text[-8000:]})
    if (p.returncode==0)!=ok:raise AssertionError('native command status '+Path(str(argv[0])).name+': '+text[-1000:])
    return p.stdout
def stop(name):
    p=processes.pop(name,None)
    if p and p.poll()is None:
        p.terminate()
        try:p.wait(timeout=10)
        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
    if name in logs:logs.pop(name).close()
def start(name,binary,worker=False,reject=False):
    logs[name]=(PRIVATE/(name+'.log')).open('ab');argv=[binary,'worker'if worker else'serve','--objects',PRIVATE/'objects']
    if worker:argv+=['--identities',PRIVATE/'workers.json','--poll','20ms']
    else:argv+=['--listen','127.0.0.1:38443','--public-url',BASE,'--dev-loopback-http','--allow-private-upstreams','127.0.0.1/32','--upstream-credentials',PRIVATE/'upstreams.json']
    runtime=dict(env);runtime.pop('CRATECTL_OWNER_DSN',None)
    processes[name]=subprocess.Popen([str(a)for a in argv],env=runtime,stdout=logs[name],stderr=subprocess.STDOUT)
    if reject:
        try:code=processes[name].wait(timeout=5)
        except subprocess.TimeoutExpired:stop(name);raise AssertionError('old worker remained admitted to schema 7')
        text=(PRIVATE/(name+'.log')).read_text(errors='replace');check('actual schema-6 worker rejects the schema-7 database',code!=0 and 'schema'in text.lower()and 'flag provided but not defined'not in text);stop(name);return
    if not worker:
        for _ in range(150):
            if processes[name].poll()is not None:raise AssertionError('owned registry exited; inspect private log')
            try:
                with urllib.request.urlopen(BASE+'/health/ready',timeout=1)as r:
                    if r.status==200:return
            except OSError:time.sleep(.05)
        raise AssertionError('owned registry readiness timeout')
def api(path,method='GET',body=None,key=None,role='admin',headers=None):
    if isinstance(body,dict):body=json.dumps(body).encode()
    h={'Authorization':'Bearer '+tokens[role],'Content-Type':'application/json'};h.update(headers or {})
    if key:h['Idempotency-Key']=key
    request=urllib.request.Request(BASE+path,data=body,method=method,headers=h)
    try:r=urllib.request.urlopen(request,timeout=15)
    except urllib.error.HTTPError as error:r=error
    with r:return r.status,r.read(),dict(r.headers)
def get(path,role='admin'):
    code,body,_=api(path,role=role)
    if code!=200:raise AssertionError('management observation status '+str(code))
    return json.loads(body)
def cli(path,body=None,key=None,role='admin',method='POST',ok=True):
    argv=[CLI,'--url',BASE,'--token-file',PRIVATE/(role+'.token'),'--path',path]
    if body is not None:argv+=['--method',method,'--body-file',private('request.json',body),'--idempotency-key',key or uuid.uuid4().hex]
    raw=run(argv,ok=ok)
    return json.loads(raw)if ok else raw
def oras(*argv,ok=True,reader=False,cwd=PRIVATE):return run([ORAS,*argv,'--plain-http','--registry-config',PRIVATE/('reader-auth.json'if reader else'publisher-auth.json')],ok=ok,cwd=cwd)
def policy(repo,name='age'):return '/api/v1/repositories/'+repo+'/retention-policies/'+name
def configure(repo,tagged=True,keep=1,revision=0,enabled=True,name='age',role='admin'):
    body={'expected_revision':revision,'min_age_seconds':60,'keep_last':keep,'protect_tagged':tagged,'enabled':enabled,'reason':'Owned native retained retirement'}
    return cli(policy(repo,name),body,method='PUT',role=role)
def preview(repo,name='age',role='admin'):
    return cli(policy(repo,name)+'/runs',{'expected_revision':get(policy(repo,name),role)['revision'],'reason':'Approve exact owned native targets','dry_run':True},role=role)
def approved(plan):return {'expected_revision':plan['policy']['revision'],'reason':plan['reason'],'evaluated_at':plan['evaluated_at'],'preview_digest':plan['preview_digest']}
def admit(repo,plan,name='age',role='admin',key=None):return cli(policy(repo,name)+'/runs',approved(plan),key=key,role=role)['job']
def await_job(id,state='succeeded',role='admin'):
    deadline=time.monotonic()+40
    while time.monotonic()<deadline:
        value=get('/api/v1/maintenance/retention-runs/'+id,role)
        if value['job']['state']==state:return value
        if value['job']['state']in ['failed','cancelled']and state=='succeeded':raise AssertionError('retirement did not succeed: '+value['job']['last_error'])
        time.sleep(.1)
    raise AssertionError('retirement durable state timeout')
def pull(repo,digest,label,expected,ok=True):
    directory=PRIVATE/label;directory.mkdir();oras('pull','127.0.0.1:38443/'+repo+'/proof@'+digest,ok=ok,reader=True,cwd=directory)
    if ok:check('stock ORAS exact application/dependency bytes after '+label,(directory/'primary.txt').read_bytes()==expected and(directory/'dependency.txt').read_bytes()==dependency)
def restore(repo,root,role='admin'):
    path='proof/manifests/'+root;state=get('/api/v1/repositories/'+repo+'/artifacts/lifecycle?'+urllib.parse.urlencode({'path':path}),role)
    return cli('/api/v1/repositories/'+repo+'/artifacts/lifecycle',{'path':path,'digest':root[7:],'expected_revision':state['revision'],'action':'restore','reason':'Verify exact retained native bytes'},method='PUT',role=role)
try:
    with socket.socket()as probe:check('owned native port is available',probe.connect_ex(('127.0.0.1',38443))!=0)
    if args.require_clean_build:check('retention source and artifacts identify one clean candidate',not result['source_dirty']and result['build_source_matches_candidate'])
    check('retained baseline is qualified clean schema-6 source',identity(OLD).get('vcs.revision')=='b19d1ae393320a2adc051f61db24693fec62591a'and identity(OLD).get('vcs.modified')=='false')
    u=urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN']);database='cratectl_retention_'+RUN;pgenv=dict(env,PGHOST=u.hostname,PGPORT=str(u.port),PGUSER=urllib.parse.unquote(u.username),PGPASSWORD=urllib.parse.unquote(u.password),PGDATABASE=u.path.lstrip('/'))
    run([ROOT/'.cache/postgresql-16.15-install/bin/psql','-X','-At','-v','ON_ERROR_STOP=1','-c','CREATE DATABASE '+database],pgenv)
    for key in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']:
        u=urllib.parse.urlsplit(env[key]);env[key]=urllib.parse.urlunsplit((u.scheme,u.netloc,'/'+database,u.query,u.fragment))
    private('database.json',{'owner':env['CRATECTL_OWNER_DSN'],'runtime':env['CRATECTL_DSN']});run([OLD,'migrate']);before=json.loads(run([OLD,'migrate','--plan']));check('baseline database has six safe frozen receipts',len(before['applied'])==6 and before['safety_valid'])
    tenant='retention-'+RUN
    for role,kind,target in [('admin','admin',tenant),('recovery','admin',tenant),('reader','reader',tenant),('worker','worker',tenant),('other','admin',tenant+'-other')]:
        file=PRIVATE/(role+'.token');run([OLD,'provision','--tenant',target,'--actor',role,'--role',kind,'--token-file',file]);tokens[role]=file.read_text().strip()
    private('workers.json',{'token_files':[str(PRIVATE/'worker.token')]});private('upstreams.json',{tenant+'/self':{'value':tokens['reader'],'allowed_url':BASE+'/v2/containers/'}})
    start('registry',OLD)
    check('old baseline creates hosted OCI',api('/api/v1/repositories','POST',{'name':'containers','format':'oci'},'create-containers')[0]==201)
    check('old baseline has no retention administration route',api(policy('containers'))[0]==404)
    for role,file in [('admin','publisher-auth.json'),('reader','reader-auth.json')]:run([ORAS,'login','--plain-http','--registry-config',PRIVATE/file,'--username','token','--password-stdin','127.0.0.1:38443'],input_bytes=(tokens[role]+'\n').encode())
    dependency=b'owned independent native retention dependency\n'*1024;private('dependency.txt',dependency)
    roots=[];payloads=[]
    for label in ['held','eligible','child']:
        body=('owned native retention '+label+'\n').encode()*2048;payloads.append(body);private('primary.txt',body)
        oras('push','127.0.0.1:38443/containers/proof:latest','primary.txt:text/plain','dependency.txt:text/plain');roots.append(oras('resolve','127.0.0.1:38443/containers/proof:latest').decode().strip())
        if label=='eligible':
            settings={'upstream':{'url':BASE+'/v2/containers/','networks':['127.0.0.1/32'],'credential_ref':'self'},'cache':{'fresh_seconds':3600,'stale_seconds':0,'allow_no_store':True}}
            check('old baseline creates governed proxy/group',api('/api/v1/repositories','POST',{'name':'cache','format':'oci','mode':'proxy','settings':settings},'create-cache')[0]==201 and api('/api/v1/repositories','POST',{'name':'combined','format':'oci','mode':'group','settings':{'members':['cache','containers']}},'create-combined')[0]==201)
            pull('cache',roots[-1],'old-proxy-pull',body)
    pull('containers',roots[2],'old-hosted-pull',payloads[2])
    child_manifest=api('/v2/containers/proof/manifests/'+roots[2])[1];child=json.loads(child_manifest)
    check('native index descriptor names exact retained child bytes',hashlib.sha256(child_manifest).hexdigest()==roots[2][7:])
    index={'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','manifests':[{'mediaType':child['mediaType'],'digest':roots[2],'size':len(child_manifest)}]};private('index.json',index)
    oras('manifest','push','127.0.0.1:38443/containers/proof:latest','index.json','--media-type','application/vnd.oci.image.index.v1+json');index_digest=oras('resolve','127.0.0.1:38443/containers/proof:latest').decode().strip()
    check('old baseline establishes an active retained hold',api('/api/v1/repositories/containers/artifacts/lifecycle','PUT',{'path':'proof/manifests/'+roots[0],'digest':roots[0][7:],'action':'hold','expected_revision':0,'reason':'Preserve owned retained release'},'hold-root')[0]==200)
    source=urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN'])
    run([ROOT/'.cache/postgresql-16.15-install/bin/psql','-X','-At','-v','ON_ERROR_STOP=1','-c',"UPDATE cratectl.artifacts SET created_at=created_at-interval '600 seconds' WHERE tenant='"+tenant+"'"],dict(pgenv,PGDATABASE=source.path.lstrip('/')))
    stop('registry');plan=json.loads(run([NEW,'migrate','--plan']));check('new migrator plans only retention schema 7',plan['pending']==[7]and plan['safety_valid']);run([NEW,'migrate']);after=json.loads(run([NEW,'migrate','--plan']));check('controlled upgrade preserves all six receipts and adds safe retention tables',after['applied'][:6]==before['applied']and len(after['applied'])==7 and not after['pending']and after['safety_valid']);start('old-worker',OLD,worker=True,reject=True);run([OLD,'migrate','--plan'],ok=False)
    start('registry',NEW);start('worker',NEW,worker=True)
    configure('cache',tagged=False,keep=0);proxy_plan=preview('cache');check('proxy retirement preview selects its retained canonical manifest',proxy_plan['eligible']==1)
    proxy_job=admit('cache',proxy_plan);check('proxy retirement records one immutable outcome',await_job(proxy_job)['retired']==1)
    cache_code,cache_body,_=api('/v2/cache/proof/manifests/'+roots[1]);group_code,group_body,_=api('/v2/combined/proof/manifests/'+roots[1])
    check('local proxy tombstone prevents group fallback to still-live hosted content',cache_code==404 and b'artifact_deleted'in cache_body and group_code==404 and b'artifact_deleted'in group_body and api('/v2/containers/proof/manifests/'+roots[1])[0]==200)
    pull('combined',roots[1],'retired-group',payloads[1],ok=False);restore('cache',roots[1]);pull('combined',roots[1],'restored-group',payloads[1])
    configure('containers');selection=preview('containers');statuses={item['digest']:item['status']for item in selection['items']};check('hosted preview retains hold/current-tag/strong-parent protections',selection['eligible']==1 and statuses[roots[0][7:]]=='held'and statuses[roots[1][7:]]=='eligible'and statuses[roots[2][7:]]=='referenced'and statuses[index_digest[7:]]=='tagged')
    oras('tag','127.0.0.1:38443/containers/proof@'+roots[1],'late');cli(policy('containers')+'/runs',approved(selection),ok=False);check('changed native tag impact cannot cross an earlier preview',len(get(policy('containers')+'/runs')['items'])==0);check('remove only the owned late tag binding',api('/v2/containers/proof/manifests/late','DELETE')[0]==202)
    check('current manual digest denial is established before retirement',api('/api/v1/repositories/containers/decisions','PUT',{'path':'proof/manifests/'+roots[1],'digest':roots[1][7:],'decision':'denied'},'deny-root')[0]==200)
    selection=preview('containers');body=json.dumps(approved(selection)).encode();key='unread-response-'+RUN;stop('worker')
    with socket.create_connection(('127.0.0.1',38443),timeout=10)as connection:
        head=('POST '+policy('containers')+'/runs HTTP/1.1\r\nHost: 127.0.0.1:38443\r\nAuthorization: Bearer '+tokens['admin']+'\r\nIdempotency-Key: '+key+'\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body))+'\r\n\r\n').encode();connection.sendall(head+body)
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            rows=get(policy('containers')+'/runs')['items']
            if rows:break
            time.sleep(.05)
        check('native response is deliberately unread after independently observed admission',len(rows)==1)
    first=rows[0]['job'];replayed=cli(policy('containers')+'/runs',approved(selection),key=key);check('management CLI confirms exactly one lost-response admission',replayed['job']==first and len(get(policy('containers')+'/runs')['items'])==1)
    stop('registry');start('registry',NEW);check('actual registry restart retains the pending approved job',get('/api/v1/maintenance/retention-runs/'+first)['job']['state']=='pending');start('worker',NEW,worker=True)
    outcome=await_job(first);check('hosted retirement records exact bounded outcomes and no reclaimed bytes',outcome['retired']==1 and outcome['skipped']==3 and outcome['all_targets_processed']and outcome['bytes_reclaimed']==0)
    observed=get('/api/v1/maintenance/retention-runs/'+first+'/items?limit=100')['items'];check('immutable native target observations preserve every protection',sum(row['outcome']=='retired'for row in observed)==1 and any(row['outcome']=='held'for row in observed)and any(row['outcome']=='referenced'for row in observed))
    pull('containers',roots[1],'retired-hosted',payloads[1],ok=False);pull('containers',roots[0],'held-still-live',payloads[0]);pull('containers',roots[2],'child-still-live',payloads[2])
    restore('containers',roots[1]);pull('containers',roots[1],'restored-still-denied',payloads[1],ok=False)
    retained=get('/api/v1/repositories/containers/artifacts/reference?'+urllib.parse.urlencode({'path':'proof/manifests/'+roots[1]}))
    check('restore preserves the current explicit digest denial',retained['digest']==roots[1][7:]and retained['decision']=='denied'and api('/v2/containers/proof/manifests/'+roots[1])[0]==403)
    check('explicit current manual approval permits serving the restored exact digest',api('/api/v1/repositories/containers/decisions','PUT',{'path':'proof/manifests/'+roots[1],'digest':roots[1][7:],'decision':'allowed'},'allow-restored-root')[0]==200);pull('containers',roots[1],'restored-exact-hosted',payloads[1]);check('restore does not rebind the current native tag',oras('resolve','127.0.0.1:38443/containers/proof:latest').decode().strip()==index_digest)
    stop('worker');pending=admit('containers',preview('containers'));cli('/api/v1/jobs/'+pending+'/cancel',{});check('cancellation before worker execution leaves zero committed target effects',get('/api/v1/maintenance/retention-runs/'+pending)['job']['state']=='cancelled'and get('/api/v1/maintenance/retention-runs/'+pending)['retired']==0)
    revoked=admit('containers',preview('containers'));run([NEW,'revoke','--token-file',PRIVATE/'admin.token']);start('worker',NEW,worker=True);failed=await_job(revoked,'failed','recovery');check('revoked original requester cannot delegate retirement after worker restart',failed['job']['last_error']=='retention_requester_authorization'and failed['retired']==0)
    recovered=admit('containers',preview('containers',role='recovery'),role='recovery');check('replacement administrator supplies a fresh approved retirement',await_job(recovered,role='recovery')['retired']==1)
    check('reader/worker/other-tenant credentials cannot administer retention',api(policy('containers'),role='reader')[0]==403 and api(policy('containers'),role='worker')[0]==401 and api(policy('containers'),role='other')[0]==404)
    configure('containers',revision=1,enabled=False,role='recovery');check('disabled current policy retains immutable configuration and run history',len(get(policy('containers')+'/history?limit=100','recovery')['items'])==2 and len(get(policy('containers')+'/runs?limit=100','recovery')['items'])==4)
    result['status']='passed';result['database']=database
except BaseException as error:result['status']='failed';result['failure']=type(error).__name__+': '+str(error)
finally:
    for name in list(processes):stop(name)
    target=ROOT/'evidence'/datetime.datetime.now(datetime.timezone.utc).date().isoformat();target.mkdir(parents=True,exist_ok=True);path=target/('retention-'+RUN+'.json');path.write_text(json.dumps(result,indent=2)+'\n');print(result['status'].upper()+': '+str(len(checks))+' assertions; native retained retirement; '+str(path))
if result['status']!='passed':raise SystemExit(result.get('failure','native retention failed'))
