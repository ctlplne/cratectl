#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned v2/v3 upgrade and stock ORAS retained deletion/recovery, on real PostgreSQL."""
import argparse,datetime,hashlib,json,os,subprocess,time,urllib.error,urllib.parse,urllib.request,uuid
from pathlib import Path

parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');parser.add_argument('--baseline-version',type=int,choices=[2,3],default=2);args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT);RUN=uuid.uuid4().hex[:10]
PRIVATE=ROOT/'.private/lifecycle-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
BASE='http://127.0.0.1:38443';OLD=ROOT/('.cache/maven-final-production/cratectld'if args.baseline_version==2 else'.cache/lifecycle-final-production/cratectld');NEW=ROOT/'bin/cratectld';ORAS=ROOT/'.cache/bin/oras'
env=dict(os.environ);checks=[];commands=[];proc=None;log=None
def identity(binary):
    values={}
    for line in subprocess.check_output([ROOT/'.cache/go/bin/go','version','-m',binary],text=True).splitlines():
        parts=line.strip().split('\t')
        if len(parts)==2 and parts[0]=='build' and '='in parts[1]:key,value=parts[1].split('=',1);values[key]=value
    return values
scope=['cmd','internal','scripts','web','api','go.mod','go.sum','Makefile'];candidate=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
result={'run':RUN,'candidate':candidate,'baseline_version':args.baseline_version,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*scope]).strip()),'checks':checks,'commands':commands,'artifact_digests':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in [OLD,NEW,ROOT/'bin/cratectl',ORAS]},'build_identity':{str(p.relative_to(ROOT)):identity(p)for p in [OLD,NEW,ROOT/'bin/cratectl']},'topology':f'Native macOS arm64, retained clean schema-{args.baseline_version} binary then schema-4 binary, real PostgreSQL 16.15 nonowner forced RLS, stock ORAS; explicit HTTP loopback on 38443.','limits':['Logical retirement retains CAS bytes and all references; no physical erasure or reclaimed storage is claimed.','Source URL/configuration changes, recursive groups, retention/GC, scale, rolling upgrade, backup/restore and other clients/platforms remain required.','This campaign uses controlled maintenance with the registry stopped during migration; it does not establish compatible rolling versions.']}
result['build_source_matches_candidate']=all(result['build_identity'][str(p.relative_to(ROOT))].get('vcs.revision')==candidate and result['build_identity'][str(p.relative_to(ROOT))].get('vcs.modified')=='false'for p in [NEW,ROOT/'bin/cratectl'])
def check(label,value):
    if not value:raise AssertionError(label)
    checks.append(label)
def private(name,value):
    p=PRIVATE/name;p.write_bytes(value if isinstance(value,bytes)else json.dumps(value).encode());p.chmod(0o600);return p
def run(argv,runenv=None,input_bytes=None,ok=True,cwd=PRIVATE):
    start=time.monotonic();p=subprocess.run([str(a)for a in argv],env=runenv or env,input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,cwd=cwd,timeout=120)
    with (PRIVATE/'commands.log').open('ab')as f:f.write(p.stdout)
    (PRIVATE/'commands.log').chmod(0o600)
    commands.append({'binary':Path(str(argv[0])).name,'exit':p.returncode,'seconds':round(time.monotonic()-start,3),'expected_success':ok})
    if (p.returncode==0)!=ok:raise AssertionError('native command status: '+Path(str(argv[0])).name)
    return p.stdout
def stop():
    global proc,log
    if proc is not None:
        if proc.poll()is None:proc.terminate()
        try:proc.wait(timeout=15)
        except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
        proc=None
    if log:log.close();log=None
def start(binary):
    global proc,log
    log=(PRIVATE/'registry.log').open('ab');(PRIVATE/'registry.log').chmod(0o600)
    proc=subprocess.Popen([str(binary),'serve','--listen','127.0.0.1:38443','--public-url',BASE,'--dev-loopback-http','--objects',str(PRIVATE/'objects'),'--allow-private-upstreams','127.0.0.1/32','--upstream-credentials',str(PRIVATE/'upstreams.json')],env=env,stdout=log,stderr=subprocess.STDOUT)
    for _ in range(150):
        if proc.poll()is not None:raise AssertionError('owned registry exited')
        try:
            with urllib.request.urlopen(BASE+'/health/ready',timeout=1)as response:
                if response.status==200:return
        except (OSError,urllib.error.URLError):time.sleep(.05)
    raise AssertionError('owned registry readiness timeout')
def api(path,method='GET',value=None,role='admin',key=None,headers=None):
    h={'Authorization':'Bearer '+tokens[role],**(headers or {})}
    if value is not None:h['Content-Type']='application/json'
    if method in ('POST','PUT'):h['Idempotency-Key']=key or uuid.uuid4().hex
    request=urllib.request.Request(BASE+path,data=json.dumps(value).encode()if value is not None else None,method=method,headers=h)
    try:r=urllib.request.urlopen(request,timeout=30)
    except urllib.error.HTTPError as e:r=e
    with r:return r.status,r.read(),r.headers
def oras(*argv,ok=True,cwd=PRIVATE,reader=False):
    return run([ORAS,*argv,'--plain-http','--registry-config',PRIVATE/('reader-auth.json'if reader else'auth.json')],ok=ok,cwd=cwd)
def change(repo,action,revision,path=None,digest=None,dry=False):
    body={'action':action,'expected_revision':revision,'reason':'Owned native lifecycle proof','dry_run':dry}
    if path:body.update(path=path,digest=digest)
    return api('/api/v1/repositories/'+repo+('/artifacts/lifecycle'if path else'/state'),'PUT',body)
try:
    if args.require_clean_build:check('lifecycle source and new binaries match a clean candidate',not result['source_dirty']and result['build_source_matches_candidate'])
    check('baseline is the retained qualified source',result['build_identity'][str(OLD.relative_to(ROOT))].get('vcs.revision')==('10ea6499d874018178b43ee38a9070e81e5a0686'if args.baseline_version==2 else'bea2472271bd15993bcae9b8ea12a102b2608abe'))
    owner=urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN']);database='cratectl_lifecycle_'+RUN
    pgenv=dict(env,PGHOST=owner.hostname,PGPORT=str(owner.port or 5432),PGUSER=urllib.parse.unquote(owner.username),PGPASSWORD=urllib.parse.unquote(owner.password),PGDATABASE=owner.path.lstrip('/'))
    run([ROOT/'.cache/postgresql-16.15-install/bin/psql','-X','-v','ON_ERROR_STOP=1','-At','-c','CREATE DATABASE '+database],pgenv)
    for key in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']:
        u=urllib.parse.urlsplit(env[key]);env[key]=urllib.parse.urlunsplit((u.scheme,u.netloc,'/'+database,u.query,u.fragment))
    private('database.json',{'owner':env['CRATECTL_OWNER_DSN'],'runtime':env['CRATECTL_DSN']})
    run([OLD,'migrate']);old_plan=json.loads(run([OLD,'migrate','--plan']));check('old baseline database has its safe immutable receipts',len(old_plan['applied'])==args.baseline_version and old_plan['safety_valid'])
    tenant='lifecycle-'+RUN;tokens={}
    for role in ['admin','reader']:
        p=PRIVATE/(role+'.token');run([OLD,'provision','--tenant',tenant,'--actor',role,'--role',role,'--token-file',p]);tokens[role]=p.read_text().strip()
    private('upstreams.json',{tenant+'/self':{'value':tokens['reader'],'allowed_url':BASE+'/v2/containers/'}})
    start(OLD)
    check('baseline creates hosted OCI repository',api('/api/v1/repositories','POST',{'name':'containers','format':'oci'})[0]==201)
    for role in ['admin','reader']:
        run([ORAS,'login','--plain-http','--registry-config',PRIVATE/('reader-auth.json'if role=='reader'else'auth.json'),'--username','token','--password-stdin','127.0.0.1:38443'],input_bytes=(tokens[role]+'\n').encode())
    payload=b'owned native retained lifecycle bytes\n';private('payload.txt',payload)
    ref='127.0.0.1:38443/containers/proof:v1'
    oras('push',ref,'payload.txt:text/plain');digest=oras('resolve',ref).decode().strip();path='proof/manifests/'+digest
    manifest=api('/v2/containers/'+path)[1];metadata=json.loads(manifest);child=metadata['layers'][0]['digest']
    if args.baseline_version==2:check('old native digest deletion is missing (retained negative baseline)',api('/v2/containers/'+path,'DELETE')[0]==405)
    else:
        check('schema-3 baseline creates a governed proxy',api('/api/v1/repositories','POST',{'name':'legacy-proxy','format':'oci','mode':'proxy','settings':{'upstream':{'url':BASE+'/v2/containers/','networks':['127.0.0.1/32'],'credential_ref':'self'},'cache':{'fresh_seconds':3600,'stale_seconds':0,'allow_no_store':True}}})[0]==201)
        legacy=PRIVATE/'legacy-pull';legacy.mkdir();oras('pull','127.0.0.1:38443/legacy-proxy/proof:v1',cwd=legacy,reader=True);check('actual schema-3 binary caches stock OCI graph',(legacy/'payload.txt').read_bytes()==payload)
    stop()
    plan=json.loads(run([NEW,'migrate','--plan']));check('new migrator safely plans only remaining immutable steps',plan['pending']==list(range(args.baseline_version+1,5))and plan['safety_valid'])
    run([NEW,'migrate']);plan=json.loads(run([NEW,'migrate','--plan']));check('actual upgrade preserves every old receipt and adds safe remaining steps',plan['applied'][:args.baseline_version]==old_plan['applied']and len(plan['applied'])==4 and plan['safety_valid'])
    run([OLD,'migrate','--plan'],ok=False);check('old binary refuses the upgraded database',True)
    start(NEW)
    if args.baseline_version==3:
        upgraded=PRIVATE/'upgraded-proxy-pull';upgraded.mkdir();oras('pull','127.0.0.1:38443/legacy-proxy/proof:v1',cwd=upgraded,reader=True);check('schema-4 keeps valid schema-3 cached graph at source revision zero',(upgraded/'payload.txt').read_bytes()==payload and json.loads(api('/api/v1/repositories/legacy-proxy/configuration')[1])['source_revision']==0)
    pull=PRIVATE/'initial-pull';pull.mkdir();oras('pull',ref,cwd=pull,reader=True);check('stock ORAS installs retained bytes after actual upgrade',(pull/'payload.txt').read_bytes()==payload)
    code,body,_=change('containers','hold',0,path,digest[7:]);check('administrator hold commits exact revision',code==200 and json.loads(body)['current']['held'])
    oras('manifest','delete','--force','127.0.0.1:38443/containers/proof@'+digest,ok=False);check('stock ORAS cannot delete a held manifest',True)
    check('hold release compares revision',change('containers','release_hold',1,path,digest[7:])[0]==200)
    check('strong incoming manifest reference protects blob',api('/v2/containers/proof/blobs/'+child,'DELETE')[0]==409)
    preview=json.loads(change('containers','delete',2,path,digest[7:],True)[1]);check('preview reports tag aliases without deleting',preview['tags']==['v1']and not preview['current']['deleted'])
    oras('manifest','delete','--force','127.0.0.1:38443/containers/proof@'+digest);check('stock ORAS digest deletion commits',True)
    for method,headers in [('GET',{}),('HEAD',{}),('GET',{'If-None-Match':'"'+digest[7:]+'"'}),('GET',{'Range':'bytes=0-7'}),('GET',{'Cache-Control':'no-cache'})]:
        check('deleted canonical path rejects '+method+' '+str(list(headers)),api('/v2/containers/'+path,method,headers=headers)[0]==404)
    check('deleted target hides tags',not json.loads(api('/v2/containers/proof/tags/list')[1])['tags'])
    oras('pull','127.0.0.1:38443/containers/proof@'+digest,ok=False,reader=True)
    stop();start(NEW);check('real registry restart preserves tombstone',api('/v2/containers/'+path)[0]==404)
    request=urllib.request.Request(BASE+'/v2/containers/proof/manifests/v1',data=manifest,method='PUT',headers={'Authorization':'Bearer '+tokens['admin'],'Content-Type':metadata['mediaType']})
    try:r=urllib.request.urlopen(request)
    except urllib.error.HTTPError as e:r=e
    with r:check('same-byte native publication cannot implicitly restore',r.status==404)
    physical=PRIVATE/'objects'/tenant/'sha256'/digest[7:9]/digest[7:];saved=physical.read_bytes();physical.write_bytes(b'x'+saved[1:])
    check('restore rejects corrupt retained bytes',change('containers','restore',3,path,digest[7:])[0]==503)
    physical.write_bytes(saved)
    check('manual denial persists separately from deletion',api('/api/v1/repositories/containers/decisions','PUT',{'path':path,'digest':digest[7:],'decision':'denied'})[0]==200)
    private('payload.txt',b'new tag target\n');oras('push',ref,'payload.txt:text/plain');new_digest=oras('resolve',ref).decode().strip()
    check('explicit restore verifies old graph without changing policy',change('containers','restore',3,path,digest[7:])[0]==200)
    check('restored denied bytes remain unavailable',api('/v2/containers/'+path)[0]==403)
    check('restore preserves a newer tag target',oras('resolve',ref).decode().strip()==new_digest)
    check('manual exact-byte allowance remains explicit',api('/api/v1/repositories/containers/decisions','PUT',{'path':path,'digest':digest[7:],'decision':'allowed'})[0]==200)
    recovered=PRIVATE/'recovered';recovered.mkdir();oras('pull','127.0.0.1:38443/containers/proof@'+digest,cwd=recovered,reader=True);check('stock ORAS recovers exact restored bytes',(recovered/'payload.txt').read_bytes()==payload)
    proxy={'name':'proxy','format':'oci','mode':'proxy','settings':{'upstream':{'url':BASE+'/v2/containers/','networks':['127.0.0.1/32'],'credential_ref':'self','authentication':'bearer'},'cache':{'fresh_seconds':60,'allow_no_store':True}}}
    check('create explicit credential-bound proxy',api('/api/v1/repositories','POST',proxy)[0]==201)
    proxy_ref='127.0.0.1:38443/proxy/proof@'+digest
    cache_pull=PRIVATE/'cache-pull';cache_pull.mkdir();oras('pull',proxy_ref,cwd=cache_pull,reader=True);check('stock ORAS fills governed proxy graph',(cache_pull/'payload.txt').read_bytes()==payload)
    for revision,action in enumerate(['suspend','resume','remove','restore']):
        check('source '+action+' commits retained state',change('proxy',action,revision)[0]==200)
        code=api('/v2/proxy/'+path)[0];check('source '+action+' serving state is explicit',code==({'suspend':503,'resume':200,'remove':404,'restore':200}[action]))
    check('local proxy tombstone commits',change('proxy','delete',0,path,digest[7:])[0]==200)
    check('forced proxy refresh cannot resurrect',api('/v2/proxy/'+path,headers={'Cache-Control':'no-cache'})[0]==404)
    oras('pull',proxy_ref,ok=False,reader=True)
    check('explicit proxy restore verifies retained complete graph',change('proxy','restore',1,path,digest[7:])[0]==200)
    check('bytes remain retained after all lifecycle transitions',physical.read_bytes()==saved)
    result['status']='passed';print('PASS: '+str(len(checks))+' lifecycle assertions')
except BaseException as e:
    result['status']='failed';result['failure']=type(e).__name__+': '+str(e);raise
finally:
    stop();target=ROOT/'evidence'/datetime.datetime.now(datetime.timezone.utc).date().isoformat();target.mkdir(parents=True,exist_ok=True);evidence=target/('lifecycle-'+RUN+'.json');evidence.write_text(json.dumps(result,indent=2)+'\n');print('Evidence: '+str(evidence))
