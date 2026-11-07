#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned historical upgrades and stock ORAS retained deletion/recovery, on real PostgreSQL."""
import argparse,datetime,hashlib,io,json,os,platform,subprocess,time,urllib.error,urllib.parse,urllib.request,uuid,zipfile
from pathlib import Path
from qualification_contract import CURRENT_SCHEMA, candidate_binary_directory, candidate_artifact_names

parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');parser.add_argument('--binary-directory',type=Path,help='Owned candidate binaries; defaults to bin');parser.add_argument('--baseline-version',type=int,choices=range(2,CURRENT_SCHEMA),default=2);args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT);RUN=uuid.uuid4().hex[:10]
PRIVATE=ROOT/'.private/lifecycle-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
BASELINES={row['schema']:(row['binary'],row['source']) for row in json.loads((ROOT/'docs/qualification/upgrade-baselines.json').read_text())['baselines'] if row['schema'] is not None}
BIN=candidate_binary_directory(args.binary_directory)
BASE='http://127.0.0.1:38443';OLD=ROOT/BASELINES[args.baseline_version][0];NEW=BIN/'cratectld';ORAS=ROOT/'.cache/bin/oras'
env=dict(os.environ);checks=[];commands=[];proc=None;log=None
def identity(binary):
    values={}
    for line in subprocess.check_output([ROOT/'.cache/go/bin/go','version','-m',binary],text=True).splitlines():
        parts=line.strip().split('\t')
        if len(parts)==2 and parts[0]=='build' and '='in parts[1]:key,value=parts[1].split('=',1);values[key]=value
    return values
scope=['cmd','internal','scripts','web','api','go.mod','go.sum','Makefile'];candidate=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
result={'run':RUN,'candidate':candidate,'baseline_version':args.baseline_version,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*scope]).strip()),'checks':checks,'commands':commands,'artifact_digests':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in [OLD,NEW,BIN/'cratectl',ORAS]},'build_identity':{str(p.relative_to(ROOT)):identity(p)for p in [OLD,NEW,BIN/'cratectl']},'topology':f'Native {platform.platform()}, retained clean schema-{args.baseline_version} binary then schema-{CURRENT_SCHEMA} binary, real PostgreSQL 16.15 nonowner forced RLS, stock ORAS; explicit HTTP loopback on 38443.','limits':['Logical retirement retains CAS bytes and all references; no physical erasure or reclaimed storage is claimed.','Source URL/configuration changes, recursive groups, retention/GC, scale, rolling upgrade, backup/restore and other clients/platforms remain required.','This campaign uses controlled maintenance with the registry stopped during migration; it does not establish compatible rolling versions.']}
result['build_source_matches_candidate']=all(result['build_identity'][str(p.relative_to(ROOT))].get('vcs.revision')==candidate and result['build_identity'][str(p.relative_to(ROOT))].get('vcs.modified')=='false'for p in [NEW,BIN/'cratectl'])
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
    proc=subprocess.Popen([str(binary),'serve','--listen','127.0.0.1:38443','--public-url',BASE,'--dev-loopback-http','--objects',str(PRIVATE/'objects'),'--allow-private-upstreams','127.0.0.1/32','--upstream-credentials',str(PRIVATE/'upstreams.json')],env={k:v for k,v in env.items()if k!='CRATECTL_OWNER_DSN'},stdout=log,stderr=subprocess.STDOUT)
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
    if method in ('POST','PUT','PATCH'):h['Idempotency-Key']=key or uuid.uuid4().hex
    request=urllib.request.Request(BASE+path,data=json.dumps(value).encode()if value is not None else None,method=method,headers=h)
    try:r=urllib.request.urlopen(request,timeout=30)
    except urllib.error.HTTPError as e:r=e
    with r:return r.status,r.read(),r.headers
def oras(*argv,ok=True,cwd=PRIVATE,reader=False):
    return run([ORAS,*argv,'--plain-http','--registry-config',PRIVATE/('reader-auth.json'if reader else'auth.json')],runenv={k:v for k,v in env.items()if k not in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']},ok=ok,cwd=cwd)
def change(repo,action,revision,path=None,digest=None,dry=False):
    body={'action':action,'expected_revision':revision,'reason':'Owned native lifecycle proof','dry_run':dry}
    if path:body.update(path=path,digest=digest)
    return api('/api/v1/repositories/'+repo+('/artifacts/lifecycle'if path else'/state'),'PUT',body)
try:
    if args.require_clean_build:check('lifecycle source and new binaries match a clean candidate',not result['source_dirty']and result['build_source_matches_candidate'])
    check('baseline is the retained qualified clean source',result['build_identity'][str(OLD.relative_to(ROOT))].get('vcs.revision')==BASELINES[args.baseline_version][1]and result['build_identity'][str(OLD.relative_to(ROOT))].get('vcs.modified')=='false')
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
        run([ORAS,'login','--plain-http','--registry-config',PRIVATE/('reader-auth.json'if role=='reader'else'auth.json'),'--username','token','--password-stdin','127.0.0.1:38443'],runenv={k:v for k,v in env.items()if k not in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']},input_bytes=(tokens[role]+'\n').encode())
    payload=b'owned native retained lifecycle bytes\n'*(2048 if args.baseline_version>=8 else 1);private('payload.txt',payload)
    ref='127.0.0.1:38443/containers/proof:v1'
    files=['payload.txt:text/plain']
    if args.baseline_version>=8:
        dependency=b'owned independent dependency bytes\n'*256;private('dependency.txt',dependency);files.append('dependency.txt:text/plain')
    oras('push',ref,*files);digest=oras('resolve',ref).decode().strip();path='proof/manifests/'+digest
    manifest=api('/v2/containers/'+path)[1];metadata=json.loads(manifest);child=metadata['layers'][0]['digest']
    if args.baseline_version>=8:
        old_child_path='proof/blobs/'+child
        check('actual prior runtime places a retained hold before upgrade',change('containers','hold',0,old_child_path,child[7:])[0]==200)
        old_events=json.loads(api('/api/v1/audit')[1])['items']
        old_hold=next(e for e in reversed(old_events)if json.loads(e['payload']).get('kind')=='artifact.lifecycle.changed'and json.loads(e['payload'])['data']['current']['path']==old_child_path)
        result['pre_upgrade_hold_receipt']={'sequence':old_hold['sequence'],'hash':old_hold['hash'],'snapshot':json.loads(old_hold['payload'])['data']['current']}
    if args.baseline_version>=10:
        prior_case_ref='127.0.0.1:38443/containers/preupgrade-case:v1'
        oras('push',prior_case_ref,*files);prior_case_digest=oras('resolve',prior_case_ref).decode().strip();prior_case_path='preupgrade-case/manifests/'+prior_case_digest
        prior_case_endpoint='/api/v1/repositories/containers/artifacts/holds/preupgrade'
        prior_case_input={'path':prior_case_path,'digest':prior_case_digest[7:],'action':'hold','expected_revision':0,'reason':'Actual old runtime independent case preservation'}
        status,raw,_=api(prior_case_endpoint,'PUT',prior_case_input);prior_case=json.loads(raw)
        check('actual schema10 runtime places an independent case before upgrade',status==200 and prior_case['case']['revision']==1 and prior_case['case']['held'])
        prior_case_events=json.loads(api('/api/v1/audit')[1])['items']
        prior_case_event=next(e for e in reversed(prior_case_events)if json.loads(e['payload']).get('kind')=='artifact.hold_case.changed'and json.loads(e['payload'])['data']['case']['path']==prior_case_path)
        result['pre_upgrade_case_receipt']={'sequence':prior_case_event['sequence'],'hash':prior_case_event['hash'],'snapshot':json.loads(prior_case_event['payload'])['data']}
    if args.baseline_version==2:check('old native digest deletion is missing (retained negative baseline)',api('/v2/containers/'+path,'DELETE')[0]==405)
    else:
        check(f'schema-{args.baseline_version} baseline creates a governed proxy',api('/api/v1/repositories','POST',{'name':'legacy-proxy','format':'oci','mode':'proxy','settings':{'upstream':{'url':BASE+'/v2/containers/','networks':['127.0.0.1/32'],'credential_ref':'self'},'cache':{'fresh_seconds':3600,'stale_seconds':0,'allow_no_store':True}}})[0]==201)
        legacy=PRIVATE/'legacy-pull';legacy.mkdir();oras('pull','127.0.0.1:38443/legacy-proxy/proof:v1',cwd=legacy,reader=True);check(f'actual schema-{args.baseline_version} binary caches stock OCI graph',(legacy/'payload.txt').read_bytes()==payload)
    if args.baseline_version>=14:
        check(f'actual schema{args.baseline_version} creates reviewed hosted Go source before export migration',api('/api/v1/repositories','POST',{'name':'export-source','format':'go','require_review':True,'access':'restricted'})[0]==201)
        go_module='go.cratectl.invalid/Owned/export-upgrade';go_version='v1.0.0';go_path='go.cratectl.invalid/!owned/export-upgrade/@v/v1.0.0';go_payload=b'original Go bytes before schema15'
        go_zip=io.BytesIO()
        with zipfile.ZipFile(go_zip,'w',zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(go_module+'@'+go_version+'/go.mod','module '+go_module+'\n\ngo 1.26.0\n')
            archive.writestr(go_module+'@'+go_version+'/assets/owned.txt',go_payload)
        go_zip_file=private('go-before-upgrade.zip',go_zip.getvalue())
        run([BIN/'cratectl','--url',BASE,'--token-file',PRIVATE/'admin.token','--method','PUT','--path','/go/export-source/'+go_path+'.zip','--upload-file',go_zip_file,'--go-module-time','2026-01-02T03:04:05Z'],runenv={k:v for k,v in env.items()if k not in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']})
        go_before=json.loads(api('/api/v1/repositories/export-source/artifacts')[1])['items']
        check(f'actual schema{args.baseline_version} retains complete hosted Go bundle',len(go_before)==3)
        for artifact in go_before:
            check(f'schema{args.baseline_version} approves exact old Go representation '+artifact['path'],api('/api/v1/repositories/export-source/decisions','PUT',{'path':artifact['path'],'digest':artifact['digest'],'decision':'allowed'})[0]==200)
        go_before=json.loads(api('/api/v1/repositories/export-source/artifacts')[1])['items']
        if args.baseline_version>=15:
            prior_export_request={'repository':'export-source','module':go_module,'version':go_version,'expected_source_revision':0,'lifetime_seconds':3600}
            prior_export_key='actual-schema15-export-'+RUN
            status,prior_export_receipt,_=api('/api/v1/go/exports','POST',prior_export_request,key=prior_export_key);prior_export=json.loads(prior_export_receipt)
            check(f'actual schema{args.baseline_version} daemon creates durable export before migration to{CURRENT_SCHEMA}',status==201 and prior_export['generation']==1 and prior_export['payload_pins_retained'])
            prior_change={'action':'acknowledge','expected_generation':1,'lifetime_seconds':0,'manifest_sha256':prior_export['manifest']['digest']}
            prior_change_key='actual-schema15-ack-'+RUN
            status,prior_change_receipt,_=api('/api/v1/go/exports/'+prior_export['id'],'PATCH',prior_change,key=prior_change_key)
            check(f'actual schema{args.baseline_version} daemon acknowledges export before migration to{CURRENT_SCHEMA}',status==200 and json.loads(prior_change_receipt)['generation']==2 and json.loads(prior_change_receipt)['state']=='acknowledged')
            status,prior_session,_=api('/api/v1/go/exports/'+prior_export['id']);prior_session=json.loads(prior_session)
            check(f'old schema{args.baseline_version} original session is readable',status==200)
            prior_objects={}
            for kind in ['manifest','zip','mod','info']:
                status,body,_=api('/api/v1/go/exports/'+prior_export['id']+'/'+kind+'?generation=2')
                check(f'old schema{args.baseline_version} retains exact export object '+kind,status==200)
                prior_objects[kind]=body
            prior_audit=json.loads(api('/api/v1/audit')[1])['items']
        if args.baseline_version>=17:
            prior_set_request={'entries':[{'repository':'export-source','module':go_module,'version':go_version,'expected_source_revision':0}], 'lifetime_seconds':3600,'max_artifact_bytes':1<<20}
            prior_set_key='actual-schema17-set-'+RUN
            status,prior_set_receipt,_=api('/api/v1/go/export-sets','POST',prior_set_request,key=prior_set_key);prior_set=json.loads(prior_set_receipt)
            check('actual schema17 daemon creates common immutable set before18 migration',status==201 and prior_set['root_count']==1 and prior_set['generation']==1 and prior_set['payload_pins_retained'])
            prior_set_change={'action':'acknowledge','expected_generation':1,'lifetime_seconds':0,'manifest_sha256':prior_set['manifest']['digest']}
            prior_set_change_key='actual-schema17-set-ack-'+RUN
            status,prior_set_change_receipt,_=api('/api/v1/go/export-sets/'+prior_set['id']+'/control','POST',prior_set_change,key=prior_set_change_key)
            check('actual schema17 daemon acknowledges common set before18',status==200 and json.loads(prior_set_change_receipt)['generation']==2)
            status,prior_set_session,_=api('/api/v1/go/export-sets/'+prior_set['id']);prior_set_session=json.loads(prior_set_session)
            check('actual schema17 common session is readable',status==200)
            prior_set_objects={}
            for suffix in ['manifest','roots/0/zip','roots/0/mod','roots/0/info']:
                status,body,_=api('/api/v1/go/export-sets/'+prior_set['id']+'/'+suffix+'?generation=2')
                check('actual schema17 retains original common set object '+suffix,status==200)
                prior_set_objects[suffix]=body
            prior_audit=json.loads(api('/api/v1/audit')[1])['items']
    stop()
    plan=json.loads(run([NEW,'migrate','--plan']));check('new migrator safely plans only remaining immutable steps',plan['pending']==list(range(args.baseline_version+1,CURRENT_SCHEMA+1))and plan['safety_valid'])
    run([NEW,'migrate']);plan=json.loads(run([NEW,'migrate','--plan']));check('actual upgrade preserves every old receipt and adds safe remaining steps',plan['applied'][:args.baseline_version]==old_plan['applied']and plan['binary_version']==CURRENT_SCHEMA and len(plan['applied'])==CURRENT_SCHEMA and plan['safety_valid'])
    run([OLD,'migrate','--plan'],ok=False);check('old binary refuses the upgraded database',True)
    start(NEW)
    if args.baseline_version>=14:
        go_after=json.loads(api('/api/v1/repositories/export-source/artifacts')[1])['items']
        check(f'actual schema{args.baseline_version} to{CURRENT_SCHEMA} preserves Go bytes metadata timestamps and approvals',go_after==go_before)
        if args.baseline_version>=15:
            status,after_session,_=api('/api/v1/go/exports/'+prior_export['id']);after_session=json.loads(after_session)
            check(f'schema{args.baseline_version} into{CURRENT_SCHEMA} preserves original session state identity deadlines and roots',status==200 and {k:v for k,v in after_session.items()if k!='server_time'}=={k:v for k,v in prior_session.items()if k!='server_time'})
            for kind,original in prior_objects.items():
                status,body,_=api('/api/v1/go/exports/'+prior_export['id']+'/'+kind+'?generation=2')
                check(f'schema{args.baseline_version} into{CURRENT_SCHEMA} preserves exact old export bytes '+kind,status==200 and body==original)
            status,replayed,headers=api('/api/v1/go/exports','POST',prior_export_request,key=prior_export_key)
            check(f'schema{args.baseline_version} creation receipt replays byte for byte after{CURRENT_SCHEMA}',status==201 and replayed==prior_export_receipt and headers.get('Idempotent-Replayed')=='true')
            status,replayed,headers=api('/api/v1/go/exports/'+prior_export['id'],'PATCH',prior_change,key=prior_change_key)
            check(f'schema{args.baseline_version} acknowledgment receipt replays byte for byte after{CURRENT_SCHEMA}',status==200 and replayed==prior_change_receipt and headers.get('Idempotent-Replayed')=='true')
            check(f'schema{args.baseline_version} original journal prefix survives{CURRENT_SCHEMA} without replayed events',json.loads(api('/api/v1/audit')[1])['items']==prior_audit)
        if args.baseline_version>=17:
            status,after_set,_=api('/api/v1/go/export-sets/'+prior_set['id']);after_set=json.loads(after_set)
            check('schema18 preserves actual17 common session identity state deadlines and pins',status==200 and {k:v for k,v in after_set.items()if k!='server_time'}=={k:v for k,v in prior_set_session.items()if k!='server_time'})
            for suffix,original in prior_set_objects.items():
                status,body,_=api('/api/v1/go/export-sets/'+prior_set['id']+'/'+suffix+'?generation=2')
                check('schema18 preserves actual17 original common set bytes '+suffix,status==200 and body==original)
            status,replayed,headers=api('/api/v1/go/export-sets','POST',prior_set_request,key=prior_set_key)
            check('actual17 common creation receipt replays byte for byte after18',status==201 and replayed==prior_set_receipt and headers.get('Idempotent-Replayed')=='true')
            status,replayed,headers=api('/api/v1/go/export-sets/'+prior_set['id']+'/control','POST',prior_set_change,key=prior_set_change_key)
            check('actual17 common acknowledgment receipt replays byte for byte after18',status==200 and replayed==prior_set_change_receipt and headers.get('Idempotent-Replayed')=='true')
            check('actual17 common journal remains unchanged after18 receipt replays',json.loads(api('/api/v1/audit')[1])['items']==prior_audit)
            graph_request={'repository':'export-source','expected_source_revision':0,'main_go_mod':'module owned/upgrade-main\ngo 1.27.0\nrequire '+go_module+' '+go_version+'\n','lifetime_seconds':3600,'max_artifact_bytes':1<<20}
            graph_key='actual18-requirement-'+RUN
            graph_endpoint='/api/v1/go/export-sets/requirements'
            status,graph_receipt,_=api(graph_endpoint,'POST',graph_request,key=graph_key);graph=json.loads(graph_receipt)
            check('upgraded native18 creates original requirement evidence and shared selected pins',status==201 and graph['profile']=='cratectl.go.hosted.requirement-export.v1' and graph['source_count']==1 and graph['root_count']==1 and graph['generation']==1 and graph['payload_pins_retained'] and not graph['delivery_verified'])
            status,replayed,headers=api(graph_endpoint,'POST',graph_request,key=graph_key)
            check('native18 original requirement receipt replays exactly',status==201 and replayed==graph_receipt and headers.get('Idempotent-Replayed')=='true')
            status,parent_raw,_=api(graph_endpoint+'/'+graph['id']+'/manifest?generation=1');parent=json.loads(parent_raw)
            check('native18 exact graph parent retains separate originals without trust grants',status==200 and hashlib.sha256(parent_raw).hexdigest()==graph['manifest']['digest'] and len(parent['sources'])==1 and not parent['selection']['dependency_closure'] and not parent['selection']['checksum_authority_verified'] and not parent['selection']['current_registry_admission'])
            references={'main':graph['main_go_mod'],'proof':graph['requirement_proof'],'selection':graph['selection_manifest'],'inputs/0/manifest':parent['sources'][0]['manifest'],'inputs/0/mod':parent['sources'][0]['mod']}
            for suffix,object_ref in references.items():
                status,body,_=api(graph_endpoint+'/'+graph['id']+'/'+suffix+'?generation=1')
                check('native18 retains exact staged original requirement object '+suffix,status==200 and len(body)==object_ref['size'] and hashlib.sha256(body).hexdigest()==object_ref['digest'])
            status,body,_=api('/api/v1/go/export-sets/'+graph['id']+'/roots/0/zip?generation=1')
            check('native18 graph selected payload uses shared guarded delivery',status==200 and body==prior_objects['zip'])
            status,_,_=api('/api/v1/go/export-sets/'+graph['id']+'/control','POST',{'action':'cancel','expected_generation':1,'lifetime_seconds':0,'manifest_sha256':graph['selection_manifest']['digest']},key='actual18-graph-cancel-'+RUN)
            check('native18 graph cancellation uses shared generation fence',status==200)
            status,terminal,_=api(graph_endpoint+'/'+graph['id']);terminal=json.loads(terminal)
            check('native18 terminal graph retains original evidence and releases payload pins',status==200 and terminal['state']=='cancelled' and terminal['manifest']==graph['manifest'] and terminal['manifest_retained'] and not terminal['payload_pins_retained'])
        request={'repository':'export-source','module':go_module,'version':go_version,'expected_source_revision':0,'lifetime_seconds':3600}
        export_key=f'native-schema{args.baseline_version}-export-'+RUN
        status,raw,_=api('/api/v1/go/exports','POST',request,key=export_key);export=json.loads(raw)
        check('upgraded native runtime commits original Go snapshot manifest and pins',status==201 and export['generation']==1 and export['payload_pins_retained'] and export['manifest_retained'] and export['delivery_verified'] is False)
        status,again,headers=api('/api/v1/go/exports','POST',request,key=export_key)
        check('new export lost acknowledgment recovers same immutable native receipt',status==201 and again==raw and headers.get('Idempotent-Replayed')=='true')
        status,manifest_raw,_=api('/api/v1/go/exports/'+export['id']+'/manifest?generation=1');export_manifest=json.loads(manifest_raw)
        check('new schema manifest retains all original pre-upgrade representation digests',status==200 and hashlib.sha256(manifest_raw).hexdigest()==export['manifest']['digest'] and {a['path']:a['digest']for a in export_manifest['artifacts']}=={a['path']:a['digest']for a in go_before})
        check('export historical policy does not manufacture current or destination trust',export_manifest['require_review'] and all(a['decision']=='allowed' for a in export_manifest['artifacts']) and export_manifest['current_registry_admission'] is False and export_manifest['checksum_authority_verified'] is False and export_manifest['dependency_closure'] is False)
        run([NEW,'migrate'])
        status,retained,_=api('/api/v1/go/exports/'+export['id'])
        check(f'schema{CURRENT_SCHEMA} live no-op replay preserves new export identity and pins',status==200 and json.loads(retained)['manifest']==export['manifest'] and json.loads(retained)['generation']==1)
    if args.baseline_version>=3:
        upgraded=PRIVATE/'upgraded-proxy-pull';upgraded.mkdir();oras('pull','127.0.0.1:38443/legacy-proxy/proof:v1',cwd=upgraded,reader=True);check(f'schema-{CURRENT_SCHEMA} keeps valid baseline cached graph at source revision zero',(upgraded/'payload.txt').read_bytes()==payload and json.loads(api('/api/v1/repositories/legacy-proxy/configuration')[1])['source_revision']==0)
    pull=PRIVATE/'initial-pull';pull.mkdir();oras('pull',ref,cwd=pull,reader=True);check('stock ORAS installs retained bytes after actual upgrade',(pull/'payload.txt').read_bytes()==payload)
    if args.baseline_version>=8:
        client_env={k:v for k,v in env.items()if k not in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']}
        def management_cli(endpoint,method='GET',value=None,key='native-hold-upgrade'):
            argv=[BIN/'cratectl','--url',BASE,'--token-file',PRIVATE/'admin.token','--method',method,'--path',endpoint]
            if value is not None:
                body_file=private('hold-cli-body.json',value);argv+=['--body-file',body_file,'--idempotency-key',key]
            return json.loads(run(argv,runenv=client_env))
        inventory=management_cli('/api/v1/holds?state=active&repository=containers')
        check('native CLI discovers the actual pre-upgrade held reference',len(inventory['items'])==1 and inventory['items'][0]['path']==old_child_path and inventory['items'][0]['held'])
        history=management_cli('/api/v1/repositories/containers/artifacts/lifecycle/history?'+urllib.parse.urlencode({'path':old_child_path}))
        check('native CLI reads the unchanged original pre-upgrade hold journal snapshot',len(history['items'])==1 and history['items'][0]['event_hash']==old_hold['hash']and history['items'][0]['state']==json.loads(old_hold['payload'])['data']['current'])
        release={'path':old_child_path,'digest':child[7:],'action':'release_hold','expected_revision':1,'reason':'Owned administrator completes pre-upgrade review'}
        completed=management_cli('/api/v1/repositories/containers/artifacts/lifecycle','PUT',release)
        repeated=management_cli('/api/v1/repositories/containers/artifacts/lifecycle','PUT',release)
        check('native CLI confirms exact release and lost-response retry without duplicating the effect',completed==repeated and completed['current']['revision']==2 and not completed['current']['held'])
        released=management_cli('/api/v1/holds?state=released&repository=containers')
        check('released pre-upgrade reference remains discoverable with its immutable receipts',len(released['items'])==1 and released['items'][0]['path']==old_child_path)
    if args.baseline_version>=8:
        check('stock ORAS consumes the nontrivial retained package and independent dependency after upgrade',(pull/'payload.txt').read_bytes()==payload and (pull/'dependency.txt').read_bytes()==dependency)
        history_after_retry=management_cli('/api/v1/repositories/containers/artifacts/lifecycle/history?'+urllib.parse.urlencode({'path':old_child_path}))
        check('exact native CLI release replay leaves one original hold and one release receipt',[v['action']for v in history_after_retry['items']]==['hold','release_hold'])
    if args.baseline_version>=10:
        prior_current=management_cli(prior_case_endpoint+'?'+urllib.parse.urlencode({'path':prior_case_path}))
        check('new runtime preserves the old independent case record exactly',prior_current==prior_case['case'])
        prior_history=management_cli(prior_case_endpoint+'/history?'+urllib.parse.urlencode({'path':prior_case_path}))
        check('native CLI preserves the original schema10 independent case snapshot and hash',len(prior_history['items'])==1 and prior_history['items'][0]['event_hash']==prior_case_event['hash'] and prior_history['items'][0]['case']==prior_case['case'])
        oras('manifest','delete','--force','127.0.0.1:38443/containers/preupgrade-case@'+prior_case_digest,ok=False);check('old independent case still protects native deletion after upgrade',True)
        prior_case_input.update(action='release_hold',expected_revision=1,reason='Current administrator completes old case review')
        prior_released=management_cli(prior_case_endpoint,'PUT',prior_case_input,key='native-preupgrade-case-release')
        check('current CLI releases only the old case while preserving its reason',prior_released['case']['released'] and prior_released['case']['hold_reason']==prior_case['case']['hold_reason'])
        prior_pull=PRIVATE/'preupgrade-case-pull';prior_pull.mkdir();oras('pull',prior_case_ref,cwd=prior_pull,reader=True)
        check('stock ORAS consumes exact independent case bytes across schema10to11',(prior_pull/'payload.txt').read_bytes()==payload and(prior_pull/'dependency.txt').read_bytes()==dependency)
    if args.baseline_version>=9:
        case_ref='127.0.0.1:38443/containers/independent:v1'
        oras('push',case_ref,*files);case_digest=oras('resolve',case_ref).decode().strip();case_path='independent/manifests/'+case_digest
        case_base='/api/v1/repositories/containers/artifacts/holds/'
        def case_input(action,revision,reason,**extra):
            return dict(path=case_path,digest=case_digest[7:],action=action,expected_revision=revision,reason=reason,**extra)
        check('legacy hold remains independent of named cases',change('containers','hold',0,case_path,case_digest[7:])[0]==200)
        for case_id in ['review-a','review-b']:
            placed=management_cli(case_base+case_id,'PUT',case_input('hold',0,'Owned independent '+case_id),key='native-case-place-'+case_id)
            check('native CLI places independent '+case_id,placed['case']['revision']==1 and placed['case']['held']and placed['current']['held'])
        release_a=case_input('release_hold',1,'Owned review A complete')
        released_a=management_cli(case_base+'review-a','PUT',release_a,key='native-case-release-a')
        replay_a=management_cli(case_base+'review-a','PUT',release_a,key='native-case-release-a')
        check('case-specific release retry preserves other protections without a second effect',released_a==replay_a and released_a['case']['released']and released_a['current']['held'])
        legacy_release=json.loads(change('containers','release_hold',4,case_path,case_digest[7:])[1])
        check('legacy release preserves independent case B',legacy_release['current']['held']and legacy_release['current']['case_held']and not legacy_release['current'].get('legacy_held',False))
        oras('manifest','delete','--force','127.0.0.1:38443/containers/independent@'+case_digest,ok=False)
        check('stock ORAS cannot delete after only case A and legacy release',api('/v2/containers/'+case_path)[0]==200)
        original=management_cli(case_base+'review-a/history?'+urllib.parse.urlencode({'path':case_path}))
        check('native CLI sees one original case hold and one release after retry',[v['action']for v in original['items']]==['hold','release_hold']and original['items'][1]['current']['held'])
        released_b=management_cli(case_base+'review-b','PUT',case_input('release_hold',1,'Owned review B complete'),key='native-case-release-b')
        check('last independent release removes the aggregate hold',not released_b['current']['held'])
        oras('manifest','delete','--force','127.0.0.1:38443/containers/independent@'+case_digest)
        check('stock ORAS deletes only after every protection is released',api('/v2/containers/'+case_path)[0]==404)
        case_state=json.loads(api('/api/v1/repositories/containers/artifacts/lifecycle?'+urllib.parse.urlencode({'path':case_path}))[1])
        check('explicit retained restore still verifies the independent reference',change('containers','restore',case_state['revision'],case_path,case_digest[7:])[0]==200)
        case_pull=PRIVATE/'case-recovered';case_pull.mkdir();oras('pull','127.0.0.1:38443/containers/independent@'+case_digest,cwd=case_pull,reader=True)
        check('stock ORAS installs exact bytes after all-case release and retained restore',(case_pull/'payload.txt').read_bytes()==payload and (case_pull/'dependency.txt').read_bytes()==dependency)
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
