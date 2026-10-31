#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Real schema-5 upgrade, recurring rotation, corruption recovery and stock ORAS."""
import argparse,datetime,hashlib,json,os,subprocess,time,urllib.error,urllib.parse,urllib.request,uuid
from pathlib import Path

parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT);RUN=uuid.uuid4().hex[:10];PRIVATE=ROOT/'.private/schedule-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
OLD=ROOT/'.cache/repair-final-production/cratectld';NEW=ROOT/'bin/cratectld';CLI=ROOT/'bin/cratectl';ORAS=ROOT/'.cache/bin/oras';BASE='http://127.0.0.1:38443';env=dict(os.environ);checks=[];commands=[];processes={};logs={};tokens={}
def identity(binary):
 out={}
 for line in subprocess.check_output([ROOT/'.cache/go/bin/go','version','-m',binary],text=True).splitlines():
  fields=line.strip().split('\t')
  if len(fields)==2 and fields[0]=='build'and '='in fields[1]:k,v=fields[1].split('=',1);out[k]=v
 return out
candidate=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip();scope=['cmd','internal','scripts','web','api','go.mod','go.sum','Makefile']
result={'run':RUN,'candidate':candidate,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*scope]).strip()),'checks':checks,'commands':commands,'artifact_digests':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in [OLD,NEW,CLI,ORAS]},'build_identity':{str(p.relative_to(ROOT)):identity(p)for p in [OLD,NEW,CLI]},'topology':'Native macOS arm64, real PostgreSQL 16.15 forced-RLS restricted runtime, retained clean schema-5 baseline then schema-9 registry/worker, stock ORAS 1.3.6 and streaming cratectl CLI. Explicit owned HTTP loopback on 38443.','limits':['Deterministic rotating referenced-byte samples, not random statistical or full-volume/security assessments. SQL scan cost and large-profile behavior remain unqualified.','A real 60-second recurrence, supported exact-byte recovery, credential revocation/reauthorization and actual process restart are observed. No S3, unreferenced-file schedules, retention/GC, multi-host fairness or production backup/restore is claimed.','Schema-5 to schema-9 upgrade uses controlled maintenance with all old processes stopped; rolling compatibility remains open.']}
result['build_source_matches_candidate']=all(result['build_identity'][str(p.relative_to(ROOT))].get('vcs.revision')==candidate and result['build_identity'][str(p.relative_to(ROOT))].get('vcs.modified')=='false'for p in [NEW,CLI])
def check(label,condition):
 if not condition:raise AssertionError(label)
 checks.append(label)
def private(name,value):
 p=PRIVATE/name;p.write_bytes(value if isinstance(value,bytes)else json.dumps(value).encode());p.chmod(0o600);return p
def run(argv,extra=None,input_bytes=None,ok=True,cwd=PRIVATE,timeout=90):
 e=dict(env);e.update(extra or {});p=subprocess.run([str(x)for x in argv],env=e,cwd=cwd,input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout);output=p.stdout.decode(errors='replace')
 for value in tokens.values():output=output.replace(value,'[REDACTED]')
 commands.append({'argv':[str(x).replace(str(PRIVATE),'PRIVATE')for x in argv],'exit':p.returncode,'output':output[-8000:],'expected_failure':not ok})
 if (p.returncode==0)!=ok:raise AssertionError('native command status: '+Path(str(argv[0])).name+': '+output[-1000:])
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
 else:argv+=['--listen','127.0.0.1:38443','--public-url',BASE,'--dev-loopback-http']
 processes[name]=subprocess.Popen([str(x)for x in argv],env=env,stdout=logs[name],stderr=subprocess.STDOUT)
 if reject:
  try:code=processes[name].wait(timeout=5)
  except subprocess.TimeoutExpired:stop(name);raise AssertionError('old worker remained admitted to schema 9')
  rejection=(PRIVATE/(name+'.log')).read_text(errors='replace');check('actual old worker rejects the upgraded database',code!=0 and 'schema'in rejection.lower()and 'flag provided but not defined'not in rejection);stop(name);return
 if not worker:
  for _ in range(150):
   if processes[name].poll()is not None:raise AssertionError('owned registry exited')
   try:
    with urllib.request.urlopen(BASE+'/health/ready',timeout=1)as response:
     if response.status==200:return
   except Exception:time.sleep(.05)
  raise AssertionError('owned registry readiness timeout')
def api(path,method='GET',body=None,key=None,role='admin',headers=None):
 if isinstance(body,dict):body=json.dumps(body).encode()
 h={'Authorization':'Bearer '+tokens[role],'Content-Type':'application/json'};h.update(headers or {})
 if key:h['Idempotency-Key']=key
 request=urllib.request.Request(BASE+path,data=body,method=method,headers=h)
 try:
  with urllib.request.urlopen(request,timeout=10)as r:return r.status,r.read(),dict(r.headers)
 except urllib.error.HTTPError as e:return e.code,e.read(),dict(e.headers)
def get(path,role='admin'):
 code,body,_=api(path,role=role)
 if code!=200:raise AssertionError('management observation status '+str(code))
 return json.loads(body)
def oras(*argv,cwd=PRIVATE,ok=True):return run([ORAS,*argv,'--plain-http','--registry-config',PRIVATE/'oras.json'],cwd=cwd,ok=ok)
def cli(path,body=None,role='admin',key=None):
 argv=[CLI,'--url',BASE,'--token-file',PRIVATE/(role+'.token'),'--path',path]
 if body is not None:argv+=['--method','PUT','--body-file',private('schedule-request.json',body),'--idempotency-key',key or 'schedule-'+uuid.uuid4().hex]
 return json.loads(run(argv))
def await_runs(count,role='admin',timeout=80):
 deadline=time.monotonic()+timeout
 while time.monotonic()<deadline:
  rows=get(SCHEDULE+'/runs?limit=100',role)['items']
  if len(rows)>=count and rows[count-1]['state']=='succeeded':return rows
  time.sleep(.15)
 raise AssertionError('recurring run did not complete')
try:
 if args.require_clean_build:check('schedule code and artifacts identify one clean candidate',not result['source_dirty']and result['build_source_matches_candidate'])
 check('retained old baseline is the qualified schema-5 source',identity(OLD).get('vcs.revision')=='1fe1b8ab9ef91f75fd9a586693d9983b5c5324d6')
 u=urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN']);database='cratectl_schedules_'+RUN;pgenv=dict(env,PGHOST=u.hostname,PGPORT=str(u.port),PGUSER=urllib.parse.unquote(u.username),PGPASSWORD=urllib.parse.unquote(u.password),PGDATABASE=u.path.lstrip('/'))
 run([ROOT/'.cache/postgresql-16.15-install/bin/psql','-X','-v','ON_ERROR_STOP=1','-At','-c','CREATE DATABASE '+database],pgenv)
 for key in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']:
  u=urllib.parse.urlsplit(env[key]);env[key]=urllib.parse.urlunsplit((u.scheme,u.netloc,'/'+database,u.query,u.fragment))
 private('database.json',{'owner':env['CRATECTL_OWNER_DSN'],'runtime':env['CRATECTL_DSN']});run([OLD,'migrate']);before=json.loads(run([OLD,'migrate','--plan']));check('actual old database has five safe frozen receipts',len(before['applied'])==5 and before['safety_valid'])
 tenant='schedules-'+RUN
 for role,kind,target in [('admin','admin',tenant),('recovery','admin',tenant),('reader','reader',tenant),('worker','worker',tenant),('other','admin',tenant+'-other')]:
  p=PRIVATE/(role+'.token');run([OLD,'provision','--tenant',target,'--actor',role,'--role',kind,'--token-file',p]);tokens[role]=p.read_text().strip()
 private('workers.json',{'token_files':[str(PRIVATE/'worker.token')]});start('registry',OLD)
 check('old baseline creates hosted OCI',api('/api/v1/repositories','POST',{'name':'containers','format':'oci'},'create-containers')[0]==201)
 old_selector=subprocess.check_output(['git','show','1fe1b8ab9ef91f75fd9a586693d9983b5c5324d6:web/src/operations.tsx'],text=True);check('retained old console offered an unsupported abandoned job filter',"'failed','abandoned'"in old_selector and api('/api/v1/jobs?state=abandoned')[0]==409)
 run([ORAS,'login','--plain-http','--registry-config',PRIVATE/'oras.json','--username','token','--password-stdin','127.0.0.1:38443'],input_bytes=(tokens['reader']+'\n').encode())
 private('primary.txt',b'owned recurring native artifact\n'*1024);private('dependency.txt',b'owned independent dependency\n'*512)
 # Publication uses the administrator; consumption uses the scoped reader.
 run([ORAS,'login','--plain-http','--registry-config',PRIVATE/'publisher.json','--username','token','--password-stdin','127.0.0.1:38443'],input_bytes=(tokens['admin']+'\n').encode())
 ref='127.0.0.1:38443/containers/proof:v1';run([ORAS,'push',ref,'primary.txt:text/plain','dependency.txt:text/plain','--plain-http','--registry-config',PRIVATE/'publisher.json'])
 baseline=PRIVATE/'baseline-pull';baseline.mkdir();oras('pull',ref,cwd=baseline);check('stock ORAS consumes nontrivial old-baseline content and dependency',(baseline/'primary.txt').read_bytes()==(PRIVATE/'primary.txt').read_bytes()and(baseline/'dependency.txt').read_bytes()==(PRIVATE/'dependency.txt').read_bytes())
 manifest=json.loads(oras('manifest','fetch',ref));config_digest=manifest['config']['digest'][7:];root_digest=oras('resolve',ref).decode().strip()[7:];stop('registry')
 plan=json.loads(run([NEW,'migrate','--plan']));check('migrator plans integrity schedules, retention, automatic-retirement and hold-inventory steps',plan['pending']==[6,7,8,9]and plan['safety_valid']);run([NEW,'migrate']);plan=json.loads(run([NEW,'migrate','--plan']));check('upgrade preserves receipts 1–5 and adds safe schedule/retention tables',plan['applied'][:5]==before['applied']and len(plan['applied'])==9 and plan['safety_valid']);start('old-worker',OLD,True,True)
 start('registry',NEW);start('worker',NEW,True)
 targets=get('/api/v1/maintenance/integrity-sweeps?repository=containers&limit=100')['items'];check('native OCI graph exposes at least four retained byte bindings',len(targets)>=4)
 target=next(row for row in targets[2:4]if row['digest']!=config_digest);target_path='proof/'+('manifests/'if target['digest']==root_digest else'blobs/')+'sha256:'+target['digest'];code,body,_=api('/v2/containers/'+target_path);check('independent source captures exact future sample target',code==200 and len(body)==target['size']and hashlib.sha256(body).hexdigest()==target['digest']);source=private('independent-recovery.bin',body)
 SCHEDULE='/api/v1/maintenance/integrity-schedules/recurring';settings={'expected_revision':0,'repository':'containers','interval_seconds':60,'sample_size':2,'enabled':True,'reason':'Owned real recurring stock-client journey','run_immediately':True}
 preview=cli(SCHEDULE,dict(settings,dry_run=True));check('CLI preview has no durable schedule',preview['revision']==1 and api(SCHEDULE)[0]==404)
 started=time.monotonic();created=cli(SCHEDULE,settings,key='native-schedule-create');check('CLI creates an exact-revision recurring plan',created['revision']==1 and created['enabled'])
 rows=await_runs(1);first=rows[0];check('first automatic sample is bounded and byte-verified',first['sample_assessed']and first['sample_clean']and first['progress']['targets']==2 and not first['all_tenant_content_assessed']and not first['security_approval'])
 first_items=get('/api/v1/maintenance/integrity-sweeps/'+first['job']+'/items?limit=100')['items'];check('first sample captures the first two ordered bindings',[r['digest']for r in first_items]==[r['digest']for r in targets[:2]])
 physical=PRIVATE/'objects'/tenant/'sha256'/target['digest'][:2]/target['digest'];physical.write_bytes(b'X'*target['size']);check('corrupt next-sample bytes fail native readback',api('/v2/containers/'+target_path)[0]==503);failed=PRIVATE/'corrupt-pull';failed.mkdir();oras('pull',ref,cwd=failed,ok=False)
 rows=await_runs(2);second=rows[1];result['actual_recurrence_seconds']=round(time.monotonic()-started,3)
 check('real interval elapses without an owner database clock edit',result['actual_recurrence_seconds']>=59)
 check('second rotating sample retains actual corruption finding',second['sample_assessed']and not second['sample_clean']and second['progress']['issues']>=1 and second['progress']['targets']==2)
 second_items=get('/api/v1/maintenance/integrity-sweeps/'+second['job']+'/items?limit=100')['items'];check('second sample advances to the next captured bindings',[r['digest']for r in second_items]==[r['digest']for r in targets[2:4]])
 check('native due slots remain exactly sixty seconds apart',(datetime.datetime.fromisoformat(second['due_at'].replace('Z','+00:00'))-datetime.datetime.fromisoformat(first['due_at'].replace('Z','+00:00'))).total_seconds()==60)
 settings.update(expected_revision=1,enabled=False,run_immediately=False,reason='Pause future admission after observed native finding');paused=cli(SCHEDULE,settings);check('pause retains the observed run and cursor',not paused['enabled']and paused['last_job']==second['job'])
 check('reader cannot inspect schedule authority',api(SCHEDULE,role='reader')[0]==403);check('other tenant cannot inspect this named schedule',api(SCHEDULE,role='other')[0]==404)
 stop('worker');settings.update(expected_revision=2,enabled=True,run_immediately=True,reason='Authorize slot before original credential revocation');cli(SCHEDULE,settings);run([NEW,'revoke','--token-file',PRIVATE/'admin.token']);start('worker',NEW,True)
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  if get(SCHEDULE,'recovery')['blocked']:break
  time.sleep(.1)
 else:raise AssertionError('revoked authorizer did not block recurring admission')
 check('revoked authorizer produces no third run',len(get(SCHEDULE+'/runs?limit=100','recovery')['items'])==2)
 repair={'path':target_path,'digest':target['digest'],'expected_source_revision':0,'reason':'Recover owned recurring integrity finding','provenance':'Independent exact copy retained before fault injection'}
 code,body,_=api('/api/v1/repositories/containers/artifacts/repairs','POST',repair,'native-recurring-repair',role='recovery');check('replacement administrator admits supported byte repair',code==202);repair_id=json.loads(body)['job']
 accepted=json.loads(run([CLI,'--url',BASE,'--token-file',PRIVATE/'recovery.token','--method','PUT','--path','/api/v1/maintenance/repairs/'+repair_id+'/source','--upload-file',source,'--idempotency-key','native-recurring-source','--timeout','60s']));check('streaming CLI supplies the exact independent recovery source',accepted['source_ready'])
 deadline=time.monotonic()+15
 while time.monotonic()<deadline:
  if get('/api/v1/jobs/'+repair_id,'recovery')['state']=='succeeded':break
  time.sleep(.1)
 else:raise AssertionError('supported repair did not finish')
 recovered=PRIVATE/'recovered-pull';recovered.mkdir();oras('pull',ref,cwd=recovered);check('stock reader ORAS consumes exact recovered bytes',(recovered/'primary.txt').read_bytes()==(PRIVATE/'primary.txt').read_bytes()and(recovered/'dependency.txt').read_bytes()==(PRIVATE/'dependency.txt').read_bytes())
 settings.update(expected_revision=3,sample_size=len(targets),reason='Reauthorize and assess current complete captured graph');current=cli(SCHEDULE,settings,role='recovery');check('new administrator reauthorizes at a new revision',current['revision']==4 and not current['blocked']and current['authorized_actor']=='recovery')
 rows=await_runs(3,'recovery',20);check('clean later sample preserves earlier immutable finding',rows[2]['sample_clean']and rows[1]['progress']['issues']>=1 and not rows[2]['all_tenant_content_assessed'])
 settings.update(expected_revision=4,enabled=False,run_immediately=False,reason='Retain completed native campaign without future admissions');cli(SCHEDULE,settings,role='recovery')
 stop('worker');stop('registry');start('registry',NEW);start('worker',NEW,True)
 final=cli(SCHEDULE,role='recovery');history=get(SCHEDULE+'/history?limit=100','recovery')['items'];check('real registry and worker restart retain pause and all configuration receipts',not final['enabled']and final['revision']==5 and [r['revision']for r in history]==[1,2,3,4,5])
 final_rows=get(SCHEDULE+'/runs?limit=100','recovery')['items'];check('restart preserves exact prior run identities and findings',[r['job']for r in final_rows]==[r['job']for r in rows]and final_rows[1]['progress']['issues']>=1)
 public=json.dumps({'schedule':final,'history':history,'runs':final_rows});check('public schedule records omit credential values and private hashes',all(t not in public and hashlib.sha256(t.encode()).hexdigest()not in public for t in tokens.values()))
 result['status']='passed';print('PASS: '+str(len(checks))+' recurring schedule assertions')
except BaseException as e:result['status']='failed';result['failure']=type(e).__name__+': '+str(e);raise
finally:
 for name in list(processes):stop(name)
 target=ROOT/'evidence'/datetime.datetime.now(datetime.timezone.utc).date().isoformat();target.mkdir(exist_ok=True);p=target/('schedules-'+RUN+'.json');p.write_text(json.dumps(result,indent=2)+'\n');print('Evidence: '+str(p))
