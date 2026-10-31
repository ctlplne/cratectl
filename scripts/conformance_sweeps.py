#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned native worker/API/CLI proof with real PostgreSQL and actual process kills."""
import argparse,hashlib,json,os,platform,signal,subprocess,time,urllib.error,urllib.request,uuid,http.server,threading
from pathlib import Path
from qualification_contract import candidate_binary_directory, candidate_artifact_names
BIN = candidate_binary_directory()
parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT);RUN=uuid.uuid4().hex[:10]
PRIVATE=ROOT/'.private'/'sweeps-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
BASE='http://127.0.0.1:38443';checks=[];commands=[];tokens={};processes={};logs={};fixtures=[];env=dict(os.environ);runtime=dict(env);runtime.pop('CRATECTL_OWNER_DSN',None)
source_scope=['cmd','internal','scripts','api','go.mod','go.sum','Makefile']
def build_identity(name):
 text=subprocess.check_output([str(ROOT/'.cache/go/bin/go'),'version','-m',str(ROOT/name)],text=True)
 fields={}
 for line in text.splitlines():
  value=line.strip().split('\t')
  if len(value)==2 and value[0]=='build' and '='in value[1]:k,v=value[1].split('=',1);fields[k]=v
 return fields
result={'run':RUN,'candidate':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'source_scope':source_scope,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*source_scope],text=True).strip()),'artifact_digests':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest()for n in candidate_artifact_names()},'build_identity':{n:build_identity(n)for n in candidate_artifact_names()},'database_profile':env.get('CRATECTL_DEV_DATABASE','container'),'host':platform.platform(),'topology':'actual native registry and worker kills; nonowner forced-RLS runtime PostgreSQL; owner-only fault injection into owned fixtures; shared local CAS; two tenants on loopback','checks':checks,'commands':commands,'limits':['Builtin event indexing and SHA-256 storage integrity only; no scanner, signature approval, webhook, replication, GC or migration executor.','Two configured tenants on one native host; broader multi-host/fairness/scale, OS, storage outage and restore campaigns remain required.','A storage integrity observation cannot approve security policy; cancelled or stale attempts cannot publish observations.']}
result['limits']=['Current artifact and retained upload-part snapshot only; unreferenced CAS/staged files, continuous scheduling, repair, holds/retention/GC, S3 and full backup/restore remain required.','Snapshot target budget and existing SQL deadline bound admission; production-scale lock cost remains unqualified.','Two tenants on one native host; fault injection/repair changes only owned fixture data. Storage integrity is not security approval.']
result['build_source_matches_candidate']=all(v.get('vcs.revision')==result['candidate']and v.get('vcs.modified')=='false'for v in result['build_identity'].values())
def check(name,condition):
 if not condition:raise AssertionError(name)
 checks.append(name)
def command(arguments,expected=0,runenv=env):
 commands.append([str(a).replace(str(ROOT)+'/','')for a in arguments]);p=subprocess.run([str(a)for a in arguments],env=runenv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
 if p.returncode!=expected:raise AssertionError('native command returned unexpected status: '+Path(str(arguments[0])).name)
 return p.stdout

def request(path,identity='a',method='GET',data=None,key=None):
 headers={'Authorization':'Bearer '+tokens[identity]}
 if isinstance(data,(dict,list)):data=json.dumps(data,separators=(',',':')).encode();headers['Content-Type']='application/json'
 elif data is not None:headers['Content-Type']='application/octet-stream'
 if key:headers['Idempotency-Key']=key
 r=urllib.request.Request(BASE+path,data=data,headers=headers,method=method)
 try:
  with urllib.request.urlopen(r,timeout=15)as response:return response.status,response.read(),dict(response.headers)
 except urllib.error.HTTPError as e:return e.code,e.read(),dict(e.headers)
def mutation(path,data,identity='a',method='PUT',key=None):return request(path,identity,method,data,key or uuid.uuid4().hex)
def value(path,identity='a'):
 code,raw,_=request(path,identity);check('read '+path.split('?')[0]+' for '+identity,code==200);return json.loads(raw)
def write_private(name,data):
 p=PRIVATE/name
 if not isinstance(data,bytes):data=json.dumps(data).encode()
 p.write_bytes(data);p.chmod(0o600);return p
def start_server(budget=100):
 logfile=(PRIVATE/'registry.log').open('ab');logs['server']=logfile
 p=subprocess.Popen([str(BIN/'cratectld'),'serve','--listen','127.0.0.1:38443','--public-url',BASE,'--dev-loopback-http','--objects',str(PRIVATE/'objects'),'--allow-private-upstreams','127.0.0.1/32','--integrity-sweep-target-budget',str(budget)],env=runtime,stdout=logfile,stderr=subprocess.STDOUT);processes['server']=p
 for _ in range(100):
  if p.poll()is not None:raise AssertionError('owned registry process stopped during startup')
  try:
   with urllib.request.urlopen(BASE+'/health/ready',timeout=1)as response:
    if response.status==200:return
  except Exception:time.sleep(.05)
 raise AssertionError('owned registry readiness timeout')
def stop(name,hard=False):
 p=processes.pop(name,None)
 if p is not None:
  if p.poll()is None:
   if hard:p.kill()
   else:p.terminate()
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
 if name in logs:logs.pop(name).close()
def start_worker(name,rate=0,config=None,max_bytes=8<<20,timeout="60s"):
 logfile=(PRIVATE/(name+'.log')).open('ab');logs[name]=logfile
 p=subprocess.Popen([str(BIN/'cratectld'),'worker','--identities',str(config or PRIVATE/'workers.json'),'--objects',str(PRIVATE/'objects'),'--name','cratectl-'+name,'--lease','2s','--poll','50ms','--job-timeout',timeout,'--max-job-bytes',str(max_bytes),'--verify-bytes-per-second',str(rate)],env=runtime,stdout=logfile,stderr=subprocess.STDOUT);processes[name]=p;return p
def jobs(identity='a',queue='',state=''):
 query='?limit=1000&queue='+queue+'&state='+state
 code,raw,_=request('/api/v1/jobs'+query,identity)
 if code!=200:raise AssertionError('job inventory unavailable')
 return json.loads(raw)['items']
def job_id(j):return str(j['sequence'])+':'+j['task']
def get_job(identifier,identity='a'):
 code,raw,_=request('/api/v1/jobs/'+identifier,identity)
 if code!=200:raise AssertionError('job detail unavailable')
 return json.loads(raw)
def wait_for(label,predicate,seconds=15):
 deadline=time.monotonic()+seconds
 while time.monotonic()<deadline:
  out=predicate()
  if out:return out
  for name,p in processes.items():
   if p.poll()is not None:raise AssertionError('owned process exited unexpectedly: '+name)
  time.sleep(.05)
 raise AssertionError('timeout: '+label)
def publish(path,data,identity='a'):
 code,_,_=request('/r/packages/'+path,identity,'PUT',data)
 check(identity+': publish '+path,code==201)
def policy(queue,capacity=64,identity='a'):
 code,_,_=mutation('/api/v1/jobs/queues/'+queue,{'capacity':capacity,'max_running':1,'max_attempts':2,'retry_seconds':1,'retry_max_seconds':2},identity)
 check(identity+': configure '+queue+' queue',code==200)
def observations(identifier,identity='a'):
 code,raw,_=request('/api/v1/jobs/'+identifier+'/observations?limit=1000',identity)
 if code!=200:raise AssertionError('integrity observation inventory unavailable')
 return json.loads(raw)
def states(name):return [j['state']for j in jobs(name,'integrity')]
def notes(name):
 p=PRIVATE/(name+'.log');out=[]
 if p.exists():
  for line in p.read_text().splitlines():
   try:out.append(json.loads(line))
   except ValueError:pass
 return out
def sweep(repository='',key=None,expected=202):
 code,raw,headers=mutation('/api/v1/maintenance/integrity-sweeps',{'repository':repository},method='POST',key=key)
 check('sweep admission status '+str(expected),code==expected)
 return json.loads(raw) if raw else{},headers
def summary(identifier,identity='a'):
 return value('/api/v1/maintenance/integrity-sweeps/'+identifier,identity)
def snapshot(identifier,limit=1000,after=0):
 code,raw,_=request('/api/v1/maintenance/integrity-sweeps/'+identifier+'/items?limit='+str(limit)+'&after='+str(after))
 if code!=200:raise AssertionError('sweep target inventory unavailable')
 return json.loads(raw)
def wait_sweep(identifier):
 job=get_job(identifier)
 if job['state']=='failed':raise AssertionError('sweep execution failed: '+job['last_error'])
 return job if job['state']=='succeeded'else None
def object_path(tenant,digest):return PRIVATE/'objects'/tenant/'sha256'/digest[:2]/digest
def sync_write(path,data):
 with path.open('wb')as f:f.write(data);f.flush();os.fsync(f.fileno())
def inject(sql):
 # Only fixture faults use the owner connection. Never pass a DSN/password in argv.
 import urllib.parse
 cfg=urllib.parse.urlparse(env['CRATECTL_OWNER_DSN']);pg=dict(env,PGHOST=cfg.hostname,PGPORT=str(cfg.port),PGUSER=cfg.username,PGDATABASE=cfg.path.lstrip('/'),PGPASSWORD=urllib.parse.unquote(cfg.password or''))
 p=subprocess.run([str(ROOT/'.cache/postgresql-16.15-install/bin/psql'),'-X','-v','ON_ERROR_STOP=1'],input=sql,text=True,env=pg,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
 if p.returncode:raise AssertionError('owned fixture fault injection failed')
def cancel_publication_checks(identity='a'):
 for job in jobs(identity,'integrity'):
  if job['kind']=='artifact.integrity'and job['state']in ['pending','retry']:
   code,_,_=mutation('/api/v1/jobs/'+job_id(job)+'/cancel',{},identity,method='POST');check('cancel publication-only fixture check',code==200)
try:
 if args.require_clean_build:
  check('qualification source is clean',not result['source_dirty']);check('qualification binaries embed exact clean source',result['build_source_matches_candidate'])
 check('real runtime and owner PostgreSQL provided',bool(env.get('CRATECTL_DSN'))and bool(env.get('CRATECTL_OWNER_DSN')))
 tenants={}
 for identity in ['a','b']:
  tenant='sweep-'+identity+'-'+RUN;tenants[identity]=tenant
  for role,label in [('admin',identity),('worker',identity+'-worker'),('reader',identity+'-reader')]:
   p=PRIVATE/(label+'.token');command([BIN/'cratectld','provision','--tenant',tenant,'--actor',role,'--role',role,'--token-file',p]);tokens[label]=p.read_text().strip()
 write_private('workers.json',{'token_files':[str(PRIVATE/'a-worker.token'),str(PRIVATE/'b-worker.token')]})
 start_server(budget=3)
 for identity in ['a','b']:
  code,_,_=mutation('/api/v1/repositories',{'name':'packages','format':'generic','require_review':identity=='a'},identity,'POST');check(identity+': create repository',code==201)
  policy('integrity',identity=identity)
 check('reader cannot preview storage sweep',request('/api/v1/maintenance/integrity-sweeps','a-reader')[0]==403)
 check('worker cannot call public sweep API',request('/api/v1/maintenance/integrity-sweeps','a-worker')[0]==401)
 check('sweep requires idempotency key',request('/api/v1/maintenance/integrity-sweeps',method='POST',data={})[0]==400)
 check('sweep rejects caller-controlled operator budget',mutation('/api/v1/maintenance/integrity-sweeps',{'target_budget':999},method='POST')[0]==400)
 payloads={'large.bin':b'owned historical integrity bytes\n'*65000,'corrupt.bin':b'owned exact stored bytes','missing.bin':b'owned missing storage object','conflict.bin':b'owned contradictory reference','empty.bin':b''}
 digests={path:hashlib.sha256(data).hexdigest()for path,data in payloads.items()}
 for path,data in payloads.items():publish(path,data)
 publish('large-alias.bin',payloads['large.bin']);publish('other.bin',b'other tenant data','b')
 check('policy still denies unassessed bytes before sweep',request('/r/packages/large.bin')[0]==403)
 # Include a retained cancelled upload part, not only served artifact bindings.
 code,_,_=mutation('/api/v1/repositories',{'name':'images','format':'oci'},method='POST');check('create upload-part repository',code==201)
 code,_,headers=request('/v2/images/app/blobs/uploads/',method='POST',data=b'');check('begin upload part fixture',code==202)
 upload=next(v for k,v in headers.items()if k.lower()=='docker-upload-uuid');upload_path='/v2/images/app/blobs/uploads/'+upload
 part=b'owned retained upload chunk';check('store immutable chunk',request(upload_path,method='PATCH',data=part)[0]==202);check('cancel upload retaining chunk refs',request(upload_path,method='DELETE')[0]==204)
 cancel_publication_checks();cancel_publication_checks('b')
 corrupt=object_path(tenants['a'],digests['corrupt.bin']);sync_write(corrupt,b'X'*len(payloads['corrupt.bin']))
 missing=object_path(tenants['a'],digests['missing.bin']);saved=PRIVATE/'missing-original';missing.rename(saved)
 tenant=tenants['a'];digest=digests['conflict.bin'];size=len(payloads['conflict.bin'])
 inject("INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type) VALUES('"+tenant+"','packages','inconsistent-size','"+digest+"',"+str(size+1)+",'application/octet-stream');")
 preview=value('/api/v1/maintenance/integrity-sweeps?limit=1');check('bounded preview exposes more without false clean claim',len(preview['items'])==1 and preview['more']and preview['security_approval']is False)
 key=uuid.uuid4().hex;sweep(key=key,expected=503);check('budget rejection retains no partial sweep',not any(j['kind']=='storage.sweep'for j in jobs()))
 stop('server');start_server(budget=100)
 admitted,_=sweep(key=key);identifier=admitted['job'];replay,headers=sweep(key=key);check('snapshot admission replays identical durable job',replay==admitted and any(k.lower()=='idempotent-replayed'and v=='true'for k,v in headers.items()))
 progress=get_job(identifier)['target'];check('snapshot captures every distinct binding and alias count',progress['targets']==7 and progress['artifact_references']==7 and progress['upload_parts']==1)
 all_items=snapshot(identifier)['items'];check('snapshot includes cancelled upload chunk',any(x['upload_parts']==1 for x in all_items))
 pages=[];cursor=0
 while True:
  page=snapshot(identifier,1,cursor);pages.extend(page['items'])
  if not page['more']:break
  cursor=page['items'][-1]['ordinal']
 check('immutable snapshot pagination visits each target once',len(pages)==7 and len({x['ordinal']for x in pages})==7)
 check('other tenant cannot inspect snapshot job',request('/api/v1/maintenance/integrity-sweeps/'+identifier,'b')[0]==404)
 check('other tenant cannot inspect snapshot targets',request('/api/v1/maintenance/integrity-sweeps/'+identifier+'/items','b')[0]==404)
 # Later content remains outside this snapshot; publication intent covers it separately.
 publish('later.bin',b'later source reference');cancel_publication_checks()
 check('post-admission reference does not alter snapshot membership',len(snapshot(identifier)['items'])==7)
 start_worker('crash',rate=65536)
 def large_running():
  j=get_job(identifier)
  return j if j['state']=='running'and j['target']['after_ordinal']<len(all_items)and all_items[j['target']['after_ordinal']]['size']>1<<20 else None
 running=wait_for('large historical target claim',large_running);old_generation=running['generation'];old_cursor=running['target']['after_ordinal']
 stop('crash',hard=True);time.sleep(2.2);start_worker('recovered')
 finished=wait_for('reclaimed sweep finishes all targets',lambda:wait_sweep(identifier))
 detail=summary(identifier);check('completed sweep is not a false healthy receipt',detail['all_targets_assessed']is True and detail['integrity_clean']is False and detail['security_approval']is False)
 check('resume advances lease generation and covers all targets',finished['generation']>old_generation and finished['target']['checked']==7)
 items=snapshot(identifier)['items'];by_digest={}
 for item in items:by_digest.setdefault(item['digest'],[]).append(item)
 check('same-length corruption is detected',by_digest[digests['corrupt.bin']][0]['status']=='corrupt')
 check('missing referenced object is detected',by_digest[digests['missing.bin']][0]['status']=='missing')
 check('contradictory reference lengths stay visible',all(x['reference_conflict']for x in by_digest[digests['conflict.bin']])and any(x['status']=='inconsistent'for x in by_digest[digests['conflict.bin']]))
 check('empty referenced object is verified',by_digest[digests['empty.bin']][0]['status']=='verified')
 obs=observations(identifier)['items'];check('killed attempt cannot publish an observation',all(x['generation']!=old_generation for x in obs))
 check('snapshot observations retain target ordinals and pass identity',len(obs)==7 and len({x['ordinal']for x in obs})==7 and all(x['pass']==1 for x in obs))
 check('successful hash does not approve denied bytes',request('/r/packages/large.bin')[0]==403)
 stop('recovered')
 # Restore only owned fixture bytes/metadata, then repeat the same immutable target set.
 sync_write(corrupt,payloads['corrupt.bin']);saved.rename(missing)
 inject("UPDATE cratectl.artifacts SET size="+str(size)+" WHERE tenant='"+tenant+"' AND repository='packages' AND path='inconsistent-size';")
 code,_,_=mutation('/api/v1/jobs/'+identifier+'/retry',{},method='POST');check('completed inspection can start a fresh pass over retained snapshot',code==200)
 restarted=get_job(identifier)['target'];check('redrive resets current coverage and retains original cutoff',restarted['pass']==2 and restarted['checked']==0 and restarted['cutoff']==progress['cutoff'])
 start_worker('recheck');wait_for('repeat sweep completes',lambda:wait_sweep(identifier));detail=summary(identifier)
 # The immutable contradictory snapshot remains contradictory even after mutable metadata repair.
 check('repair cannot rewrite the original snapshot finding',detail['integrity_clean']is False and get_job(identifier)['target']['issues']==2)
 obs=observations(identifier)['items'];check('repeat pass preserves prior observations',len(obs)==14 and {x['pass']for x in obs}=={1,2})
 stop('recheck')
 fresh,_=sweep();fresh_id=fresh['job'];start_worker('fresh');wait_for('fresh repaired snapshot',lambda:wait_sweep(fresh_id));check('fresh snapshot proves repaired current references clean',summary(fresh_id)['integrity_clean']is True)
 stop('fresh')
 # Running cancellation must stop acceptance and resume the unassessed cursor.
 cancelled,_=sweep();cancel_id=cancelled['job'];start_worker('cancel',rate=65536)
 wait_for('cancellable sweep large target',lambda:get_job(cancel_id)['state']=='running'and get_job(cancel_id)['target']['after_ordinal']<get_job(cancel_id)['target']['targets']and snapshot(cancel_id)['items'][get_job(cancel_id)['target']['after_ordinal']]['size']>1<<20)
 before=get_job(cancel_id)['target']['checked'];code,_,_=mutation('/api/v1/jobs/'+cancel_id+'/cancel',{},method='POST');check('running sweep cancellation admitted',code==200)
 wait_for('sweep acknowledges cancellation',lambda:get_job(cancel_id)['state']=='cancelled');check('cancelled attempt cannot advance target coverage',get_job(cancel_id)['target']['checked']==before);stop('cancel')
 code,_,_=mutation('/api/v1/jobs/'+cancel_id+'/retry',{},method='POST');check('cancelled sweep resumes saved progress',code==200)
 start_worker('resume');wait_for('cancelled sweep resumes to completion',lambda:wait_sweep(cancel_id));stop('resume')
 # Resource limits and timeouts are findings, never healthy receipts.
 limited,_=sweep();limit_id=limited['job'];start_worker('limits',max_bytes=1);wait_for('bounded sweep completes',lambda:wait_sweep(limit_id));stop('limits')
 check('object byte limits remain explicit findings',summary(limit_id)['integrity_clean']is False and any(x['status']=='limit'for x in snapshot(limit_id)['items']))
 timed,_=sweep();timeout_id=timed['job'];start_worker('timeouts',rate=65536,timeout='1s');wait_for('timed inspection completes remaining targets',lambda:wait_sweep(timeout_id));stop('timeouts')
 check('timed-out hash remains an explicit finding',summary(timeout_id)['integrity_clean']is False and any(x['status']=='timeout'for x in snapshot(timeout_id)['items']))
 scoped,_=sweep('images');scope_id=scoped['job'];start_worker('scoped');wait_for('scoped upload-part sweep',lambda:wait_sweep(scope_id));stop('scoped')
 check('repository scope retains only its snapshot bindings',get_job(scope_id)['target']['targets']==1 and all(x['repository']=='images'for x in snapshot(scope_id)['items']))
 code,_,_=mutation('/api/v1/repositories',{'name':'empty','format':'generic'},method='POST');check('create empty sweep scope',code==201)
 empty,_=sweep('empty');empty_id=empty['job'];start_worker('empty');wait_for('empty snapshot completes honestly',lambda:wait_sweep(empty_id));stop('empty')
 check('empty snapshot reports zero assessed targets',get_job(empty_id)['target']['targets']==0 and observations(empty_id)['items']==[])
 stop('server');start_server();check('snapshot, coverage and observation history survive registry restart',summary(identifier)['job']['target']['pass']==2 and len(observations(identifier)['items'])==14)
 result['sweep_profile']={'original_snapshot':progress,'first_pass':finished['target'],'repeated_snapshot':get_job(identifier)['target'],'fresh_repaired_snapshot':get_job(fresh_id)['target'],'limit_inspection':get_job(limit_id)['target'],'timeout_inspection':get_job(timeout_id)['target'],'crashed_generation':old_generation,'crashed_cursor':old_cursor,'original_observations_retained':len(observations(identifier)['items'])}
 result['status']='passed'
except Exception as exc:
 message=str(exc)
 for secret in tokens.values():message=message.replace(secret,'[REDACTED]')
 result['status']='failed';result['error']=message
finally:
 for name in list(processes):stop(name)
 out=ROOT/'evidence'/'2026-10-28'/('sweeps-'+RUN+'.json');out.write_text(json.dumps(result,indent=2)+'\n');print(result['status'].upper()+': '+str(len(checks))+' assertions; native referenced storage integrity sweep');print('Evidence: '+str(out))
 if result['status']!='passed':raise SystemExit(1)
