#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned native worker/API/CLI proof with real PostgreSQL and actual process kills."""
import argparse,hashlib,json,os,platform,signal,subprocess,time,urllib.error,urllib.request,uuid,http.server,threading
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT);RUN=uuid.uuid4().hex[:10]
PRIVATE=ROOT/'.private'/'jobs-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
BASE='http://127.0.0.1:38443';checks=[];commands=[];tokens={};processes={};logs={};fixtures=[];env=dict(os.environ);runtime=dict(env);runtime.pop('CRATECTL_OWNER_DSN',None)
source_scope=['cmd','internal','scripts','api','go.mod','go.sum','Makefile']
def build_identity(name):
 text=subprocess.check_output([str(ROOT/'.cache/go/bin/go'),'version','-m',str(ROOT/name)],text=True)
 fields={}
 for line in text.splitlines():
  value=line.strip().split('\t')
  if len(value)==2 and value[0]=='build' and '='in value[1]:k,v=value[1].split('=',1);fields[k]=v
 return fields
result={'run':RUN,'candidate':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'source_scope':source_scope,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*source_scope],text=True).strip()),'artifact_digests':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest()for n in ['bin/cratectld','bin/cratectl']},'build_identity':{n:build_identity(n)for n in ['bin/cratectld','bin/cratectl']},'database_profile':env.get('CRATECTL_DEV_DATABASE','container'),'host':platform.platform(),'topology':'actual native registry and workers; nonowner forced-RLS PostgreSQL; shared local CAS; loopback 38443/35432','checks':checks,'commands':commands,'limits':['Builtin event indexing and SHA-256 storage integrity only; no scanner, signature approval, webhook, replication, GC or migration executor.','Two configured tenants on one native host; broader multi-host/fairness/scale, OS, storage outage and restore campaigns remain required.','A storage integrity observation cannot approve security policy; cancelled or stale attempts cannot publish observations.']}
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
def start_server():
 logfile=(PRIVATE/'registry.log').open('ab');logs['server']=logfile
 p=subprocess.Popen([str(ROOT/'bin/cratectld'),'serve','--listen','127.0.0.1:38443','--public-url',BASE,'--dev-loopback-http','--objects',str(PRIVATE/'objects'),'--allow-private-upstreams','127.0.0.1/32'],env=runtime,stdout=logfile,stderr=subprocess.STDOUT);processes['server']=p
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
def start_worker(name,rate=0,config=None):
 logfile=(PRIVATE/(name+'.log')).open('ab');logs[name]=logfile
 p=subprocess.Popen([str(ROOT/'bin/cratectld'),'worker','--identities',str(config or PRIVATE/'workers.json'),'--objects',str(PRIVATE/'objects'),'--name','cratectl-'+name,'--lease','2s','--poll','50ms','--job-timeout','60s','--max-job-bytes',str(8<<20),'--verify-bytes-per-second',str(rate)],env=runtime,stdout=logfile,stderr=subprocess.STDOUT);processes[name]=p;return p
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
try:
 if args.require_clean_build:
  check('qualification source is clean',not result['source_dirty']);check('qualification binaries embed exact clean source',result['build_source_matches_candidate'])
 check('real runtime/owner PostgreSQL configuration provided',bool(env.get('CRATECTL_DSN'))and bool(env.get('CRATECTL_OWNER_DSN')))
 tenants={}
 for identity in ['a','b']:
  tenant='jobs-'+identity+'-'+RUN;tenants[identity]=tenant
  for role,label in [('admin',identity),('worker',identity+'-worker')]:
   p=PRIVATE/(label+'.token');command([ROOT/'bin/cratectld','provision','--tenant',tenant,'--actor','executor'if role=='worker'else'operator','--role',role,'--token-file',p]);tokens[label]=p.read_text().strip()
 reader=PRIVATE/'a-reader.token';command([ROOT/'bin/cratectld','provision','--tenant',tenants['a'],'--actor','reader','--role','reader','--token-file',reader]);tokens['a-reader']=reader.read_text().strip()
 write_private('workers.json',{'token_files':[str(PRIVATE/'a-worker.token'),str(PRIVATE/'b-worker.token')]})
 wrong=write_private('wrong-purpose.json',{'token_files':[str(PRIVATE/'a.token')]})
 command([ROOT/'bin/cratectld','worker','--identities',wrong,'--objects',PRIVATE/'objects'],expected=1,runenv=runtime)
 check('public admin credential cannot start a worker',True)
 start_server()
 for identity in ['a','b']:
  code,_,_=mutation('/api/v1/repositories',{'name':'packages','format':'generic','require_review':identity=='a'},identity,'POST');check(identity+': create repository',code==201)
  for queue in ['events','integrity']:policy(queue,identity=identity)
 check('worker credential cannot authenticate to public jobs API',request('/api/v1/jobs','a-worker')[0]==401)
 check('reader credential cannot inspect administrator job state',request('/api/v1/jobs','a-reader')[0]==403)
 large=b'owned worker crash payload\n'*(80000);large=large[:2<<20];digest=hashlib.sha256(large).hexdigest()
 publish('large.bin',large);publish('alias.bin',large);publish('third.bin',b'other owned backlog\n'*90000);publish('small.bin',b'tenant-b-small','b')
 check('unassessed review-required bytes are blocked before workers',request('/r/packages/large.bin')[0]==403)
 pages=[];cursor=''
 while True:
  code,raw,_=request('/api/v1/jobs?limit=1'+('&after='+cursor if cursor else''));check('job page returned',code==200);page=json.loads(raw);pages.extend(page['items']);cursor=page['next']
  if not cursor:break
 check('job cursor traverses each job once',len(pages)==len({job_id(j)for j in pages})and len(pages)==len(jobs()))
 check('public job records omit claim tokens',all('lease_token'not in j and 'Token'not in j and 'token'not in j for j in pages))
 first=next(j for j in jobs()if j['queue']=='integrity');check('other tenant cannot read this job identity',request('/api/v1/jobs/'+job_id(first),'b')[0]==404)
 cli=command([ROOT/'bin/cratectl','--url',BASE,'--token-file',PRIVATE/'a.token','--path','/api/v1/jobs?limit=1000'],runenv=runtime);check('first-party CLI lists durable jobs',len(json.loads(cli)['items'])==len(pages))
 start_worker('crash',64<<10)
 running=wait_for('slow integrity claim',lambda:next((j for j in jobs('a','integrity','running')),None));crashed_id=job_id(running);old_generation=running['generation']
 wait_for('reserved event lane serves second tenant during a slow hash',lambda:all(j['state']=='succeeded'for j in jobs('b','events')))
 check('event lane progresses while an integrity lane is busy',get_job(crashed_id)['state']=='running')
 stop('crash',hard=True)
 check('hard kill leaves a durable running lease',get_job(crashed_id)['state']=='running')
 start_worker('recovered')
 wait_for('reclaimed integrity jobs finish',lambda:states('a')and all(s=='succeeded'for s in states('a'))and all(s=='succeeded'for s in states('b')))
 recovered=get_job(crashed_id)
 check('new process reclaims expired work with a newer fence',recovered['generation']>old_generation and recovered['attempts']>=2)
 obs=observations(crashed_id);check('killed attempt has no successful observation',len(obs['items'])==1 and obs['items'][0]['generation']>old_generation and obs['items'][0]['status']=='verified')
 claims=[n for n in notes('recovered')if n.get('queue')=='integrity'and n.get('state')=='running'];b_index=next(n for n,x in enumerate(claims)if x['tenant']==tenants['b'])
 check('round robin serves the other tenant before draining backlog',any(x['tenant']==tenants['a']for x in claims[b_index+1:]))
 check('successful hash observation is not security approval',obs['assessment_kind']=='storage_integrity'and obs['security_approval']is False and request('/r/packages/large.bin')[0]==403)
 code,_,_=mutation('/api/v1/repositories/packages/decisions',{'path':'large.bin','digest':digest,'decision':'allowed'});check('manual policy approval remains explicit',code==200)
 code,data,_=request('/r/packages/large.bin');check('approved exact bytes served',code==200 and hashlib.sha256(data).hexdigest()==digest)
 stop('recovered')
 object_path=PRIVATE/'objects'/tenants['a']/'sha256'/digest[:2]/digest
 with object_path.open('wb')as f:f.write(b'x'*len(large));f.flush();os.fsync(f.fileno())
 retry_key=uuid.uuid4().hex
 first_retry=mutation('/api/v1/jobs/'+crashed_id+'/retry',{},method='POST',key=retry_key)
 replay_retry=mutation('/api/v1/jobs/'+crashed_id+'/retry',{},method='POST',key=retry_key)
 check('retry is durable and idempotent',first_retry[0]==200 and replay_retry[0]==200 and first_retry[1]==replay_retry[1]and replay_retry[2].get('Idempotent-Replayed')=='true')
 start_worker('corruption')
 wait_for('bounded corruption retries stop',lambda:get_job(crashed_id)['state']=='failed')
 corrupted=observations(crashed_id)['items'];check('corrupt exact bytes have retained failed observations',sum(x['status']=='corrupt'for x in corrupted)==2)
 check('worker observation cannot bypass the serving hash check',request('/r/packages/large.bin')[0]!=200)
 stop('corruption')
 with object_path.open('wb')as f:f.write(large);f.flush();os.fsync(f.fileno())
 check('operator retries repaired exact bytes',mutation('/api/v1/jobs/'+crashed_id+'/retry',{},method='POST')[0]==200)
 start_worker('repair')
 wait_for('repaired work succeeds',lambda:get_job(crashed_id)['state']=='succeeded')
 repaired=observations(crashed_id)['items'];check('repair preserves prior corrupt evidence',repaired[-1]['status']=='verified'and sum(x['status']=='corrupt'for x in repaired)==2)
 check('attempt history survives redrive',get_job(crashed_id)['attempts']>=5)
 code,data,_=request('/r/packages/large.bin');check('repair restores exact permitted bytes',code==200 and hashlib.sha256(data).hexdigest()==digest)
 code,_,_=mutation('/api/v1/repositories/packages/decisions',{'path':'large.bin','digest':digest,'decision':'denied'});check('current deny overrides a successful hash observation',code==200 and request('/r/packages/large.bin')[0]==403)
 stop('repair')
 publish('cancel.bin',b'owned cancellation\n'*70000)
 start_worker('cancel',64<<10)
 cancel_job=wait_for('cancellable hash starts',lambda:next((j for j in jobs('a','integrity','running')),None));cancel_id=job_id(cancel_job)
 check('running cancellation request accepted',mutation('/api/v1/jobs/'+cancel_id+'/cancel',{},method='POST')[0]==200)
 wait_for('worker acknowledges cancellation',lambda:get_job(cancel_id)['state']=='cancelled')
 check('cancelled hash emits no success-shaped observation',observations(cancel_id)['items']==[])
 stop('cancel')
 class OwnedUpstream(http.server.BaseHTTPRequestHandler):
  saturated=True
  def log_message(self,*arguments):pass
  def do_GET(self):
   if OwnedUpstream.saturated:
    status=value('/api/v1/jobs/queues')['items'];outstanding=next(x['outstanding']for x in status if x['queue']=='events')
    policy('events',outstanding);OwnedUpstream.saturated=False
   self.send_response(200);self.send_header('Cache-Control','max-age=60');self.end_headers();self.wfile.write(b'owned queue recovery source')
 upstream=http.server.ThreadingHTTPServer(('127.0.0.1',0),OwnedUpstream);fixtures.append(upstream);threading.Thread(target=upstream.serve_forever,daemon=True).start()
 code,_,_=mutation('/api/v1/repositories',{'name':'upstream','format':'generic','mode':'proxy','settings':{'upstream':{'url':'http://127.0.0.1:'+str(upstream.server_port)+'/','networks':['127.0.0.1/32']},'cache':{'fresh_seconds':60}}},method='POST');check('create an owned proxy source',code==201)
 code,raw,_=request('/r/upstream/object');check('mid-fill event saturation returns queue capacity',code==503 and json.loads(raw)['error']['code']=='durable_queue_full')
 lease=value('/api/v1/repositories/upstream/cache?path=object');check('queue rejection releases the current source lease',lease['state']=='failed'and lease['last_error']=='queue_capacity')
 policy('events',64)
 code,data,_=request('/r/upstream/object');check('capacity repair immediately retries the source',code==200 and data==b'owned queue recovery source')
 proxy_jobs=[j for j in jobs('a','integrity')if j['target'].get('repository')=='upstream'];check('successful source recovery records exact-byte work',len(proxy_jobs)==1)
 check('pending source verification can be cancelled explicitly',mutation('/api/v1/jobs/'+job_id(proxy_jobs[0])+'/cancel',{},method='POST')[0]==200)
 policy('integrity',1);publish('reserve.bin',b'owned credential rollover\n'*80000)
 before=len(jobs());code,raw,_=request('/r/packages/rejected.bin',method='PUT',data=b'not acknowledged when saturated')
 check('saturation has an actionable protocol response',code==503 and json.loads(raw)['error']['code']=='durable_queue_full')
 check('saturation rolls back artifact and job references',request('/r/packages/rejected.bin')[0]==404 and len(jobs())==before)
 policy('integrity',64);policy('events',1)
 start_worker('revoked',64<<10)
 live=wait_for('job before credential revocation',lambda:next((j for j in jobs('a','integrity','running')),None));live_id=job_id(live);generation=live['generation']
 command([ROOT/'bin/cratectld','revoke','--token-file',PRIVATE/'a-worker.token'])
 wait_for('worker notices revoked execution authority',lambda:any(n.get('state')=='lease_or_credential_lost'for n in notes('revoked')))
 check('revoked in-flight attempt cannot commit an observation',observations(live_id)['items']==[])
 previous_b=len(jobs('b','integrity'));publish('still-working.bin',b'valid other tenant progresses','b');check('new work is admitted independently for a valid tenant',len(jobs('b','integrity'))==previous_b+1);wait_for('valid tenant proceeds after another credential is revoked',lambda:all(s=='succeeded'for s in states('b')))
 check('one revoked tenant does not stop other tenants',processes['revoked'].poll()is None)
 new_token=PRIVATE/'a-worker-new.token';command([ROOT/'bin/cratectld','provision','--tenant',tenants['a'],'--actor','executor-new','--role','worker','--token-file',new_token]);tokens['a-worker-new']=new_token.read_text().strip()
 config=write_private('workers-new.json',{'token_files':[str(new_token),str(PRIVATE/'b-worker.token')]})
 stop('revoked');start_worker('final',config=config)
 wait_for('replacement credential reclaims old work',lambda:get_job(live_id)['state']=='succeeded')
 check('credential rollover advances the execution fence',get_job(live_id)['generation']>generation)
 wait_for('remaining event work drains',lambda:all(j['state']=='succeeded'for j in jobs('a','events')))
 check('event indexing is a real visible effect',len(value('/api/v1/activity')['items'])>0)
 stop('final');stop('server');start_server()
 check('job outcome survives registry process restart',get_job(live_id)['state']=='succeeded'and len(observations(live_id)['items'])==1)
 result['tenants']={'count':2,'worker_purposes':'dedicated per tenant, revalidated on every worker operation'};result['status']='passed'
except Exception as exc:
 message=str(exc)
 for secret in tokens.values():message=message.replace(secret,'[REDACTED]')
 result['status']='failed';result['error']=message
finally:
 for name in list(processes):stop(name)
 for fixture in fixtures:fixture.shutdown();fixture.server_close()
 out=ROOT/'evidence'/'2026-10-28'/('jobs-'+RUN+'.json');out.write_text(json.dumps(result,indent=2)+'\n');print(result['status'].upper()+': '+str(len(checks))+' assertions; native durable jobs');print('Evidence: '+str(out))
 if result['status']!='passed':raise SystemExit(1)
