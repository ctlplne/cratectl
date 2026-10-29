#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned native worker/API/CLI proof with real PostgreSQL and actual process kills."""
import socket,http.client,datetime
import argparse,hashlib,json,os,platform,signal,subprocess,time,urllib.error,urllib.request,uuid,http.server,threading
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT);RUN=uuid.uuid4().hex[:10]
PRIVATE=ROOT/'.private'/'leases-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
BASE='http://127.0.0.1:38443';checks=[];commands=[];tokens={};processes={};logs={};fixtures=[];env=dict(os.environ);runtime=dict(env);runtime.pop('CRATECTL_OWNER_DSN',None)
source_scope=['cmd','internal','scripts','api','go.mod','go.sum','Makefile']
def build_identity(name):
 text=subprocess.check_output([str(ROOT/'.cache/go/bin/go'),'version','-m',str(ROOT/name)],text=True)
 fields={}
 for line in text.splitlines():
  value=line.strip().split('\t')
  if len(value)==2 and value[0]=='build' and '='in value[1]:k,v=value[1].split('=',1);fields[k]=v
 return fields
result={'run':RUN,'candidate':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'source_scope':source_scope,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*source_scope],text=True).strip()),'artifact_digests':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest()for n in ['bin/cratectld','bin/cratectl']},'build_identity':{n:build_identity(n)for n in ['bin/cratectld','bin/cratectl']},'database_profile':env.get('CRATECTL_DEV_DATABASE','container'),'host':platform.platform(),'topology':'actual native registry kill/restart, maintenance worker, held HTTP bodies, nonowner forced-RLS PostgreSQL; loopback 38443/35432','checks':checks,'commands':commands,'limits':['Builtin event indexing and SHA-256 storage integrity only; no scanner, signature approval, webhook, replication, GC or migration executor.','Two configured tenants on one native host; broader multi-host/fairness/scale, OS, storage outage and restore campaigns remain required.','A storage integrity observation cannot approve security policy; cancelled or stale attempts cannot publish observations.']}
result['limits']=['Expired retrieval/upload lease metadata only; no physical deletion, full CAS inventory, orphan GC, holds, historical integrity sweep or production upgrade qualification.','Two tenants on one native host; mixed-host fairness and scale remain required.']
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
 p=subprocess.Popen([str(ROOT/'bin/cratectld'),'serve','--listen','127.0.0.1:38443','--public-url',BASE,'--dev-loopback-http','--objects',str(PRIVATE/'objects'),'--allow-private-upstreams','127.0.0.1/32','--upload-lease','2s','--upload-ttl','4s','--proxy-lease','2s'],env=runtime,stdout=logfile,stderr=subprocess.STDOUT);processes['server']=p
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
def begin():
 code,_,headers=request('/v2/images/app/blobs/uploads/','a','POST',b'')
 check('begin native OCI upload session',code==202)
 return '/v2/images/app/blobs/uploads/'+next(v for k,v in headers.items()if k.lower()=='docker-upload-uuid')
def upload_status(path):
 code,_,headers=request(path);return code,headers.get('Range')
def open_chunk(path,data):
 connection=socket.create_connection(('127.0.0.1',38443),timeout=5)
 headers='PATCH '+path+' HTTP/1.1\r\nHost: 127.0.0.1:38443\r\nAuthorization: Bearer '+tokens['a']+'\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n'
 connection.sendall(headers.encode()+('%x\r\n'%len(data)).encode()+data+b'\r\n')
 return connection
def finish_chunk(connection):
 try:connection.sendall(b'0\r\n\r\n')
 except (BrokenPipeError,ConnectionResetError):pass
 response=http.client.HTTPResponse(connection);response.begin();response.read();return response.status

def cache(path,identity='a'):
 return value('/api/v1/repositories/source/cache?path='+path,identity)
def preview(identity='a'):
 return value('/api/v1/maintenance/reconciliations?limit=100',identity)
def recover(repository='',key=None,page=1):
 code,raw,_=mutation('/api/v1/maintenance/reconciliations',{'repository':repository,'page_size':page},method='POST',key=key)
 check('admit durable bounded reconciliation',code==202);return json.loads(raw)['job']
def done_job(identifier):
 job=get_job(identifier);return job if job['state']=='succeeded'else None
class HeldOrigin(http.server.BaseHTTPRequestHandler):
 gates={};started={}
 def do_GET(self):
  body=b'owned governed retrieval bytes';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','max-age=60');self.end_headers()
  if self.path in self.gates:
   self.wfile.write(body[:5]);self.wfile.flush();self.started[self.path].set();self.gates[self.path].wait(20)
   body=body[5:]
  try:self.wfile.write(body)
  except (BrokenPipeError,ConnectionResetError):pass
 def log_message(self,*args):pass
threads=[];sockets=[]
try:
 if args.require_clean_build:
  check('qualification source is clean',not result['source_dirty']);check('qualification binaries embed exact clean source',result['build_source_matches_candidate'])
 check('real runtime and owner PostgreSQL provided',bool(env.get('CRATECTL_DSN'))and bool(env.get('CRATECTL_OWNER_DSN')))
 tenants={}
 for identity in ['a','b']:
  tenant='leases-'+identity+'-'+RUN;tenants[identity]=tenant
  for role,label in [('admin',identity),('worker',identity+'-worker'),('reader',identity+'-reader')]:
   p=PRIVATE/(label+'.token');command([ROOT/'bin/cratectld','provision','--tenant',tenant,'--actor',role,'--role',role,'--token-file',p]);tokens[label]=p.read_text().strip()
 write_private('workers.json',{'token_files':[str(PRIVATE/'a-worker.token'),str(PRIVATE/'b-worker.token')]})
 fixture=http.server.ThreadingHTTPServer(('127.0.0.1',0),HeldOrigin);fixtures.append(fixture);threading.Thread(target=fixture.serve_forever,daemon=True).start()
 start_server()
 for identity in ['a','b']:
  for repo in [{'name':'images','format':'oci'},{'name':'source','format':'generic','mode':'proxy','settings':{'upstream':{'url':'http://127.0.0.1:'+str(fixture.server_port)+'/','networks':['127.0.0.1/32']},'cache':{'fresh_seconds':60}}}]:
   code,_,_=mutation('/api/v1/repositories',repo,identity,'POST');check(identity+': create '+repo['name'],code==201)
  policy('maintenance',identity=identity)
 check('reader cannot preview reconciliation',request('/api/v1/maintenance/reconciliations','a-reader')[0]==403)
 check('worker purpose cannot call public maintenance API',request('/api/v1/maintenance/reconciliations','a-worker')[0]==401)
 check('mutation requires idempotency key',request('/api/v1/maintenance/reconciliations',method='POST',data={})[0]==400)
 check('unknown reconciliation JSON rejected',mutation('/api/v1/maintenance/reconciliations',{'erase':True},method='POST')[0]==400)
 check('unbounded page rejected',mutation('/api/v1/maintenance/reconciliations',{'page_size':1001},method='POST')[0]==400)
 path=begin();committed=b'acknowledged';check('native first chunk accepted',request(path,method='PATCH',data=committed)[0]==202)
 connection=open_chunk(path,b'never-acknowledged');sockets.append(connection);time.sleep(.2)
 check('same upload refuses overlapping writers',request(path,method='PATCH',data=b'conflict')[0]==503)
 before=time.monotonic();probe=recover('images');check('slow HTTP body does not block tenant maintenance admission',time.monotonic()-before<1.5)
 time.sleep(4.3)
 check('heartbeat keeps held chunk live beyond session TTL',upload_status(path)==(204,'0-11'))
 check('held unacknowledged chunk is not part of the committed offset',upload_status(path)[1]=='0-11')
 stop('server',hard=True);connection.close();sockets.remove(connection);time.sleep(2.2);start_server()
 sample=preview();items=sample['uploads']['items'];check('actual crash leaves recoverable upload operation',any(x['subject']==path.rsplit('/',1)[-1]for x in items))
 check('other tenant preview excludes crashed upload',preview('b')['uploads']['items']==[])
 key=uuid.uuid4().hex;identifier=recover('images',key=key);again=recover('images',key=key);check('idempotent maintenance admission returns same job',identifier==again)
 check('pending maintenance can cancel',mutation('/api/v1/jobs/'+identifier+'/cancel',{},method='POST')[0]==200)
 check('cancelled maintenance can resume same cursor',mutation('/api/v1/jobs/'+identifier+'/retry',{},method='POST')[0]==200)
 start_worker('reaper');completed=wait_for('crashed upload reconciliation',lambda:done_job(identifier));check('crashed operation recovery retained progress',completed['target']['upload_operations_released']==1 and completed['target']['uploads_expired']==0)
 check('recovered upload retains exactly acknowledged offset',upload_status(path)==(204,'0-11'))
 suffix=b'-resumed';digest=hashlib.sha256(committed+suffix).hexdigest()
 check('resumed OCI final bytes accepted',request(path+'?digest=sha256:'+digest,method='PUT',data=suffix)[0]==201)
 code,data,_=request('/v2/images/app/blobs/sha256:'+digest);check('resumed download is exact committed prefix plus new suffix',code==200 and data==committed+suffix)
 # A job admitted before the crash uses its fixed cutoff and cannot reap later expirations.
 wait_for('pre-crash maintenance drains',lambda:done_job(probe));check('pre-crash cutoff does not count later expiration',get_job(probe)['target']['upload_operations_released']==0)
 stop('reaper')
 idle=begin();time.sleep(4.3);expired_job=recover('images');start_worker('expiry');ended=wait_for('idle session expiry',lambda:done_job(expired_job));check('idle session metadata expires without byte deletion',ended['target']['uploads_expired']==1 and upload_status(idle)[0]==404);stop('expiry')
 cancel_path=begin();held=open_chunk(cancel_path,b'cancel-me');sockets.append(held);time.sleep(.2)
 check('native upload cancellation is immediate',request(cancel_path,method='DELETE')[0]==204)
 check('cancelled in-flight chunk cannot acknowledge',finish_chunk(held)==409);held.close();sockets.remove(held)
 # Current retrievals renew; killing the actual registry leaves a durable stale owner.
 for name in ['live','crashed']:
  HeldOrigin.gates['/'+name]=threading.Event();HeldOrigin.started['/'+name]=threading.Event()
  output={}
  def read_source(name=name,output=output):
   try:output['result']=request('/r/source/'+name)
   except Exception:output['disconnected']=True
  thread=threading.Thread(target=read_source);thread.start();threads.append(thread)
  check(name+': real upstream body started',HeldOrigin.started['/'+name].wait(5))
  initial=cache(name);time.sleep(2.5);renewed=cache(name)
  check(name+': retrieval heartbeat advances deadline',renewed['lease_until']>initial['lease_until'] and renewed['state']=='fetching')
  if name=='live':
   ongoing=recover('source');start_worker('live-check');wait_for('live retrieval reconciliation',lambda:done_job(ongoing));check('reconciliation preserves live retrieval',get_job(ongoing)['target']['retrievals_released']==0 and cache(name)['generation']==initial['generation']);stop('live-check')
   HeldOrigin.gates['/'+name].set();thread.join(5);check('live slow upstream completes successfully',output.get('result',(0,))[0]==200)
  else:
   stop('server',hard=True);HeldOrigin.gates['/'+name].set();thread.join(5);time.sleep(2.2);start_server()
   abandoned=cache(name);check('crash retains fetching state until durable recovery',abandoned['state']=='fetching')
   recovery=recover('source');start_worker('source-reaper');wait_for('crashed source reconciliation',lambda:done_job(recovery));check('recovery advances retrieval generation and records reason',cache(name)['generation']>initial['generation'] and cache(name)['state']=='failed' and cache(name)['last_error']=='lease_recovered')
   check('source recovery has exact durable count',get_job(recovery)['target']['retrievals_released']==1)
   code,data,_=request('/r/source/'+name);check('new generation retrieves bytes after recovery',code==200 and data==b'owned governed retrieval bytes');stop('source-reaper')
 stop('server');start_server();check('maintenance result and cursor survive registry restart',get_job(identifier)['state']=='succeeded' and get_job(identifier)['target']['upload_operations_released']==1)
 result['status']='passed'
except Exception as exc:
 message=str(exc)
 for secret in tokens.values():message=message.replace(secret,'[REDACTED]')
 result['status']='failed';result['error']=message
finally:
 for gate in HeldOrigin.gates.values():gate.set()
 for connection in sockets:connection.close()
 for name in list(processes):stop(name)
 for thread in threads:thread.join(5)
 for fixture in fixtures:fixture.shutdown();fixture.server_close()
 out=ROOT/'evidence'/'2026-10-28'/('leases-'+RUN+'.json');out.write_text(json.dumps(result,indent=2)+'\n');print(result['status'].upper()+': '+str(len(checks))+' assertions; native upload/proxy lease recovery');print('Evidence: '+str(out))
 if result['status']!='passed':raise SystemExit(1)
