#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned native worker/API/CLI proof with real PostgreSQL and actual process kills."""
import socket
import argparse,hashlib,json,os,platform,signal,subprocess,time,urllib.error,urllib.request,uuid,http.server,threading
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT);RUN=uuid.uuid4().hex[:10]
PRIVATE=ROOT/'.private'/'inventory-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
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
result['limits']=['Live ordered local filesystem inventory, not an atomic volume snapshot or deletion authorization. Concurrent entries behind completed cursors require another run.','Only owned macOS/Linux-compatible fixtures; Windows, large directories, multi-host storage identity, S3, GC/holds/retention, scheduling/repair and backup/restore remain required.','Owner connection is used only for explicit fixture faults and legacy metadata setup; registry/worker use nonowner forced-RLS runtime connections.']
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
def start_server(entries=10000,directory=10000):
 logfile=(PRIVATE/'registry.log').open('ab');logs['server']=logfile
 p=subprocess.Popen([str(ROOT/'bin/cratectld'),'serve','--listen','127.0.0.1:38443','--public-url',BASE,'--dev-loopback-http','--objects',str(PRIVATE/'objects'),'--allow-private-upstreams','127.0.0.1/32','--inventory-entry-budget',str(entries),'--inventory-directory-entry-budget',str(directory)],env=runtime,stdout=logfile,stderr=subprocess.STDOUT);processes['server']=p
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
def inject(sql):
 # Only fixture faults use the owner connection. Never pass a DSN/password in argv.
 import urllib.parse
 cfg=urllib.parse.urlparse(env['CRATECTL_OWNER_DSN']);pg=dict(env,PGHOST=cfg.hostname,PGPORT=str(cfg.port),PGUSER=cfg.username,PGDATABASE=cfg.path.lstrip('/'),PGPASSWORD=urllib.parse.unquote(cfg.password or''))
 p=subprocess.run([str(ROOT/'.cache/postgresql-16.15-install/bin/psql'),'-X','-v','ON_ERROR_STOP=1'],input=sql,text=True,env=pg,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
 if p.returncode:raise AssertionError('owned fixture fault injection failed')
def inventory(key=None,page=1,expected=202):
 code,raw,headers=mutation('/api/v1/maintenance/storage-inventories',{'page_size':page},method='POST',key=key)
 check('inventory admission status '+str(expected),code==expected);return json.loads(raw),headers
def inventory_detail(identifier):
 code,raw,_=request('/api/v1/maintenance/storage-inventories/'+identifier)
 if code!=200:raise AssertionError('inventory detail unavailable')
 return json.loads(raw)
def inventory_items(identifier,area='',after=0,limit=1000):
 code,raw,_=request('/api/v1/maintenance/storage-inventories/'+identifier+'/items?limit='+str(limit)+'&after='+str(after)+'&area='+area)
 if code!=200:raise AssertionError('inventory items unavailable')
 return json.loads(raw)
def inventory_observations(identifier):
 code,raw,_=request('/api/v1/maintenance/storage-inventories/'+identifier+'/observations?limit=1000')
 if code!=200:raise AssertionError('inventory hash history unavailable')
 return json.loads(raw)['items']
def inventory_refs(identifier):
 code,raw,_=request('/api/v1/maintenance/storage-inventories/'+identifier+'/references?limit=1000')
 if code!=200:raise AssertionError('inventory reference snapshot unavailable')
 return json.loads(raw)['items']
def completed(identifier):
 j=get_job(identifier)
 if j['state']=='failed':raise AssertionError('inventory failed: '+j['last_error'])
 return j if j['state']=='succeeded'else None
def object_path(tenant,digest):return PRIVATE/'objects'/tenant/'sha256'/digest[:2]/digest
def sync_write(path,data):
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 with path.open('wb')as f:f.write(data);f.flush();os.fsync(f.fileno())
def owned_object(tenant,data):
 digest=hashlib.sha256(data).hexdigest();sync_write(object_path(tenant,digest),data);return digest
def cancel_publication_checks(identity='a'):
 for j in jobs(identity,'integrity'):
  if j['kind']=='artifact.integrity'and j['state']in ['pending','retry']:
   check('cancel publication-only fixture check',mutation('/api/v1/jobs/'+job_id(j)+'/cancel',{},identity,method='POST')[0]==200)
def open_live_publication(data):
 sock=socket.create_connection(('127.0.0.1',38443),timeout=5)
 header='PUT /r/packages/inflight.bin HTTP/1.1\r\nHost: 127.0.0.1:38443\r\nAuthorization: Bearer '+tokens['a']+'\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n'
 sock.sendall(header.encode()+('%x\r\n'%len(data)).encode()+data+b'\r\n');return sock
sockets=[]
try:
 if args.require_clean_build:
  check('qualification source is clean',not result['source_dirty']);check('qualification binaries embed exact clean source',result['build_source_matches_candidate'])
 check('real runtime and owner PostgreSQL provided',bool(env.get('CRATECTL_DSN'))and bool(env.get('CRATECTL_OWNER_DSN')))
 tenants={}
 for identity in ['a','b']:
  tenant='inventory-'+identity+'-'+RUN;tenants[identity]=tenant
  for role,label in [('admin',identity),('worker',identity+'-worker'),('reader',identity+'-reader')]:
   p=PRIVATE/(label+'.token');command([ROOT/'bin/cratectld','provision','--tenant',tenant,'--actor',role,'--role',role,'--token-file',p]);tokens[label]=p.read_text().strip()
 write_private('workers.json',{'token_files':[str(PRIVATE/'a-worker.token'),str(PRIVATE/'b-worker.token')]})
 start_server()
 for identity in ['a','b']:
  check(identity+': create repository',mutation('/api/v1/repositories',{'name':'packages','format':'generic','require_review':identity=='a'},identity,'POST')[0]==201);policy('integrity',identity=identity)
 check('reader cannot list storage inventory',request('/api/v1/maintenance/storage-inventories','a-reader')[0]==403)
 check('worker purpose cannot call public inventory API',request('/api/v1/maintenance/storage-inventories','a-worker')[0]==401)
 check('inventory admission requires idempotency key',request('/api/v1/maintenance/storage-inventories',method='POST',data={})[0]==400)
 check('caller cannot override operator inventory budget',mutation('/api/v1/maintenance/storage-inventories',{'max_entries':10000000},method='POST')[0]==400)
 large=b'owned historical inventory bytes\n'*45000;large_digest=hashlib.sha256(large).hexdigest();missing=b'owned missing reference'
 publish('large.bin',large);publish('alias.bin',large);publish('missing.bin',missing);publish('other.bin',b'other tenant bytes','b')
 missing_digest=hashlib.sha256(missing).hexdigest();missing_path=object_path(tenants['a'],missing_digest);missing_saved=PRIVATE/'missing-original';missing_path.rename(missing_saved)
 orphan=b'owned unreferenced CAS bytes';orphan_digest=owned_object(tenants['a'],orphan)
 corrupt_original=b'owned orphan storage integrity';corrupt_digest=owned_object(tenants['a'],corrupt_original);sync_write(object_path(tenants['a'],corrupt_digest),b'X'*len(corrupt_original))
 for n in range(100000):
  changed_original=('owned changed fixture '+str(n)).encode();changed_digest=hashlib.sha256(changed_original).hexdigest()
  if changed_digest>large_digest:break
 else:raise AssertionError('cannot construct deterministic later hash fixture')
 owned_object(tenants['a'],changed_original)
 aroot=PRIVATE/'objects'/tenants['a'];b_digest=hashlib.sha256(b'other tenant bytes').hexdigest()
 link_original=b'owned link marker';link_digest=hashlib.sha256(link_original).hexdigest();link=object_path(tenants['a'],link_digest);link.parent.mkdir(parents=True,exist_ok=True,mode=0o700);link.symlink_to(object_path(tenants['b'],b_digest))
 fifo_original=b'owned special file fixture';fifo_digest=hashlib.sha256(fifo_original).hexdigest();fifo=object_path(tenants['a'],fifo_digest);fifo.parent.mkdir(parents=True,exist_ok=True,mode=0o700);os.mkfifo(fifo,0o600)
 tenant=tenants['a'];inject("INSERT INTO cratectl.artifacts(tenant,repository,path,digest,size,media_type) VALUES('"+tenant+"','packages','special-fifo','"+fifo_digest+"',"+str(len(fifo_original))+",'application/octet-stream');")
 unexpected=aroot/'unexpected-owned-directory';unexpected.mkdir(mode=0o700);sync_write(unexpected/'retained-child',b'must not disappear')
 sync_write(aroot/'staged'/'upload-owned-retained',b'owned temporary bytes')
 check('create OCI repository',mutation('/api/v1/repositories',{'name':'images','format':'oci'},method='POST')[0]==201)
 def begin_upload():
  code,_,headers=request('/v2/images/app/blobs/uploads/',method='POST',data=b'');check('begin retained upload fixture',code==202);return next(v for k,v in headers.items()if k.lower()=='docker-upload-uuid')
 upload=begin_upload();part=b'owned immutable upload part';check('retain active immutable upload chunk',request('/v2/images/app/blobs/uploads/'+upload,method='PATCH',data=part)[0]==202)
 legacy=begin_upload();sync_write(aroot/'uploads'/legacy,b'owned legacy acknowledged and trailing bytes')
 inject("UPDATE cratectl.uploads SET parts_version=0,offset_bytes=5 WHERE tenant='"+tenant+"' AND id='"+legacy+"';")
 cancel_publication_checks();cancel_publication_checks('b')
 active=open_live_publication(b'owned inflight staged bytes');sockets.append(active)
 wait_for('live publication stage exists',lambda:len(list((aroot/'staged').iterdir()))>=2)
 key=uuid.uuid4().hex;admitted,_=inventory(key=key);identifier=admitted['job'];replay,headers=inventory(key=key)
 check('inventory admission replays identical durable intent',replay==admitted and any(k.lower()=='idempotent-replayed'and v=='true'for k,v in headers.items()))
 check('inventory list returns admitted job',any(job_id(x)==identifier for x in value('/api/v1/maintenance/storage-inventories')['items']))
 check('other tenant cannot inspect inventory metadata',request('/api/v1/maintenance/storage-inventories/'+identifier,'b')[0]==404)
 check('other tenant cannot inspect inventory entries',request('/api/v1/maintenance/storage-inventories/'+identifier+'/items','b')[0]==404)
 start_worker('crash',rate=65536)
 def large_running():
  j=get_job(identifier)
  if j['state']!='running'or j['target']['phase']!='hash':return None
  candidates=[x for x in inventory_items(identifier,'cas')['items']if x['expected_layout']and x['ordinal']>j['target']['hash_after_ordinal']]
  return j if candidates and candidates[0]['digest']==large_digest else None
 running=wait_for('large inventoried CAS hash starts',large_running);old_generation=running['generation'];old_cursor=running['target']['hash_after_ordinal']
 stop('crash',hard=True);active.close();sockets.remove(active)
 sync_write(object_path(tenants['a'],changed_digest),b'Y'*len(changed_original))
 time.sleep(2.2);start_worker('recovered');finished=wait_for('crash-fenced inventory finishes',lambda:completed(identifier));stop('recovered')
 detail=inventory_detail(identifier);check('inventory completion never authorizes deletion or policy',detail['safe_to_delete']is False and detail['security_approval']is False)
 check('unsupported directories and special files prevent complete-layout claim',detail['supported_layout_accounted']is False)
 check('corrupt and changed CAS files prevent a clean receipt',detail['cas_integrity_clean']is False)
 check('missing and special-file references remain findings',detail['reference_snapshot_clean']is False)
 items=inventory_items(identifier)['items'];by_digest={x['digest']:x for x in items if x['area']=='cas'}
 check('unreferenced CAS bytes are inventoried and hashed',by_digest[orphan_digest]['status']=='verified'and by_digest[orphan_digest]['artifact_references_at_walk']==0)
 check('same-length orphan corruption is detected',by_digest[corrupt_digest]['status']=='corrupt')
 check('post-enumeration file changes do not reuse old metadata',by_digest[changed_digest]['status']=='changed')
 check('CAS symlink is recorded without following another tenant',by_digest[link_digest]['type']=='symlink'and by_digest[link_digest]['expected_layout']is False)
 check('CAS named pipe is recorded without blocking',by_digest[fifo_digest]['type']=='other'and by_digest[fifo_digest]['expected_layout']is False)
 check('legacy upload inventory preserves authoritative offset',any(x['area']=='uploads'and x['name']==legacy and x['acknowledged_bytes_at_walk']==5 and x['upload_state_at_walk']=='active'for x in items))
 check('live and retained temporary files remain unverified',detail['unverified_temporary_and_legacy_files']>=3)
 refs=inventory_refs(identifier);check('missing reference is detected beyond filesystem enumeration',any(x['digest']==missing_digest and x['status']=='missing'for x in refs))
 check('special reference is rejected as unsupported I/O',any(x['digest']==fifo_digest and x['status']=='io_error'for x in refs))
 physical_obs=inventory_observations(identifier);check('killed generation cannot commit a hash observation',all(x['generation']!=old_generation for x in physical_obs))
 check('reclaimed inventory advances generation and retains cursor',finished['generation']>old_generation and finished['target']['cas_checked']==finished['target']['cas_files'])
 pages=[];cursor=0
 while True:
  page=inventory_items(identifier,after=cursor,limit=1);pages.extend(page['items'])
  if not page['more']:break
  cursor=page['items'][-1]['ordinal']
 check('inventory cursor traverses every retained entry once',len(pages)==len(items)and len({x['ordinal']for x in pages})==len(items))
 publish('now-referenced.bin',orphan);cancel_publication_checks()
 item=next(x for x in inventory_items(identifier,'cas')['items']if x['digest']==orphan_digest)
 check('current references are separate from unreferenced-at-walk status',item['artifact_references_at_walk']==0 and item['current_artifact_references']==1)
 check('verified CAS bytes still require policy approval',request('/r/packages/large.bin')[0]==403)
 # Repair only owned fixtures; the original walk/entry identities remain immutable.
 sync_write(object_path(tenants['a'],corrupt_digest),corrupt_original);sync_write(object_path(tenants['a'],changed_digest),changed_original);missing_saved.rename(missing_path)
 link.rename(PRIVATE/'saved-symlink');fifo.rename(PRIVATE/'saved-fifo');unexpected.rename(PRIVATE/'saved-unexpected-directory')
 sync_write(link,link_original);sync_write(fifo,fifo_original)
 before_count=len(physical_obs);check('completed inventory can recheck its retained observed set',mutation('/api/v1/jobs/'+identifier+'/retry',{},method='POST')[0]==200)
 start_worker('repeat');wait_for('repeat inventory verification pass',lambda:completed(identifier));stop('repeat')
 check('repeat pass retains old layout findings and observations',get_job(identifier)['target']['pass']==2 and get_job(identifier)['target']['entries']==len(items)and len(inventory_observations(identifier))==before_count*2 and inventory_detail(identifier)['supported_layout_accounted']is False)
 fresh,_=inventory();fresh_id=fresh['job'];start_worker('fresh');fresh_done=wait_for('fresh repaired inventory',lambda:completed(fresh_id));stop('fresh')
 fresh_detail=inventory_detail(fresh_id);check('new inventory accounts for repaired supported layout',fresh_detail['supported_layout_accounted']is True and fresh_detail['cas_integrity_clean']is True and fresh_detail['reference_snapshot_clean']is True)
 # Cancellation accepts no observation from the in-flight file and retains a resumable cursor.
 cancelled,_=inventory();cancel_id=cancelled['job'];start_worker('cancel',rate=65536)
 def cancellable():
  j=get_job(cancel_id)
  if j['state']!='running'or j['target']['phase']!='hash':return None
  candidates=[x for x in inventory_items(cancel_id,'cas')['items']if x['expected_layout']and x['ordinal']>j['target']['hash_after_ordinal']]
  return j if candidates and candidates[0]['digest']==large_digest else None
 live=wait_for('cancellable large inventory hash',cancellable);cursor=live['target']['hash_after_ordinal']
 check('cancel in-flight inventory',mutation('/api/v1/jobs/'+cancel_id+'/cancel',{},method='POST')[0]==200)
 wait_for('inventory cancellation acknowledges',lambda:get_job(cancel_id)['state']=='cancelled');check('cancelled hash cannot advance cursor',get_job(cancel_id)['target']['hash_after_ordinal']==cursor);stop('cancel')
 check('cancelled inventory resumes same observed set',mutation('/api/v1/jobs/'+cancel_id+'/retry',{},method='POST')[0]==200)
 start_worker('resume');wait_for('resumed inventory completes',lambda:completed(cancel_id));stop('resume')
 # Small operator limits fail explicitly without reporting full coverage.
 stop('server');start_server(entries=1);limited,_=inventory();limited_id=limited['job'];start_worker('limited')
 wait_for('total inventory budget fails honestly',lambda:get_job(limited_id)['state']=='failed');stop('limited');check('entry budget failure does not claim completed layout',get_job(limited_id)['last_error']=='inventory_budget'and inventory_detail(limited_id)['supported_layout_accounted']is False)
 stop('server');start_server(directory=1);directory,_=inventory();directory_id=directory['job'];start_worker('directory')
 wait_for('directory scan budget fails honestly',lambda:get_job(directory_id)['state']=='failed');stop('directory');check('directory budget is an explicit failure',get_job(directory_id)['last_error']=='inventory_budget')
 stop('server');start_server()
 # A different object-root identity cannot be mixed into an admitted run.
 fence_key=uuid.uuid4().hex;fenced,_=inventory(key=fence_key);fence_id=fenced['job']
 stop('server');(PRIVATE/'objects').rename(PRIVATE/'objects-original');(PRIVATE/'objects').mkdir(mode=0o700);start_server();start_worker('root-change')
 wait_for('changed storage identity fences inventory',lambda:get_job(fence_id)['state']=='failed');stop('root-change')
 check('replacement root produces no successful mixed inventory',get_job(fence_id)['last_error']=='storage_changed')
 replay,_=inventory(key=fence_key);check('idempotent admission survives later storage replacement',replay==fenced)
 stop('server');(PRIVATE/'objects').rename(PRIVATE/'replacement-empty');(PRIVATE/'objects-original').rename(PRIVATE/'objects');start_server()
 check('inventory history survives registry restart',get_job(identifier)['state']=='succeeded'and get_job(identifier)['target']['pass']==2 and len(inventory_observations(identifier))==before_count*2)
 result['inventory_profile']={'first_pass':finished['target'],'repeat_pass':get_job(identifier)['target'],'repaired_inventory':fresh_done['target'],'crashed_generation':old_generation,'crashed_cursor':old_cursor,'physical_observations_first_pass':before_count,'retained_entries':len(items),'safe_to_delete':False,'security_approval':False}
 result['status']='passed'
except Exception as exc:
 message=str(exc)
 for secret in tokens.values():message=message.replace(secret,'[REDACTED]')
 result['status']='failed';result['error']=message
finally:
 for sock in sockets:sock.close()
 for name in list(processes):stop(name)
 out=ROOT/'evidence'/'2026-10-28'/('inventory-'+RUN+'.json');out.write_text(json.dumps(result,indent=2)+'\n');print(result['status'].upper()+': '+str(len(checks))+' assertions; native tenant filesystem inventory');print('Evidence: '+str(out))
 if result['status']!='passed':raise SystemExit(1)
