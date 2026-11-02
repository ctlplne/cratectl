#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned schema-4 upgrade, stock ORAS recovery and streaming repair CLI proof."""
import argparse,datetime,hashlib,json,os,platform,subprocess,time,urllib.error,urllib.parse,urllib.request,uuid
from pathlib import Path
from qualification_contract import candidate_binary_directory, candidate_artifact_names
BIN = candidate_binary_directory()
from qualification_contract import CURRENT_SCHEMA
parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT);RUN=uuid.uuid4().hex[:10];PRIVATE=ROOT/'.private/repair-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
BASE='http://127.0.0.1:38443';OLD=ROOT/'.cache/source-final-production/cratectld';NEW=BIN/'cratectld';ORAS=ROOT/'.cache/bin/oras';env=dict(os.environ);checks=[];commands=[];processes={};logs={};tokens={}
def identity(binary):
 out={}
 for line in subprocess.check_output([ROOT/'.cache/go/bin/go','version','-m',binary],text=True).splitlines():
  fields=line.strip().split('\t')
  if len(fields)==2 and fields[0]=='build'and '='in fields[1]:key,value=fields[1].split('=',1);out[key]=value
 return out
candidate=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip();scope=['cmd','internal','scripts','web','api','go.mod','go.sum','Makefile']
result={'run':RUN,'candidate':candidate,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*scope]).strip()),'checks':checks,'commands':commands,'artifact_digests':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in [OLD,NEW,BIN/'cratectl',ORAS]},'build_identity':{str(p.relative_to(ROOT)):identity(p)for p in [OLD,NEW,BIN/'cratectl']},'topology':f'Native {platform.platform()}, real PostgreSQL 16.15 with nonowner forced RLS, owned registry/worker, stock ORAS and streaming cratectl CLI; explicit HTTP loopback.','limits':['Exact local-byte repair retains corrupt/staged data and preserves policy/lifecycle. No erasure, reclaimed space or security approval is claimed.','Named raw/OCI outcomes only; all format/client, legacy metadata repair, S3, scale, backup/restore and other-platform requirements remain open.','Maintenance upgrade with all old processes stopped; rolling versions and transfer draining remain unqualified.']}
result['expected_schema'] = CURRENT_SCHEMA
result['build_source_matches_candidate']=all(result['build_identity'][str(p.relative_to(ROOT))].get('vcs.revision')==candidate and result['build_identity'][str(p.relative_to(ROOT))].get('vcs.modified')=='false'for p in [NEW,BIN/'cratectl'])
def check(label,condition):
 if not condition:raise AssertionError(label)
 checks.append(label)
def private(name,value):
 p=PRIVATE/name;p.write_bytes(value if isinstance(value,bytes)else json.dumps(value).encode());p.chmod(0o600);return p
def run(argv,extra=None,cwd=PRIVATE,input_bytes=None,ok=True):
 e=dict(env);e.update(extra or {});p=subprocess.run([str(a)for a in argv],env=e,cwd=cwd,input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90)
 output=p.stdout.decode(errors='replace')
 for token in tokens.values():output=output.replace(token,'[REDACTED]')
 commands.append({'argv':[str(a).replace(str(PRIVATE),'PRIVATE')for a in argv],'exit':p.returncode,'output':output[-8000:],'expected_failure':not ok})
 if (p.returncode==0)!=ok:raise AssertionError('unexpected command result: '+str(argv[0])+': '+output[-1500:])
 return p.stdout
def stop(name):
 p=processes.pop(name,None)
 if p and p.poll()is None:
  p.terminate()
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
 if name in logs:logs.pop(name).close()
def start(name,binary,worker=False):
 logs[name]=(PRIVATE/(name+'.log')).open('ab')
 argv=[binary,'worker'if worker else'serve','--objects',PRIVATE/'objects']
 if worker:argv+=['--identities',PRIVATE/'workers.json','--poll','20ms']
 else:
  argv+=['--listen','127.0.0.1:38443','--public-url',BASE,'--dev-loopback-http']
  if binary==NEW:argv+=['--transfer-timeout','60s']
 processes[name]=subprocess.Popen([str(x)for x in argv],env=env,stdout=logs[name],stderr=subprocess.STDOUT)
 if not worker:
  for _ in range(150):
   if processes[name].poll()is not None:raise AssertionError('owned registry exited')
   try:
    with urllib.request.urlopen(BASE+'/health/ready',timeout=1)as response:
     if response.status==200:return
   except Exception:time.sleep(.05)
  raise AssertionError('owned registry did not become ready')
def api(path,method='GET',body=None,key=None,role='admin',headers=None):
 if isinstance(body,dict):body=json.dumps(body).encode()
 h={'Authorization':'Bearer '+tokens[role],'Content-Type':'application/json'};h.update(headers or {})
 if key:h['Idempotency-Key']=key
 request=urllib.request.Request(BASE+path,data=body,method=method,headers=h)
 try:
  with urllib.request.urlopen(request,timeout=10)as response:return response.status,response.read(),dict(response.headers)
 except urllib.error.HTTPError as e:return e.code,e.read(),dict(e.headers)
def oras(*arguments,cwd=PRIVATE,ok=True):return run([ORAS,*arguments,'--plain-http','--registry-config',PRIVATE/'oras.json'],cwd=cwd,ok=ok)
def plan(repo,path,digest):
 input={'path':path,'digest':digest,'expected_source_revision':0,'reason':'Recover independently retained owned fixture','provenance':'Private independent native fixture source'}
 code,body,_=api('/api/v1/repositories/'+repo+'/artifacts/repairs','POST',dict(input,dry_run=True));check('preview exact retained repair target',code==200 and not json.loads(body)['source_ready'])
 code,body,_=api('/api/v1/repositories/'+repo+'/artifacts/repairs','POST',input,'repair-plan-'+uuid.uuid4().hex);check('durable repair waits for source',code==202 and json.loads(body)['state']=='awaiting_source');return json.loads(body)['job']
def repair(repo,path,digest,source):
 id=plan(repo,path,digest);key='repair-source-'+uuid.uuid4().hex
 output=run([BIN/'cratectl','--url',BASE,'--token-file',PRIVATE/'admin.token','--method','PUT','--path','/api/v1/maintenance/repairs/'+id+'/source','--upload-file',source,'--idempotency-key',key,'--timeout','60s'])
 check('streaming CLI accepts exact source',json.loads(output)['source_ready'])
 for _ in range(300):
  code,body,_=api('/api/v1/jobs/'+id);job=json.loads(body)
  if job['state']in ['failed','cancelled','uncertain']:raise AssertionError('repair stopped: '+job['last_error'])
  if job['state']=='succeeded':break
  time.sleep(.03)
 else:raise AssertionError('repair did not complete')
 check('worker commits verified completion',job['handler']=='storage.repair'and job['state']=='succeeded')
 check('private requester and source filenames are omitted','requester'not in body.decode()and 'upload-'not in body.decode())
 code,body,_=api('/api/v1/jobs/'+id+'/observations');rows=json.loads(body)['items'];check('immutable readback observation',code==200 and rows and rows[-1]['status']=='verified')
 replay=run([BIN/'cratectl','--url',BASE,'--token-file',PRIVATE/'admin.token','--method','PUT','--path','/api/v1/maintenance/repairs/'+id+'/source','--upload-file',source,'--idempotency-key',key]);check('source replay confirms original result',json.loads(replay)==json.loads(output))
 return job
try:
 if args.require_clean_build:check('repair code and artifacts identify one clean candidate',not result['source_dirty']and result['build_source_matches_candidate'])
 check('schema-4 baseline is retained qualified source',identity(OLD).get('vcs.revision')=='06156af19b9759035e96d63cf7a8bf52903235f7')
 owner=urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN']);database='cratectl_repair_'+RUN;pgenv=dict(env,PGHOST=owner.hostname,PGPORT=str(owner.port),PGUSER=urllib.parse.unquote(owner.username),PGPASSWORD=urllib.parse.unquote(owner.password),PGDATABASE=owner.path.lstrip('/'))
 run([ROOT/'.cache/postgresql-16.15-install/bin/psql','-X','-v','ON_ERROR_STOP=1','-At','-c','CREATE DATABASE '+database],pgenv)
 for key in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']:
  u=urllib.parse.urlsplit(env[key]);env[key]=urllib.parse.urlunsplit((u.scheme,u.netloc,'/'+database,u.query,u.fragment))
 private('database.json',{'owner':env['CRATECTL_OWNER_DSN'],'runtime':env['CRATECTL_DSN']});run([OLD,'migrate']);before=json.loads(run([OLD,'migrate','--plan']));check('actual old database has four frozen receipts',len(before['applied'])==4 and before['safety_valid'])
 tenant='repair-'+RUN
 for role in ['admin','reader','worker']:
  p=PRIVATE/(role+'.token');run([OLD,'provision','--tenant',tenant,'--actor',role,'--role',role,'--token-file',p]);tokens[role]=p.read_text().strip()
 private('workers.json',{'token_files':[str(PRIVATE/'worker.token')]})
 start('registry',OLD)
 for name,fmt in [('raw','generic'),('containers','oci')]:check('baseline creates '+name,api('/api/v1/repositories','POST',{'name':name,'format':fmt},'create-'+name)[0]==201)
 payload=(b'owned exact native repair bytes\n'*2048);source=private('payload.txt',payload);digest=hashlib.sha256(payload).hexdigest()
 check('old baseline publishes raw bytes',api('/r/raw/file','PUT',payload,headers={'Content-Type':'application/octet-stream'})[0]==201)
 run([ORAS,'login','--plain-http','--registry-config',PRIVATE/'oras.json','--username','token','--password-stdin','127.0.0.1:38443'],input_bytes=(tokens['admin']+'\n').encode())
 ref='127.0.0.1:38443/containers/proof:v1';oras('push',ref,'payload.txt:text/plain');root_digest=oras('resolve',ref).decode().strip();root_path='proof/manifests/'+root_digest
 manifest=api('/v2/containers/'+root_path)[1];manifest_source=private('manifest.json',manifest);stop('registry')
 pending=json.loads(run([NEW,'migrate','--plan']));check(f'repair-capable migrator plans the remaining versions 5 through {CURRENT_SCHEMA}',pending['binary_version']==CURRENT_SCHEMA and pending['pending']==list(range(5,CURRENT_SCHEMA+1))and pending['safety_valid']);run([NEW,'migrate']);after=json.loads(run([NEW,'migrate','--plan']));check(f'upgrade retains all four receipts and adds {CURRENT_SCHEMA - 4} remaining steps',after['applied'][:4]==before['applied']and after['binary_version']==CURRENT_SCHEMA and len(after['applied'])==CURRENT_SCHEMA and not after['pending']and after['safety_valid']);run([OLD,'migrate','--plan'],ok=False);check('old runtime rejects repair jobs database',True)
 run([NEW,'serve','--transfer-timeout','0s'],ok=False);check('unbounded transfer deadline is rejected before startup',True)
 start('registry',NEW);start('worker',NEW,True)
 physical=PRIVATE/'objects'/tenant/'sha256'/digest[:2]/digest;physical.unlink();check('missing bytes fail the native download',api('/r/raw/file')[0]==503);missing=PRIVATE/'missing-pull';missing.mkdir();oras('pull',ref,cwd=missing,ok=False)
 id=plan('raw','file',digest);code,body,_=api('/api/v1/jobs/'+id);check('waiting source is never claimed',json.loads(body)['attempts']==0)
 check('reader cannot submit repair source',api('/api/v1/maintenance/repairs/'+id+'/source','PUT',payload,'reader-source',role='reader',headers={'Content-Type':'application/octet-stream'})[0]==403)
 api('/api/v1/jobs/'+id+'/cancel','POST',{},'cancel-unused-plan')
 repair('raw','file',digest,source);check('raw source restored exactly',api('/r/raw/file')[1]==payload)
 target=PRIVATE/'repaired-pull';target.mkdir();oras('pull',ref,cwd=target);check('stock ORAS installs the repaired shared layer',(target/'payload.txt').read_bytes()==payload)
 corrupt=b'X'*len(payload);physical.write_bytes(corrupt);api('/api/v1/repositories/raw/decisions','PUT',{'path':'file','digest':digest,'decision':'denied'},'deny-raw')
 job=repair('containers','proof/blobs/sha256:'+digest,digest,source);check('repair retains prior corrupt inode',job['target']['installation']['retained_previous']);check('repair preserves a denial on another reference',api('/r/raw/file')[0]==403)
 check('prior corrupt bytes remain retained',any(p.is_file()and p.read_bytes()==corrupt for p in (PRIVATE/'objects'/tenant/'staged').iterdir()))
 check('native deletion retains a canonical tombstone',api('/v2/containers/'+root_path,'DELETE')[0]==202)
 root_physical=PRIVATE/'objects'/tenant/'sha256'/root_digest[7:9]/root_digest[7:];root_physical.write_bytes(b'Z'*len(manifest));repair('containers',root_path,root_digest[7:],manifest_source);check('byte repair cannot restore a tombstone',api('/v2/containers/'+root_path)[0]==404)
 restored=api('/api/v1/repositories/containers/artifacts/lifecycle','PUT',{'path':root_path,'digest':root_digest[7:],'action':'restore','expected_revision':1,'reason':'Restore only after exact-byte repair'},'restore-after-repair');check('explicit lifecycle recovery follows byte repair',restored[0]==200)
 stop('worker');stop('registry');start('registry',NEW);final=PRIVATE/'restart-pull';final.mkdir();oras('pull',ref,cwd=final);check('stock ORAS exact recovery survives real process restart',(final/'payload.txt').read_bytes()==payload)
 result['status']='passed';print('PASS: '+str(len(checks))+' repair assertions')
except BaseException as e:result['status']='failed';result['failure']=type(e).__name__+': '+str(e);raise
finally:
 for name in list(processes):stop(name)
 target=ROOT/'evidence'/datetime.datetime.now(datetime.timezone.utc).date().isoformat();target.mkdir(exist_ok=True);path=target/('repairs-'+RUN+'.json');path.write_text(json.dumps(result,indent=2)+'\n');print('Evidence: '+str(path))
