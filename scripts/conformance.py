# SPDX-License-Identifier: BUSL-1.1
"""Real local service + PostgreSQL + stock clients; all credentials stay private."""
import base64,csv,datetime,hashlib,io,json,os,platform,shutil,subprocess,sys,tarfile,time,urllib.error,urllib.parse,urllib.request,uuid,zipfile
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as XML
from pathlib import Path
from qualification_contract import candidate_binary_directory, candidate_artifact_names
BIN = candidate_binary_directory()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT)
BASE='http://127.0.0.1:38443';RUN=uuid.uuid4().hex[:10]
PRIVATE=ROOT/'.private/conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
EVIDENCE=ROOT/'evidence'/datetime.datetime.now(datetime.timezone.utc).date().isoformat();EVIDENCE.mkdir(exist_ok=True)
database_profile=os.environ.get('CRATECTL_DEV_DATABASE','container')
config=json.loads(Path(os.environ.get('CRATECTL_CONFORMANCE_DATABASE_FILE',str(ROOT/('.private/native-db.json' if database_profile=='native' else '.private/db.json')))).read_text())
env=dict(os.environ,CRATECTL_OWNER_DSN=config['owner'],CRATECTL_DSN=config['runtime'])
tokens={};checks=[];commands=[];proc=None;logfile=None

def run(args,cwd=ROOT,extra=None,input_text=None,expect_failure=False):
 e=dict(env);e.update(extra or {})
 result=subprocess.run([str(a) for a in args],cwd=cwd,env=e,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,input=input_text)
 output=result.stdout
 for token in tokens.values():output=output.replace(token,'[REDACTED]')
 public_args=[str(a).replace(str(PRIVATE),'PRIVATE') for a in args]
 for token in tokens.values():public_args=[arg.replace(token,'[REDACTED]') for arg in public_args]
 commands.append({'argv':public_args,'exit':result.returncode,'output':output[-12000:]})
 if result.returncode and not expect_failure:raise AssertionError(f'{args[0]} exited {result.returncode}: {output[-3000:]}')
 if expect_failure:
  commands[-1]['expected_failure']=True
  if result.returncode==0:raise AssertionError(f'{args[0]} unexpectedly succeeded')
 return output

def req(p,token='admin',method='GET',data=None,key=None,headers=None):
 if isinstance(data,dict):data=json.dumps(data).encode()
 h={'Authorization':'Bearer '+tokens.get(token,token)}
 if data is not None:h['Content-Type']='application/json'
 if key:h['Idempotency-Key']=key
 h.update(headers or {})
 r=urllib.request.Request(BASE+p,data=data,headers=h,method=method)
 try:
  with urllib.request.urlopen(r,timeout=15) as response:return response.status,response.read(),dict(response.headers)
 except urllib.error.HTTPError as e:return e.code,e.read(),dict(e.headers)

def check(name,condition):
 if not condition:raise AssertionError(name)
 checks.append(name)

def repository(name,fmt,token='admin',review=False,**options):
 code,body,_=req('/api/v1/repositories',token,'POST',{'name':name,'format':fmt,'require_review':review,**options},uuid.uuid4().hex)
 check(f'{token}: create {fmt} repository {name}',code==201)

def start():
 global proc,logfile
 credentials=PRIVATE/'upstreams.json';credentials.write_text(json.dumps({tenants['admin']+'/oci-up':{'value':tokens['origin'],'allowed_url':BASE+'/v2/up-oci/'},tenants['admin']+'/fixture':{'value':tokens['origin'],'allowed_url':BASE+'/r/source/'},tenants['admin']+'/self':{'value':tokens['reader'],'allowed_url':BASE+'/r/java/'},tenants['admin']+'/bad-fixture':{'value':tokens['origin'],'allowed_url':BASE+'/r/bad-source/'},tenants['admin']+'/npm-fixture':{'value':tokens['origin'],'allowed_url':BASE+'/npm/up-npm/'},tenants['admin']+'/python-up':{'value':tokens['origin'],'allowed_url':BASE+'/pypi/up-python/'},tenants['admin']+'/npm-meta':{'value':tokens['npm-meta-origin'],'allowed_url':BASE+'/r/npm-meta/'},tenants['admin']+'/npm-files':{'value':tokens['npm-files-origin'],'allowed_url':BASE+'/r/npm-files/'}}));credentials.chmod(0o600)
 if 'config-a' in tokens:
  bindings=json.loads(credentials.read_text())
  for side in ['a','b']:
   for fmt,prefix in [('raw','r'),('java','r'),('js','npm'),('py','pypi'),('oci','v2')]:
    bindings[tenants['admin']+'/config-'+fmt+'-'+side]={'value':tokens['config-'+side],'allowed_url':BASE+'/'+prefix+'/config-'+fmt+'-'+side+'/'}
  credentials.write_text(json.dumps(bindings))
 logfile=(PRIVATE/'server.log').open('a')
 proc=subprocess.Popen([str(BIN/'cratectld'),'serve','--listen','127.0.0.1:38443','--public-url',BASE,'--dev-loopback-http','--objects',str(PRIVATE/'objects'),'--upstream-credentials',str(credentials),'--allow-private-upstreams','127.0.0.1/32'],env=env,stdout=logfile,stderr=subprocess.STDOUT)
 for _ in range(100):
  if proc.poll() is not None:raise AssertionError('server failed: '+(PRIVATE/'server.log').read_text())
  try:
   with urllib.request.urlopen(BASE+'/health/ready',timeout=1) as r:
    if r.status==200:return
  except Exception:time.sleep(.05)
 raise AssertionError('server readiness timeout')

def stop():
 global proc,logfile
 if proc is not None:
  proc.terminate();proc.wait(timeout=15);proc=None
 if logfile:logfile.close();logfile=None

def generic():
 check('expiring credential denied',req('/api/v1/repositories','expired')[0]==401)
 check('credential works before revocation',req('/api/v1/repositories','revocable')[0]==200)
 run([BIN/'cratectld','revoke','--token-file',PRIVATE/'revocable.token'])
 check('revocation affects subsequent requests',req('/api/v1/repositories','revocable')[0]==401)
 repository('raw','generic');repository('raw','generic','other')
 key=uuid.uuid4().hex;body={'name':'idem','format':'generic'}
 a=req('/api/v1/repositories',method='POST',data=body,key=key);b=req('/api/v1/repositories',method='POST',data=body,key=key)
 check('management replay returns original response',a[:2]==b[:2] and b[2].get('Idempotent-Replayed')=='true')
 check('changed request under same key conflicts',req('/api/v1/repositories',method='POST',data={'name':'changed','format':'generic'},key=key)[0]==409)
 check('management mutation requires idempotency key',req('/api/v1/repositories',method='POST',data=body)[0]==400)
 check('reader cannot publish',req('/r/raw/object','reader','PUT',b'content')[0]==403)
 check('invalid credential denied',req('/r/raw/object','bad-token')[0]==401)
 payload=b'cratectl exact immutable bytes\n'*10000
 code,body,_=req('/r/raw/object',method='PUT',data=payload);check('publish durable raw bytes',code==201);obj=json.loads(body)
 check('same-byte native replay succeeds',req('/r/raw/object',method='PUT',data=payload)[0]==201)
 check('different-byte redeploy conflicts',req('/r/raw/object',method='PUT',data=b'other')[0]==409)
 check('cross-tenant coordinates do not leak',req('/r/raw/object','other')[0]==404)
 check('other tenant can use same coordinate',req('/r/raw/object','other','PUT',b'other tenant')[0]==201)
 check('tenant bytes stay distinct',req('/r/raw/object','other')[1]==b'other tenant' and req('/r/raw/object')[1]==payload)
 code,body,h=req('/r/raw/object',headers={'Range':'bytes=1-7'});check('range preserves selected bytes',code==206 and body==payload[1:8])
 etag=req('/r/raw/object')[2]['Etag'];check('conditional GET returns 304',req('/r/raw/object',headers={'If-None-Match':etag})[0]==304)
 check('wrong checksum is rejected',req('/r/raw/wrong',method='PUT',data=b'test',headers={'X-Checksum-Sha256':'0'*64})[0]!=201)
 check('checksum failure publishes no reference',req('/r/raw/wrong')[0]==404)
 def publish(n):return req('/r/raw/race',method='PUT',data=str(n).encode())[0]
 with ThreadPoolExecutor(max_workers=8) as pool:codes=list(pool.map(publish,range(8)))
 check('concurrent first writer is unique',codes.count(201)==1 and codes.count(409)==7)
 check('require review takes effect on existing bytes',req('/api/v1/repositories/raw/policy',method='PUT',data={'require_review':True},key=uuid.uuid4().hex)[0]==200 and req('/r/raw/object')[0]==403)
 decision={'path':'object','digest':obj['digest'],'decision':'allowed'}
 check('manual review binds exact digest',req('/api/v1/repositories/raw/decisions',method='PUT',data={**decision,'digest':'0'*64},key=uuid.uuid4().hex)[0]==404)
 check('manual review allows exact bytes',req('/api/v1/repositories/raw/decisions',method='PUT',data=decision,key=uuid.uuid4().hex)[0]==200 and req('/r/raw/object')[1]==payload)
 stop();start();check('reference, policy and bytes survive restart',req('/r/raw/object')[1]==payload and req('/r/raw/race')[0]==403)
 # Independent verification of the exact retained payload, not a server assertion.
 events=json.loads(req('/api/v1/audit')[1])['items'];prev='';seq=0
 for event in events:
  seq+=1;check(f'audit sequence {seq}',event['sequence']==seq)
  check(f'audit chain {seq}',event['previous_hash']==prev and event['hash']==hashlib.sha256((prev+'\n'+event['payload']).encode()).hexdigest())
  prev=event['hash']
 check('audit is tenant scoped',all(json.loads(x['payload'])['tenant']==tenants['admin'] for x in events))
 object_path=PRIVATE/'objects'/tenants['admin']/'sha256'/obj['digest'][:2]/obj['digest']
 object_path.write_bytes(b'X'*len(payload))
 check('same-length storage corruption is never served',req('/r/raw/object')[0]==503)
 object_path.write_bytes(payload)

def npm():
 repository('js','npm')
 work=PRIVATE/'npm';work.mkdir();npmrc=work/'npmrc';npmrc.write_text(f'registry={BASE}/npm/js/\n//127.0.0.1:38443/npm/js/:_authToken={tokens["admin"]}\n');npmrc.chmod(0o600)
 extra={'NPM_CONFIG_USERCONFIG':str(npmrc),'NPM_CONFIG_CACHE':str(work/'cache')}
 for name,body in [('cratectl-proof-dep',{'name':'cratectl-proof-dep','version':'1.0.0'}),('@cratectl/proof-app',{'name':'@cratectl/proof-app','version':'1.0.0','dependencies':{'cratectl-proof-dep':'1.0.0'}})]:
  d=work/name.replace('/','-');d.mkdir();(d/'package.json').write_text(json.dumps({**body,'description':'Native conformance package','license':'MIT','main':'index.js'}));(d/'index.js').write_text('module.exports = '+ ('41;' if 'dep' in name else 'require("cratectl-proof-dep") + 1;'))
  run(['npm','publish','--ignore-scripts','--access','public'],d,extra)
 for version,tag in [('1.0.0','latest'),('2.0.0','latest'),('2.1.0-beta.1+build.7','next')]:
  d=work/('tagged-'+version);d.mkdir();(d/'package.json').write_text(json.dumps({'name':'@cratectl/tagged','version':version,'description':'Native tag and version fixture','license':'MIT','main':'index.js','dependencies':{'cratectl-proof-dep':'1.0.0'}}));(d/'index.js').write_text('module.exports = require("cratectl-proof-dep") + 1;')
  run(['npm','publish','--ignore-scripts','--access','public','--tag',tag],d,extra)
 run(['npm','dist-tag','add','@cratectl/tagged@1.0.0','stable'],work,extra)
 document=json.loads(req('/npm/js/@cratectl%2ftagged')[1])
 check('native npm tag update is independent from publication metadata',document['dist-tags']['latest']=='2.0.0' and document['dist-tags']['stable']=='1.0.0')
 check('npm package version endpoint resolves exact release',json.loads(req('/npm/js/@cratectl/tagged/1.0.0')[1])['version']=='1.0.0')
 check('npm package tag endpoint resolves current tag',json.loads(req('/npm/js/@cratectl/tagged/stable')[1])['version']=='1.0.0')
 check('native prerelease publish remains distinct from latest',document['dist-tags']['next'].startswith('2.1.0-beta.1') and document['dist-tags']['latest']=='2.0.0')
 run(['npm','dist-tag','rm','@cratectl/tagged','stable'],work,extra)
 stop();start();check('removed npm tag does not return after restart','stable' not in json.loads(req('/npm/js/@cratectl/tagged')[1])['dist-tags'])
 etag=req('/npm/js/@cratectl/tagged')[2]['Etag']
 check('npm metadata supports weak conditional entity tags',req('/npm/js/@cratectl/tagged',headers={'If-None-Match':'W/'+etag})[0]==304)
 reader_npmrc=work/'reader-npmrc';reader_npmrc.write_text(f'registry={BASE}/npm/js/\n//127.0.0.1:38443/npm/js/:_authToken={tokens["reader"]}\n');reader_npmrc.chmod(0o600)
 denied_change=req('/npm/js/-/package/@cratectl%2ftagged/dist-tags/blocked','reader','PUT',b'"1.0.0"')
 check('npm tag mutation requires writer authority',denied_change[0]==403)
 # Benign hand-crafted archives exercise metadata binding and hostile paths.
 archive_name='cratectl-archive-proof';version='1.0.0'
 def archive_document(inner_name=archive_name,extra_entry=None):
  manifest=json.dumps({'name':inner_name,'version':version,'main':'index.js','dependencies':{'cratectl-proof-dep':'1.0.0'}}).encode();stream=io.BytesIO()
  with tarfile.open(fileobj=stream,mode='w:gz') as archive:
   entries=[('package/package.json',manifest),('package/index.js',b'module.exports = require("cratectl-proof-dep") + 1;')]
   if extra_entry:entries.append(extra_entry)
   for path,body in entries:
    info=tarfile.TarInfo(path);info.size=len(body);archive.addfile(info,io.BytesIO(body))
  data=stream.getvalue()
  return {'name':archive_name,'versions':{version:{'name':archive_name,'version':version,'dependencies':{'forged-outer-dependency':'*'}}},'dist-tags':{'latest':version},'_attachments':{archive_name+'-'+version+'.tgz':{'data':base64.b64encode(data).decode(),'length':len(data)}}}
 check('npm archive identity mismatch rejected',req('/npm/js/'+archive_name,method='PUT',data=archive_document('wrong-package'))[0]==400)
 check('npm archive traversal rejected',req('/npm/js/'+archive_name,method='PUT',data=archive_document(extra_entry=('package/../../escape',b'benign fixture')))[0]==400)
 check('npm duplicate package manifest rejected',req('/npm/js/'+archive_name,method='PUT',data=archive_document(extra_entry=('package/package.json',b'{}')))[0]==400)
 check('rejected npm archive creates no reference',req('/npm/js/'+archive_name)[0]==404)
 check('archive-bound npm metadata accepted',req('/npm/js/'+archive_name,method='PUT',data=archive_document())[0]==201)
 verified=json.loads(req('/npm/js/'+archive_name+'/1.0.0')[1])
 check('npm dependency metadata comes from immutable archive bytes',verified['dependencies']=={'cratectl-proof-dep':'1.0.0'})
 consumer=work/'consumer';consumer.mkdir();(consumer/'package.json').write_text('{"name":"proof-consumer","version":"1.0.0"}')
 run(['npm','install','--ignore-scripts','--no-audit','--no-fund',archive_name],consumer,extra)
 check('stock npm installs archive-bound dependency graph',run(['node','-e','if(require("cratectl-archive-proof")!==42)process.exit(1)'],consumer).strip()=='')
 run(['npm','install','--ignore-scripts','--no-audit','--no-fund','@cratectl/tagged@latest'],consumer,extra)
 check('stock npm selects current latest release',run(['node','-e','if(require("@cratectl/tagged/package.json").version!=="2.0.0")process.exit(1)'],consumer).strip()=='')
 run(['npm','install','--ignore-scripts','--no-audit','--no-fund','@cratectl/tagged@next'],consumer,extra)
 check('stock npm selects prerelease through named tag',run(['node','-e','if(!require("@cratectl/tagged/package.json").version.startsWith("2.1.0-beta.1"))process.exit(1)'],consumer).strip()=='')
 run(['npm','install','--ignore-scripts','--no-audit','--no-fund','@cratectl/proof-app@1.0.0'],consumer,extra)
 check('stock npm resolves scoped package and dependency',run(['node','-e','if(require("@cratectl/proof-app")!==42)process.exit(1)'],consumer).strip()=='')
 stop();start();shutil.rmtree(consumer/'node_modules');run(['npm','ci','--ignore-scripts','--no-audit','--no-fund','--cache',str(work/'fresh-cache')],consumer,extra)
 check('stock npm lockfile install survives server restart',True)
 as_=json.loads(req('/api/v1/repositories/js/artifacts')[1])['items'];target=next(a for a in as_ if a['path'].startswith('@'))
 req('/api/v1/repositories/js/decisions',method='PUT',data={'path':target['path'],'digest':target['digest'],'decision':'denied'},key=uuid.uuid4().hex)
 check('npm policy denial hides package metadata',req('/npm/js/@cratectl%2fproof-app')[0]==404)
 check('npm policy denial blocks tarball',req('/npm/js/'+target['path'])[0]==403)

def npmproxy():
 repository('up-npm','npm','other')
 work=PRIVATE/'npm-proxy';work.mkdir()
 def npm_env(repository_name,label,cache_name):
  rc=work/(cache_name+'.npmrc');rc.write_text(f'registry={BASE}/npm/{repository_name}/\n//127.0.0.1:38443/npm/{repository_name}/:_authToken={tokens[label]}\nfetch-retries=0\n');rc.chmod(0o600)
  return {'NPM_CONFIG_USERCONFIG':str(rc),'NPM_CONFIG_CACHE':str(work/cache_name)}
 origin=npm_env('up-npm','other','origin-cache')
 def publish(name,version,value,extra,where):
  d=work/where;d.mkdir();body={'name':name,'version':version,'description':'Native proxy/group fixture','license':'MIT','main':'index.js'}
  if name!='cratectl-remote-dep':body['dependencies']={'cratectl-remote-dep':'1.0.0'}
  (d/'package.json').write_text(json.dumps(body));(d/'index.js').write_text('module.exports = '+str(value)+';')
  run(['npm','publish','--ignore-scripts','--access','public'],d,extra)
 publish('cratectl-remote-dep','1.0.0',41,origin,'origin-dep')
 publish('@crproxy/app','1.0.0',42,origin,'origin-v1');publish('@crproxy/app','2.0.0',43,origin,'origin-v2')
 publish('@crprivate/owned','1.0.0',99,origin,'origin-private')
 settings={'upstream':{'url':BASE+'/npm/up-npm/','networks':['127.0.0.1/32'],'credential_ref':'npm-fixture'},'cache':{'fresh_seconds':60,'negative_seconds':2,'stale_seconds':120,'allow_no_store':True,'require_checksum':True}}
 repository('npm-remote','npm',mode='proxy',access='restricted',settings=settings)
 req('/api/v1/repositories/npm-remote/grants',method='PUT',data={'actor':'reader','read':True,'write':False},key=uuid.uuid4().hex)
 proxy=npm_env('npm-remote','reader','proxy-cache');consumer=work/'consumer';consumer.mkdir();(consumer/'package.json').write_text('{"name":"remote-consumer","version":"1.0.0"}')
 run(['npm','install','--ignore-scripts','--no-audit','--no-fund','@crproxy/app@2.0.0'],consumer,proxy)
 check('stock npm installs scoped proxy package and dependency',run(['node','-e','if(require("@crproxy/app")!==43 || require("cratectl-remote-dep")!==41)process.exit(1)'],consumer).strip()=='')
 doc=json.loads(req('/npm/npm-remote/@crproxy%2fapp','reader')[1]);pinned=doc['versions']['2.0.0']['dist']['tarball'].replace(BASE,'')
 check('npm proxy rewrites source URL to immutable local binding',pinned.startswith('/npm/npm-remote/') and '/proxy/' in pinned)
 code,body,h=req(pinned,'reader');check('npm proxy pinned download supports ranges',req(pinned,'reader',headers={'Range':'bytes=0-7'})[1]==body[:8])
 check('npm proxy blocks foreign tenant coordinates',req('/npm/npm-remote/@crproxy/app','other')[0]==404)
 check('npm proxy is read only',req('/npm/npm-remote/@crproxy/app',method='PUT',data={})[0]==405)
 stop();start();shutil.rmtree(consumer/'node_modules');run(['npm','ci','--ignore-scripts','--no-audit','--no-fund','--cache',str(work/'restart-cache')],consumer,proxy)
 check('stock npm proxy lockfile survives restart',True)
 publish('@crproxy/app','3.0.0',44,origin,'origin-v3')
 req('/api/v1/repositories/npm-remote/cache',method='PUT',data={'path':'npm-catalog/@crproxy/app'},key=uuid.uuid4().hex)
 refreshed=json.loads(req('/npm/npm-remote/@crproxy/app','reader')[1]);check('npm proxy metadata refresh observes new native version',refreshed['dist-tags']['latest']=='3.0.0')
 check('old npm lockfile binding retains exact bytes after metadata refresh',req(pinned,'reader')[1]==body)
 repository('npm-local','npm',access='restricted');req('/api/v1/repositories/npm-local/grants',method='PUT',data={'actor':'reader','read':True,'write':False},key=uuid.uuid4().hex)
 local=npm_env('npm-local','admin','local-cache')
 publish('@crproxy/app','1.0.0',100,local,'local-v1');publish('@crproxy/app','4.0.0',101,local,'local-v4')
 repository('npm-combined','npm',mode='group',settings={'members':['npm-local','npm-remote'],'namespace_owners':{'@crprivate/':'npm-local'}})
 grouped=json.loads(req('/npm/npm-combined/@crproxy/app','reader')[1]);check('npm group unions versions with configured tag precedence',set(grouped['versions'])=={'1.0.0','2.0.0','3.0.0','4.0.0'} and grouped['dist-tags']['latest']=='4.0.0')
 group_env=npm_env('npm-combined','reader','group-cache');group_consumer=work/'group-consumer';group_consumer.mkdir();(group_consumer/'package.json').write_text('{"name":"group-consumer","version":"1.0.0"}')
 run(['npm','install','--ignore-scripts','--no-audit','--no-fund','@crproxy/app@latest'],group_consumer,group_env)
 check('stock npm consumes hosted version and proxied dependency through group',run(['node','-e','if(require("@crproxy/app")!==101 || require("cratectl-remote-dep")!==41)process.exit(1)'],group_consumer).strip()=='')
 check('npm namespace owner prevents public fallback',req('/npm/npm-combined/@crprivate/owned','reader')[0]==404)
 local_v1=next(a for a in json.loads(req('/api/v1/repositories/npm-local/artifacts')[1])['items'] if a['metadata'].get('version')=='1.0.0')
 req('/api/v1/repositories/npm-local/decisions',method='PUT',data={'path':local_v1['path'],'digest':local_v1['digest'],'decision':'denied'},key=uuid.uuid4().hex)
 check('npm denied version collision cannot fall through to later source','1.0.0' not in json.loads(req('/npm/npm-combined/@crproxy/app','reader')[1])['versions'])
 group_link=grouped['versions']['4.0.0']['dist']['tarball'].replace(BASE,'')
 req('/api/v1/repositories/npm-local/grants',method='PUT',data={'actor':'reader','read':False,'write':False},key=uuid.uuid4().hex)
 check('npm group rechecks underlying grants for metadata and pinned downloads',req('/npm/npm-combined/@crproxy/app','reader')[0]==403 and req(group_link,'reader')[0]==403)
 req('/api/v1/repositories/npm-local/grants',method='PUT',data={'actor':'reader','read':True,'write':False},key=uuid.uuid4().hex)
 cached=next(a for a in json.loads(req('/api/v1/repositories/npm-remote/artifacts')[1])['items'] if a['metadata'].get('version')=='2.0.0')
 req('/api/v1/repositories/npm-remote/decisions',method='PUT',data={'path':cached['path'],'digest':cached['digest'],'decision':'denied'},key=uuid.uuid4().hex)
 check('npm proxy denial hides metadata and blocks locked bytes','2.0.0' not in json.loads(req('/npm/npm-remote/@crproxy/app','reader')[1])['versions'] and req(pinned,'reader')[0]==403)
 rejection=run(['npm','ci','--ignore-scripts','--no-audit','--no-fund','--cache',str(work/'denied-cache')],consumer,proxy,expect_failure=True)
 check('stock npm fresh-cache lockfile install cannot bypass denial','403' in rejection)
 repository('npm-reviewed','npm',review=True,mode='proxy',settings=settings)
 check('npm review-required proxy hides unfetched package versions',req('/npm/npm-reviewed/@crproxy/app','reader')[0]==404)
 check('npm conventional tarball route performs quarantined intake',req('/npm/npm-reviewed/@crproxy/app/-/@crproxy/app-2.0.0.tgz','reader')[0]==403)
 intake=next(a for a in json.loads(req('/api/v1/repositories/npm-reviewed/artifacts')[1])['items'] if a['metadata'].get('version')=='2.0.0')
 req('/api/v1/repositories/npm-reviewed/decisions',method='PUT',data={'path':intake['path'],'digest':intake['digest'],'decision':'allowed'},key=uuid.uuid4().hex)
 check('npm reviewed bytes become visible after explicit approval',set(json.loads(req('/npm/npm-reviewed/@crproxy/app','reader')[1])['versions'])=={'2.0.0'})
 repository('npm-meta','generic','other',access='restricted');repository('npm-files','generic','other',access='restricted')
 for source,actor in [('npm-meta','npm-meta-origin'),('npm-files','npm-files-origin')]:
  req('/api/v1/repositories/'+source+'/grants','other','PUT',{'actor':actor,'read':True,'write':False},uuid.uuid4().hex)
 def cdn_fixture(name,bad_integrity=False,forged_graph=False):
  stream=io.BytesIO();manifest={'name':name,'version':'1.0.0','main':'index.js','bin':'./index.js'}
  with tarfile.open(fileobj=stream,mode='w:gz') as archive:
   for path,data in [('package/package.json',json.dumps(manifest).encode()),('package/index.js',b'module.exports = 88;')]:
    info=tarfile.TarInfo(path);info.size=len(data);archive.addfile(info,io.BytesIO(data))
  payload=stream.getvalue();req('/r/npm-files/'+name+'.tgz','other','PUT',payload)
  integrity='sha512-'+base64.b64encode(hashlib.sha512(b'wrong benign bytes' if bad_integrity else payload).digest()).decode()
  published={**manifest,'bin':{name:'index.js'},'dist':{'tarball':BASE+'/r/npm-files/'+name+'.tgz','integrity':integrity}}
  if forged_graph:published['dependencies']={'forged-dependency':'1.0.0'}
  document={'name':name,'versions':{'1.0.0':published},'dist-tags':{'latest':'1.0.0'}}
  req('/r/npm-meta/'+name,'other','PUT',document)
 for name,bad,forged in [('cratectl-cdn-app',False,False),('cratectl-cdn-bad',True,False),('cratectl-cdn-forged',False,True)]:cdn_fixture(name,bad,forged)
 cdn_settings={'upstream':{'url':BASE+'/r/npm-meta/','networks':['127.0.0.1/32'],'credential_ref':'npm-meta'},'cache':settings['cache']}
 repository('npm-cdn-blocked','npm',mode='proxy',settings=cdn_settings)
 check('npm metadata cannot authorize an undeclared download origin',req('/npm/npm-cdn-blocked/cratectl-cdn-app','reader')[0]==502)
 cdn_settings['download_sources']=[{'url':BASE+'/r/npm-files/','networks':['127.0.0.1/32'],'credential_ref':'npm-files'}]
 repository('npm-cdn','npm',mode='proxy',settings=cdn_settings)
 cdn_env=npm_env('npm-cdn','reader','cdn-cache');cdn_consumer=work/'cdn-consumer';cdn_consumer.mkdir();(cdn_consumer/'package.json').write_text('{"name":"cdn-consumer","version":"1.0.0"}')
 run(['npm','install','--ignore-scripts','--no-audit','--no-fund','cratectl-cdn-app'],cdn_consumer,cdn_env)
 check('stock npm installs from separately approved and credentialed download origin',run(['node','-e','if(require("cratectl-cdn-app")!==88)process.exit(1)'],cdn_consumer).strip()=='')
 cached_consumer=work/'cached-cdn-consumer';cached_consumer.mkdir();(cached_consumer/'package.json').write_text('{"name":"cached-cdn-consumer","version":"1.0.0"}')
 run(['npm','install','--ignore-scripts','--no-audit','--no-fund','cratectl-cdn-app'],cached_consumer,npm_env('npm-cdn','reader','cached-cdn-cache'))
 check('stock npm cached metadata preserves normalized executable binding',(cached_consumer/'node_modules/.bin/cratectl-cdn-app').is_symlink())
 for name,failure in [('cratectl-cdn-bad','upstream_integrity_failure'),('cratectl-cdn-forged','upstream_package_metadata_mismatch')]:
  doc=json.loads(req('/npm/npm-cdn/'+name,'reader')[1]);link=doc['versions']['1.0.0']['dist']['tarball'].replace(BASE,'')
  check('npm rejects '+failure,req(link,'reader')[0]==502)
  check('npm rejected bytes create no tarball reference',not any(a['metadata'].get('name')==name and a['media_type']!='application/vnd.cratectl.npm-catalog+json' for a in json.loads(req('/api/v1/repositories/npm-cdn/artifacts')[1])['items']))
  check('npm known-invalid source is not advertised for fallback',req('/npm/npm-cdn/'+name,'reader')[0]==404)

def wheel(name,dependency=None,version='1.0.0',addend=1,requires_python='>=3.10'):
 d=PRIVATE/'wheels';d.mkdir(exist_ok=True);filename=d/(name+'-'+version+'-py3-none-any.whl');dist=name+'-'+version+'.dist-info'
 metadata=f'Metadata-Version: 2.4\nName: {name.replace("_","-")}\nVersion: {version}\nSummary: cratectl native conformance package\nRequires-Python: {requires_python}\n'
 if dependency:metadata+=f'Requires-Dist: {dependency}==1.0.0\n'
 files={name+'/__init__.py':('value = 41\n' if not dependency else f'from {dependency.replace("-","_")} import value as dep\nvalue = dep + {addend}\n').encode(),dist+'/METADATA':(metadata+'\n').encode(),dist+'/WHEEL':b'Wheel-Version: 1.0\nGenerator: cratectl-conformance\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
 records=io.StringIO();writer=csv.writer(records,lineterminator='\n')
 for p,b in files.items():writer.writerow([p,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(b).digest()).decode().rstrip('='),len(b)])
 writer.writerow([dist+'/RECORD','','']);files[dist+'/RECORD']=records.getvalue().encode()
 with zipfile.ZipFile(filename,'w',zipfile.ZIP_DEFLATED) as archive:
  for p,b in files.items():archive.writestr(p,b)
 return filename

def pypi():
 repository('py','pypi');dep=wheel('cratectl_proof_dep');app=wheel('cratectl_proof_app','cratectl-proof-dep')
 python=ROOT/'.cache/clients/bin/python'
 run([python,'-m','twine','upload','--non-interactive','--repository-url',BASE+'/pypi/py/',dep,app],extra={'TWINE_USERNAME':'token','TWINE_PASSWORD':tokens['admin'],'TWINE_DISABLE_PROGRESS_BAR':'1'})
 netrc=PRIVATE/'netrc';netrc.write_text('machine 127.0.0.1 login token password '+tokens['admin']+'\n');netrc.chmod(0o600)
 extra={'NETRC':str(netrc),'PIP_CONFIG_FILE':os.devnull,'PIP_KEYRING_PROVIDER':'disabled','PIP_DISABLE_PIP_VERSION_CHECK':'1','PIP_EXTRA_INDEX_URL':'','PIP_NO_INPUT':'1'}
 run([python,'-m','pip','install','--no-cache-dir','--index-url',BASE+'/pypi/py/simple/','--target',PRIVATE/'python-install','cratectl-proof-app==1.0.0'],extra=extra)
 check('stock pip installs package and dependency from twine upload',run([python,'-c',f'import sys;sys.path.insert(0,{str(PRIVATE/"python-install")!r});from cratectl_proof_app import value;assert value==42']).strip()=='')
 check('Python normalized name resolution',b'cratectl_proof_app' in req('/pypi/py/simple/Cratectl_Proof.App/')[1])
 probe=wheel('cratectl_binding_probe');boundary='cratectl-'+uuid.uuid4().hex
 pieces=[]
 for field,value in [('name','cratectl-wrong-identity'),('version','1.0.0')]:
  pieces.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"\r\n\r\n{value}\r\n'.encode())
 pieces.append(f'--{boundary}\r\nContent-Disposition: form-data; name="content"; filename="{probe.name}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()+probe.read_bytes()+f'\r\n--{boundary}--\r\n'.encode())
 check('Python publication metadata must match immutable archive identity',req('/pypi/py/',method='POST',data=b''.join(pieces),headers={'Content-Type':'multipart/form-data; boundary='+boundary})[0]==400)
 req('/api/v1/repositories/py/policy',method='PUT',data={'require_review':True},key=uuid.uuid4().hex)
 check('Python quarantine hides index contents',b'.whl#' not in req('/pypi/py/simple/cratectl-proof-app/')[1])
 check('Python quarantine blocks direct files',req('/pypi/py/files/'+app.name)[0]==403)

def pypiproxy():
 repository('up-python','pypi','other')
 python=ROOT/'.cache/clients/bin/python';work=PRIVATE/'python-proxy';work.mkdir()
 dep=wheel('cratectl_py_proxy_dep');v1=wheel('cratectl_py_proxy_app','cratectl-py-proxy-dep','1.0.0',1);v2=wheel('cratectl_py_proxy_app','cratectl-py-proxy-dep','2.0.0',2);v3=wheel('cratectl_py_proxy_app','cratectl-py-proxy-dep','3.0.0',3,'>=99')
 owned=wheel('cratectl_owned_private')
 run([python,'-m','twine','upload','--non-interactive','--repository-url',BASE+'/pypi/up-python/',dep,v1,v2,v3,owned],extra={'TWINE_USERNAME':'token','TWINE_PASSWORD':tokens['other'],'TWINE_DISABLE_PROGRESS_BAR':'1'})
 settings={'upstream':{'url':BASE+'/pypi/up-python/simple/','networks':['127.0.0.1/32'],'credential_ref':'python-up'},'download_sources':[{'url':BASE+'/pypi/up-python/files/','networks':['127.0.0.1/32'],'credential_ref':'python-up'}],'cache':{'fresh_seconds':60,'negative_seconds':2,'stale_seconds':120,'allow_no_store':True,'require_checksum':True}}
 repository('python-proxy','pypi',mode='proxy',access='restricted',settings=settings)
 req('/api/v1/repositories/python-proxy/grants',method='PUT',data={'actor':'reader','read':True,'write':False},key=uuid.uuid4().hex)
 netrc=work/'netrc';netrc.write_text('machine 127.0.0.1 login token password '+tokens['reader']+'\n');netrc.chmod(0o600)
 extra={'NETRC':str(netrc),'PIP_CONFIG_FILE':os.devnull,'PIP_KEYRING_PROVIDER':'disabled','PIP_DISABLE_PIP_VERSION_CHECK':'1','PIP_EXTRA_INDEX_URL':'','PIP_NO_INPUT':'1'}
 def install(repository_name,target,spec='cratectl-py-proxy-app',expect_failure=False):
  return run([python,'-m','pip','install','--no-cache-dir','--only-binary=:all:','--index-url',BASE+'/pypi/'+repository_name+'/simple/','--target',target,spec],extra=extra,expect_failure=expect_failure)
 def verify(target,value):
  run([python,'-c',f'import sys;sys.path.insert(0,{str(target)!r});import cratectl_py_proxy_app as app;import cratectl_py_proxy_dep as dep;assert app.value=={value} and dep.value==41'])
 install('python-proxy',work/'installed');verify(work/'installed',43)
 check('stock pip proxy installs dependency and skips incompatible Python release',True)
 code,body,h=req('/pypi/python-proxy/simple/Cratectl_Py.Proxy.App/','reader',headers={'Accept':'application/vnd.pypi.simple.v1+json'});document=json.loads(body)
 check('PyPI normalized JSON index exposes all governed platform files',code==200 and len(document['files'])==3 and h['Content-Type'].startswith('application/vnd.pypi.simple.v1+json'))
 selected=next(f for f in document['files'] if f['filename']==v2.name);link=selected['url'].replace(BASE,'')
 check('PyPI proxy rewrites pinned filename-preserving URLs',link.startswith('/pypi/python-proxy/files/') and link.endswith(v2.name))
 code,metadata,_=req(link+'.metadata','reader');check('PEP 658 metadata is exact archive-derived bytes',code==200 and selected['core-metadata']['sha256']==hashlib.sha256(metadata).hexdigest() and b'Requires-Dist: cratectl-py-proxy-dep==1.0.0' in metadata)
 check('PyPI wheel range and conditional reads remain native',req(link,'reader',headers={'Range':'bytes=0-7'})[0]==206 and req(link,'reader',headers={'If-None-Match':req(link,'reader')[2]['Etag']})[0]==304)
 requirements=work/'requirements.txt';dep_doc=json.loads(req('/pypi/python-proxy/simple/cratectl-py-proxy-dep/','reader',headers={'Accept':'application/vnd.pypi.simple.v1+json'})[1]);dep_hash=dep_doc['files'][0]['hashes']['sha256']
 requirements.write_text('cratectl-py-proxy-app==2.0.0 --hash=sha256:'+selected['hashes']['sha256']+'\ncratectl-py-proxy-dep==1.0.0 --hash=sha256:'+dep_hash+'\n')
 stop();start();run([python,'-m','pip','download','--no-cache-dir','--only-binary=:all:','--require-hashes','--index-url',BASE+'/pypi/python-proxy/simple/','--dest',work/'after-restart','-r',requirements],extra=extra)
 check('stock pip hash-locked download survives restart',(work/'after-restart'/v2.name).read_bytes()==v2.read_bytes())
 req('/api/v1/repositories/up-python/yanks','other','PUT',{'filename':v2.name,'yanked':True,'reason':'owned fixture yank'},uuid.uuid4().hex)
 req('/api/v1/repositories/python-proxy/cache',method='PUT',data={'path':'pypi-catalog/cratectl-py-proxy-app'},key=uuid.uuid4().hex)
 refreshed=json.loads(req('/pypi/python-proxy/simple/cratectl-py-proxy-app/','reader',headers={'Accept':'application/vnd.pypi.simple.v1+json'})[1]);check('upstream yanking survives catalog refresh',next(f for f in refreshed['files'] if f['filename']==v2.name)['yanked']=='owned fixture yank')
 install('python-proxy',work/'after-yank');verify(work/'after-yank',42);check('stock pip excludes yanked release during normal resolution',True)
 install('python-proxy',work/'exact-yank','cratectl-py-proxy-app==2.0.0');verify(work/'exact-yank',43);check('stock pip exact pin can consume a yanked release',True)
 html_settings={**settings,'python_index_format':'html'};repository('python-html','pypi',mode='proxy',settings=html_settings)
 install('python-html',work/'html');verify(work/'html',42);check('stock pip consumes governed upstream HTML index',True)
 repository('python-local','pypi',access='restricted');req('/api/v1/repositories/python-local/grants',method='PUT',data={'actor':'reader','read':True,'write':False},key=uuid.uuid4().hex)
 # Distinct work paths preserve both same-filename collision payloads.
 original_v1=v1.read_bytes();local_v1=wheel('cratectl_py_proxy_app','cratectl-py-proxy-dep','1.0.0',10);local_v4=wheel('cratectl_py_proxy_app','cratectl-py-proxy-dep','4.0.0',4)
 run([python,'-m','twine','upload','--non-interactive','--repository-url',BASE+'/pypi/python-local/',local_v1,local_v4],extra={'TWINE_USERNAME':'token','TWINE_PASSWORD':tokens['admin'],'TWINE_DISABLE_PROGRESS_BAR':'1'})
 repository('python-group','pypi',mode='group',settings={'members':['python-local','python-proxy'],'namespace_owners':{'cratectl-owned-private/':'python-local'}})
 install('python-group',work/'group');verify(work/'group',45);check('stock pip group consumes hosted package and proxied dependency',True)
 grouped=json.loads(req('/pypi/python-group/simple/cratectl-py-proxy-app/','reader',headers={'Accept':'application/vnd.pypi.simple.v1+json'})[1]);check('PyPI group unions filenames with first-source collision ownership',len(grouped['files'])==4 and '/python-local/hosted/' in next(f['url'] for f in grouped['files'] if f['filename']==v1.name))
 check('Python namespace owner prevents dependency-confusion fallback',req('/pypi/python-group/simple/cratectl-owned-private/','reader')[0]==404)
 local_ref=next(a for a in json.loads(req('/api/v1/repositories/python-local/artifacts')[1])['items'] if a['path']==v1.name)
 req('/api/v1/repositories/python-local/decisions',method='PUT',data={'path':v1.name,'digest':local_ref['digest'],'decision':'denied'},key=uuid.uuid4().hex)
 check('denied Python filename collision cannot fall through',v1.name not in [f['filename'] for f in json.loads(req('/pypi/python-group/simple/cratectl-py-proxy-app/','reader',headers={'Accept':'application/vnd.pypi.simple.v1+json'})[1])['files']])
 group_link=next(f['url'].replace(BASE,'') for f in grouped['files'] if f['filename']==local_v4.name)
 req('/api/v1/repositories/python-local/grants',method='PUT',data={'actor':'reader','read':False,'write':False},key=uuid.uuid4().hex)
 check('Python group checks source grants for index and metadata sidecars',req('/pypi/python-group/simple/cratectl-py-proxy-app/','reader')[0]==403 and req(group_link+'.metadata','reader')[0]==403)
 req('/api/v1/repositories/python-local/grants',method='PUT',data={'actor':'reader','read':True,'write':False},key=uuid.uuid4().hex)
 cached=next(a for a in json.loads(req('/api/v1/repositories/python-proxy/artifacts')[1])['items'] if a['metadata'].get('filename')==v2.name)
 req('/api/v1/repositories/python-proxy/decisions',method='PUT',data={'path':cached['path'],'digest':cached['digest'],'decision':'denied'},key=uuid.uuid4().hex)
 check('Python denial governs package, sidecar and metadata index',req(link,'reader')[0]==403 and req(link+'.metadata','reader')[0]==403 and v2.name not in [f['filename'] for f in json.loads(req('/pypi/python-proxy/simple/cratectl-py-proxy-app/','reader',headers={'Accept':'application/vnd.pypi.simple.v1+json'})[1])['files']])
 rejected=install('python-proxy',work/'denied','cratectl-py-proxy-app==2.0.0',expect_failure=True);check('stock pip cannot resolve denied exact version','No matching distribution' in rejected or 'Could not find a version' in rejected)
 repository('python-reviewed','pypi',review=True,mode='proxy',settings=settings)
 check('review-required Python proxy hides unfetched metadata',req('/pypi/python-reviewed/simple/cratectl-py-proxy-app/','reader')[0]==404)
 check('Python conventional download performs quarantined intake',req('/pypi/python-reviewed/files/'+v2.name,'reader')[0]==403)
 intake=next(a for a in json.loads(req('/api/v1/repositories/python-reviewed/artifacts')[1])['items'] if a['metadata'].get('filename')==v2.name)
 req('/api/v1/repositories/python-reviewed/decisions',method='PUT',data={'path':intake['path'],'digest':intake['digest'],'decision':'allowed'},key=uuid.uuid4().hex)
 check('approved Python digest becomes visible with governed sidecar',len(json.loads(req('/pypi/python-reviewed/simple/cratectl-py-proxy-app/','reader',headers={'Accept':'application/vnd.pypi.simple.v1+json'})[1])['files'])==1)
 # A benign PEP 517 backend executes only inside the explicitly owned pip
 # consumer. The registry reads PKG-INFO and never invokes this backend.
 source_name='cratectl_py_source_app';source_version='1.0.0';source_core=f'Metadata-Version: 2.4\nName: {source_name.replace("_","-")}\nVersion: {source_version}\nRequires-Python: >=3.10\nRequires-Dist: cratectl-py-proxy-dep==1.0.0\n\n'
 backend='''import base64,csv,hashlib,io,os,zipfile
NAME="cratectl_py_source_app"
VERSION="1.0.0"
CORE=CORE_VALUE
def build_wheel(wheel_directory,config_settings=None,metadata_directory=None):
 dist=NAME+"-"+VERSION+".dist-info"
 files={NAME+"/__init__.py":b"from cratectl_py_proxy_dep import value as dep\\nvalue = dep + 5\\n",dist+"/METADATA":CORE.encode(),dist+"/WHEEL":b"Wheel-Version: 1.0\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n"}
 records=io.StringIO();writer=csv.writer(records,lineterminator="\\n")
 for path,data in files.items():writer.writerow([path,"sha256="+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("="),len(data)])
 writer.writerow([dist+"/RECORD","",""]);files[dist+"/RECORD"]=records.getvalue().encode()
 filename=NAME+"-"+VERSION+"-py3-none-any.whl"
 with zipfile.ZipFile(os.path.join(wheel_directory,filename),"w",zipfile.ZIP_DEFLATED) as archive:
  for path,data in files.items():archive.writestr(path,data)
 return filename
'''.replace('CORE_VALUE',repr(source_core))
 source_file=work/(source_name+'-'+source_version+'.tar.gz');source_root=source_name+'-'+source_version
 with tarfile.open(source_file,'w:gz') as archive:
  for name,body in [('PKG-INFO',source_core),('pyproject.toml','[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["."]\n'),('backend.py',backend)]:
   data=body.encode();info=tarfile.TarInfo(source_root+'/'+name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
 run([python,'-m','twine','upload','--non-interactive','--repository-url',BASE+'/pypi/up-python/',source_file],extra={'TWINE_USERNAME':'token','TWINE_PASSWORD':tokens['other'],'TWINE_DISABLE_PROGRESS_BAR':'1'})
 run([python,'-m','pip','install','--no-cache-dir','--no-build-isolation','--index-url',BASE+'/pypi/python-proxy/simple/','--target',work/'source-consumer','cratectl-py-source-app'],extra=extra)
 run([python,'-c',f'import sys;sys.path.insert(0,{str(work/"source-consumer")!r});from cratectl_py_source_app import value;assert value==46'])
 check('stock pip builds governed source distribution only in owned consumer',True)

def oci():
 repository('containers','oci',review=True);work=PRIVATE/'oci';work.mkdir();oras=ROOT/'.cache/bin/oras';auth=work/'auth.json'
 invalid={'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','layers':[]}
 check('OCI image manifest requires a configuration descriptor',req('/v2/containers/invalid/manifests/missing-config',method='PUT',data=invalid,headers={'Content-Type':invalid['mediaType']})[0]==400)
 run([oras,'login','--plain-http','--registry-config',auth,'--username','token','--password-stdin','127.0.0.1:38443'],input_text=tokens['admin']+'\n')
 (work/'hello.txt').write_text('cratectl OCI exact bytes\n');(work/'dependency.txt').write_text('second layer dependency fixture\n')
 ref='127.0.0.1:38443/containers/proof:v1'
 run([oras,'push','--plain-http','--registry-config',auth,ref,'hello.txt:text/plain','dependency.txt:text/plain'],work)
 check('OCI intake remains quarantined after native publication',req('/v2/containers/proof/manifests/v1')[0]==403)
 intake=json.loads(req('/api/v1/repositories/containers/artifacts')[1])['items']
 for artifact in intake:
  check('manual OCI graph member approval',req('/api/v1/repositories/containers/decisions',method='PUT',data={'path':artifact['path'],'digest':artifact['digest'],'decision':'allowed'},key=uuid.uuid4().hex)[0]==200)
 pull=work/'pull';pull.mkdir();run([oras,'pull','--plain-http','--registry-config',auth,ref],pull)
 check('stock ORAS pulls exact multi-layer artifact',all((pull/p).read_bytes()==(work/p).read_bytes() for p in ['hello.txt','dependency.txt']))
 stop();start();pull2=work/'after-restart';pull2.mkdir();run([oras,'pull','--plain-http','--registry-config',auth,ref],pull2)
 check('stock ORAS pull survives restart',all((pull2/p).read_bytes()==(work/p).read_bytes() for p in ['hello.txt','dependency.txt']))
 root_code,root_bytes,root_headers=req('/v2/containers/proof/manifests/v1');root_manifest=json.loads(root_bytes);root_digest=root_headers['Docker-Content-Digest']
 check('OCI rejects unacceptable stored manifest representation',req('/v2/containers/proof/manifests/v1',headers={'Accept':'application/vnd.docker.distribution.manifest.v2+json'})[0]==406)
 edge_image='nested/manifests-subdir/blobs/uploads/name';edge_ref='127.0.0.1:38443/containers/'+edge_image+':v1'
 run([oras,'push','--plain-http','--registry-config',auth,edge_ref,'hello.txt:text/plain','dependency.txt:text/plain'],work)
 for artifact in json.loads(req('/api/v1/repositories/containers/artifacts')[1])['items']:
  if artifact['path'].startswith(edge_image+'/'):
   req('/api/v1/repositories/containers/decisions',method='PUT',data={'path':artifact['path'],'digest':artifact['digest'],'decision':'allowed'},key=uuid.uuid4().hex)
 edge_pull=work/'nested-consumer';edge_pull.mkdir();run([oras,'pull','--plain-http','--registry-config',auth,edge_ref],edge_pull)
 check('stock ORAS handles image names containing protocol words',(edge_pull/'hello.txt').read_bytes()==(work/'hello.txt').read_bytes())
 duplicate=root_bytes[:-1]+b',"schemaVersion":2}'
 check('OCI ambiguous duplicate manifest members are rejected',req('/v2/containers/proof/manifests/duplicate',method='PUT',data=duplicate,headers={'Content-Type':root_manifest['mediaType']})[0]==400)
 (work/'sbom.json').write_text('{"spdxVersion":"SPDX-2.3","name":"benign attachment fixture"}\n')
 artifact_type='application/vnd.cratectl.proof.sbom.v1+json'
 attach=json.loads(run([oras,'attach','--plain-http','--registry-config',auth,'--distribution-spec','v1.1-referrers-api','--artifact-type',artifact_type,'--annotation','org.opencontainers.image.description=Owned proof attachment','--format','json',ref,'sbom.json:application/spdx+json'],work))
 attached_digest=attach['digest']
 check('OCI referrer discovery hides quarantined attachment',json.loads(req('/v2/containers/proof/referrers/'+root_digest)[1])['manifests']==[])
 attachment_artifacts=json.loads(req('/api/v1/repositories/containers/artifacts')[1])['items']
 for artifact in attachment_artifacts:
  if artifact['decision']!='allowed':
   code,_,_=req('/api/v1/repositories/containers/decisions',method='PUT',data={'path':artifact['path'],'digest':artifact['digest'],'decision':'allowed'},key=uuid.uuid4().hex)
   if code!=200:raise AssertionError('attachment graph approval failed')
 discovered=json.loads(run([oras,'discover','--plain-http','--registry-config',auth,'--distribution-spec','v1.1-referrers-api','--format','json','--depth','1',ref],work))
 check('stock ORAS discovers governed attachment',any(item['digest']==attached_digest and item['artifactType']==artifact_type for item in discovered['referrers']))
 code,body,headers=req('/v2/containers/proof/referrers/'+root_digest+'?'+urllib.parse.urlencode({'artifactType':artifact_type}))
 descriptor=next(item for item in json.loads(body)['manifests'] if item['digest']==attached_digest)
 check('OCI referrer filtering preserves type and annotations',code==200 and headers.get('Oci-Filters-Applied')=='artifactType' and descriptor['annotations']['org.opencontainers.image.description']=='Owned proof attachment')
 check('OCI referrer index supports conditional reads',req('/v2/containers/proof/referrers/'+root_digest+'?'+urllib.parse.urlencode({'artifactType':artifact_type}),headers={'If-None-Match':headers['Etag']})[0]==304)
 attachment_pull=work/'attachment';attachment_pull.mkdir();run([oras,'pull','--plain-http','--registry-config',auth,'127.0.0.1:38443/containers/proof@'+attached_digest],attachment_pull)
 check('stock ORAS pulls exact attachment bytes',(attachment_pull/'sbom.json').read_bytes()==(work/'sbom.json').read_bytes())
 check('OCI attachment remains tenant scoped',req('/v2/containers/proof/referrers/'+root_digest,'other')[0]==404)
 missing_subject='sha256:'+'a'*64
 weak={**root_manifest,'artifactType':artifact_type,'subject':{'mediaType':root_manifest['mediaType'],'digest':missing_subject,'size':123}}
 code,_,headers=req('/v2/containers/proof/manifests/weak-subject',method='PUT',data=weak,headers={'Content-Type':root_manifest['mediaType']})
 check('OCI weak subject accepts out-of-order attachment',code==201 and headers.get('Oci-Subject')==missing_subject)
 bad_index={'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','manifests':[{'mediaType':'application/vnd.docker.distribution.manifest.v2+json','digest':root_digest,'size':len(root_bytes)}]}
 check('OCI index descriptor media type must match durable child',req('/v2/containers/proof/manifests/wrong-type',method='PUT',data=bad_index,headers={'Content-Type':bad_index['mediaType']})[0]==409)
 run([oras,'manifest','index','create','--plain-http','--registry-config',auth,'127.0.0.1:38443/containers/proof:platforms','v1'],work)
 check('OCI index intake is quarantined',req('/v2/containers/proof/manifests/platforms')[0]==403)
 index_artifact=next(a for a in json.loads(req('/api/v1/repositories/containers/artifacts')[1])['items'] if a['media_type']=='application/vnd.oci.image.index.v1+json')
 req('/api/v1/repositories/containers/decisions',method='PUT',data={'path':index_artifact['path'],'digest':index_artifact['digest'],'decision':'allowed'},key=uuid.uuid4().hex)
 check('OCI approved index resolves exact child',json.loads(req('/v2/containers/proof/manifests/platforms')[1])['manifests'][0]['digest']==root_digest)
 code,page,headers=req('/v2/containers/proof/tags/list?n=1')
 check('OCI native tag page returns its next Link',code==200 and json.loads(page)['tags']==['platforms'] and bool(headers.get('Link')))
 next_page=headers['Link'].split('<',1)[1].split('>',1)[0]
 check('OCI native tag marker is exclusive',json.loads(req(next_page)[1])['tags']==['v1'])
 check('OCI tag page supports conditional reads',req('/v2/containers/proof/tags/list?n=1',headers={'If-None-Match':headers['Etag']})[0]==304)
 check('OCI tag page supports HEAD',req('/v2/containers/proof/tags/list?n=1',method='HEAD')[0]==200)
 check('OCI zero tag page has no next Link',json.loads(req('/v2/containers/proof/tags/list?n=0')[1])['tags']==[] and 'Link'not in req('/v2/containers/proof/tags/list?n=0')[2])
 check('OCI duplicate page parameters are rejected',req('/v2/containers/proof/tags/list?n=1&n=2')[0]==400)
 check('OCI zero referrer page is empty',json.loads(req('/v2/containers/proof/referrers/'+root_digest+'?n=0')[1])['manifests']==[])
 stop();start()
 check('OCI referrers survive restart',any(item['digest']==attached_digest for item in json.loads(req('/v2/containers/proof/referrers/'+root_digest)[1])['manifests']))
 # Use the documented protocol to interrupt a chunked upload and resume it.
 code,_,h=req('/v2/containers/resume/blobs/uploads/',method='POST',data=b'')
 check('OCI upload lease is durable before bytes',code==202)
 upload=h['Location'].replace(BASE,'');check('OCI first chunk accepted',req(upload,method='PATCH',data=b'first',headers={'Content-Range':'0-4'})[0]==202)
 stop();start();check('OCI upload offset survives restart',req(upload)[2].get('Range')=='0-4')
 check('OCI stale offset rejected',req(upload,method='PATCH',data=b'bad',headers={'Content-Range':'0-2'})[0]==409)
 digest=hashlib.sha256(b'firstsecond').hexdigest()
 check('OCI resumed upload completes',req(upload+'?digest=sha256:'+digest,method='PUT',data=b'second',headers={'Content-Range':'5-10'})[0]==201)
 check('OCI resumed bytes are quarantined',req('/v2/containers/resume/blobs/sha256:'+digest)[0]==403)
 req('/api/v1/repositories/containers/decisions',method='PUT',data={'path':'resume/blobs/sha256:'+digest,'digest':digest,'decision':'allowed'},key=uuid.uuid4().hex)
 check('OCI resumed bytes are exact',req('/v2/containers/resume/blobs/sha256:'+digest)[1]==b'firstsecond')
 check('OCI upload cannot cross tenant',req(upload,'other')[0]==404)
 artifacts=json.loads(req('/api/v1/repositories/containers/artifacts')[1])['items'];manifest=next(a for a in artifacts if a['digest']==root_digest.removeprefix('sha256:'))
 child=next(a for a in artifacts if a['path']=='proof/blobs/'+root_manifest['layers'][0]['digest'])
 req('/api/v1/repositories/containers/decisions',method='PUT',data={'path':child['path'],'digest':child['digest'],'decision':'denied'},key=uuid.uuid4().hex)
 check('OCI denied layer blocks an otherwise approved manifest',req('/v2/containers/proof/manifests/v1')[0]==403)
 check('OCI denied subject graph blocks attachment reads and discovery',req('/v2/containers/proof/manifests/'+attached_digest)[0]==403 and req('/v2/containers/proof/referrers/'+root_digest)[0]==403)
 check('OCI denied layer hides its tag from metadata',json.loads(req('/v2/containers/proof/tags/list')[1])['tags']==[])
 check('OCI denied layer hides manifest from reader inventory',not any(a['path']==manifest['path'] for a in json.loads(req('/api/v1/repositories/containers/artifacts','reader')[1])['items']))
 req('/api/v1/repositories/containers/decisions',method='PUT',data={'path':child['path'],'digest':child['digest'],'decision':'allowed'},key=uuid.uuid4().hex)
 req('/api/v1/repositories/containers/decisions',method='PUT',data={'path':manifest['path'],'digest':manifest['digest'],'decision':'denied'},key=uuid.uuid4().hex)
 check('OCI denied digest blocks tag resolution',req('/v2/containers/proof/manifests/v1')[0]==403)
 check('OCI denied digest disappears from tag index',json.loads(req('/v2/containers/proof/tags/list')[1])['tags']==[])


def ociproxy():
 repository('up-oci','oci','other');work=PRIVATE/'oci-proxy';work.mkdir();oras=ROOT/'.cache/bin/oras';origin_auth=work/'origin-auth.json';auth=work/'auth.json'
 run([oras,'login','--plain-http','--registry-config',origin_auth,'--username','token','--password-stdin','127.0.0.1:38443'],input_text=tokens['other']+'\n')
 run([oras,'login','--plain-http','--registry-config',auth,'--username','token','--password-stdin','127.0.0.1:38443'],input_text=tokens['admin']+'\n')
 (work/'payload.txt').write_text('owned upstream layer one\n');(work/'dependency.txt').write_text('owned upstream layer two\n')
 origin='127.0.0.1:38443/up-oci/proof'
 run([oras,'push','--plain-http','--registry-config',origin_auth,origin+':v1','payload.txt:text/plain','dependency.txt:text/plain'],work)
 (work/'sbom.json').write_text('{"name":"owned graph attachment"}\n')
 attached=json.loads(run([oras,'attach','--plain-http','--registry-config',origin_auth,'--distribution-spec','v1.1-referrers-api','--artifact-type','application/vnd.cratectl.proof','--format','json',origin+':v1','sbom.json:application/json'],work))
 root_code,root_bytes,root_headers=req('/v2/up-oci/proof/manifests/v1','other');root_digest=root_headers['Docker-Content-Digest'];root_manifest=json.loads(root_bytes)
 settings={'upstream':{'url':BASE+'/v2/up-oci/','networks':['127.0.0.1/32'],'credential_ref':'oci-up'},'cache':{'fresh_seconds':60,'negative_seconds':30,'stale_seconds':120,'allow_no_store':True}}
 repository('oci-proxy','oci',mode='proxy',settings=settings,access='restricted')
 target='127.0.0.1:38443/oci-proxy/proof:v1';consumer=work/'consumer';consumer.mkdir()
 run([oras,'pull','--plain-http','--registry-config',auth,target],consumer)
 check('stock ORAS proxy pulls exact complete multi-layer graph',all((consumer/p).read_bytes()==(work/p).read_bytes() for p in ['payload.txt','dependency.txt']))
 code,body,headers=req('/v2/oci-proxy/proof/manifests/v1')
 check('OCI proxy preserves manifest digest and bytes',code==200 and body==root_bytes and headers.get('Docker-Content-Digest')==root_digest)
 layer=root_manifest['layers'][0]['digest'];code,body,headers=req('/v2/oci-proxy/proof/blobs/'+layer,headers={'Range':'bytes=1-5'})
 check('OCI cached graph blobs support exact ranges',code==206 and body==(work/'payload.txt').read_bytes()[1:6])
 member_path='proof/blobs/'+layer
 check('OCI implicit graph members have independently inspectable cache bindings',req('/api/v1/repositories/oci-proxy/cache?'+urllib.parse.urlencode({'path':member_path}))[0]==200)
 member_cache_url='/api/v1/repositories/oci-proxy/cache?'+urllib.parse.urlencode({'path':member_path})
 member_before=json.loads(req(member_cache_url)[1])
 check('OCI member invalidation is versioned',req('/api/v1/repositories/oci-proxy/cache',method='PUT',data={'path':member_path},key=uuid.uuid4().hex)[0]==200)
 code,_,headers=req('/v2/oci-proxy/'+member_path)
 member_after=json.loads(req(member_cache_url)[1])
 check('OCI invalidated member revalidates its exact bytes',code==200 and headers.get('X-Cratectl-Cache')=='revalidated' and member_after['generation']>member_before['generation'])
 req('/api/v1/repositories/oci-proxy/cache',method='PUT',data={'path':member_path},key=uuid.uuid4().hex)
 invalidated=json.loads(req(member_cache_url)[1])
 code,body,headers=req('/v2/oci-proxy/proof/manifests/v1')
 refreshed=json.loads(req(member_cache_url)[1])
 check('OCI fresh tag revalidates an expired graph member',code==200 and body==root_bytes and headers.get('X-Cratectl-Cache')=='revalidated' and refreshed['generation']>invalidated['generation'] and refreshed['state']=='ready')
 check('OCI proxy rejects publication',req('/v2/oci-proxy/proof/blobs/uploads/',method='POST',data=b'')[0]==405)
 discovered=json.loads(run([oras,'discover','--plain-http','--registry-config',auth,'--distribution-spec','v1.1-referrers-api','--format','json','--depth','1',target],work))
 check('stock ORAS discovers proxied governed referrers',any(x['digest']==attached['digest'] for x in discovered['referrers']))
 check('OCI proxy tag catalog resolves exact bindings',json.loads(req('/v2/oci-proxy/proof/tags/list')[1])['tags']==['v1'])
 req('/api/v1/repositories/oci-proxy/cache',method='PUT',data={'path':member_path},key=uuid.uuid4().hex)
 check('OCI fresh tag catalog renews an invalidated graph member',json.loads(req('/v2/oci-proxy/proof/tags/list')[1])['tags']==['v1'] and json.loads(req(member_cache_url)[1])['state']=='ready')
 zero_settings={**settings,'cache':{**settings['cache'],'fresh_seconds':0,'stale_seconds':0}}
 repository('oci-zero','oci',mode='proxy',settings=zero_settings)
 check('OCI zero-freshness positive validation admits its current request',req('/v2/oci-zero/proof/manifests/v1')[0]==200)
 zero_before=json.loads(req('/api/v1/repositories/oci-zero/cache?path=proof/manifests/v1')[1])
 check('OCI zero-freshness next request revalidates again',req('/v2/oci-zero/proof/manifests/v1')[0]==200 and json.loads(req('/api/v1/repositories/oci-zero/cache?path=proof/manifests/v1')[1])['generation']>zero_before['generation'])
 check('OCI zero-freshness discovery keeps current graph validation',json.loads(req('/v2/oci-zero/proof/tags/list')[1])['tags']==['v1'])
 check('OCI zero-freshness referrers retain current subject and attachment validation',any(d['digest']==attached['digest'] for d in json.loads(req('/v2/oci-zero/proof/referrers/'+root_digest)[1])['manifests']))
 stop();start();after=work/'after-restart';after.mkdir();run([oras,'pull','--plain-http','--registry-config',auth,target],after)
 check('stock ORAS proxy digest pins survive restart',(after/'payload.txt').read_bytes()==(work/'payload.txt').read_bytes())
 (work/'payload.txt').write_text('owned upstream release two\n')
 run([oras,'push','--plain-http','--registry-config',origin_auth,origin+':v2','payload.txt:text/plain','dependency.txt:text/plain'],work)
 check('OCI proxy refresh observes new native tag',json.loads(req('/v2/oci-proxy/proof/tags/list',headers={'Cache-Control':'no-cache'})[1])['tags']==['v1','v2'])
 check('OCI retained digest pins preserve original manifest after refresh',req('/v2/oci-proxy/proof/manifests/'+root_digest)[1]==root_bytes)
 concurrent_origin='127.0.0.1:38443/up-oci/concurrent:v1'
 run([oras,'push','--plain-http','--registry-config',origin_auth,concurrent_origin,'payload.txt:text/plain'],work)
 with ThreadPoolExecutor(max_workers=8) as pool:responses=list(pool.map(lambda _:req('/v2/oci-proxy/concurrent/manifests/v1'),range(8)))
 state=json.loads(req('/api/v1/repositories/oci-proxy/cache?path=concurrent/manifests/v1')[1])
 coalesced=all(x[0]==200 for x in responses) and state['generation']==1 and state['state']=='ready'
 if not coalesced:raise AssertionError('OCI coalescing: codes='+str([x[0] for x in responses])+', generation='+str(state['generation'])+', state='+state['state'])
 check('OCI concurrent graph misses coalesce under one database generation',coalesced)
 repository('oci-local','oci');local='127.0.0.1:38443/oci-local/proof'
 (work/'local.txt').write_text('owned hosted group version\n')
 run([oras,'push','--plain-http','--registry-config',auth,local+':local','local.txt:text/plain'],work)
 run([oras,'tag','--plain-http','--registry-config',auth,local+':local','v1'],work)
 repository('oci-group','oci',mode='group',settings={'members':['oci-local','oci-proxy'],'namespace_owners':{'private/':'oci-local'}})
 group='127.0.0.1:38443/oci-group/proof';group_consumer=work/'group';group_consumer.mkdir();run([oras,'pull','--plain-http','--registry-config',auth,group+':local'],group_consumer)
 check('stock ORAS group pulls first hosted source',(group_consumer/'local.txt').read_bytes()==(work/'local.txt').read_bytes())
 check('OCI group unions native tags with first-source precedence',json.loads(req('/v2/oci-group/proof/tags/list')[1])['tags']==['local','v1','v2'])
 local_digest=req('/v2/oci-local/proof/manifests/v1')[2]['Docker-Content-Digest']
 check('OCI group tag collision retains first source',req('/v2/oci-group/proof/manifests/v1')[2]['Docker-Content-Digest']==local_digest)
 group_fallback=work/'group-fallback';group_fallback.mkdir();run([oras,'pull','--plain-http','--registry-config',auth,group+':v2'],group_fallback)
 check('stock ORAS group pulls an authorized proxy fallback',(group_fallback/'payload.txt').read_bytes()==(work/'payload.txt').read_bytes())
 req('/api/v1/repositories/oci-proxy/grants',method='PUT',data={'actor':'reader','read':True,'write':False},key=uuid.uuid4().hex)
 check('OCI group reader requires underlying source grant',req('/v2/oci-group/proof/manifests/v1','reader')[0]==200)
 req('/api/v1/repositories/oci-proxy/grants',method='PUT',data={'actor':'reader','read':False,'write':False},key=uuid.uuid4().hex)
 check('OCI group rechecks revoked source grants for graph and discovery',req('/v2/oci-group/proof/manifests/v1','reader')[0]==403 and req('/v2/oci-group/proof/referrers/'+root_digest,'reader')[0]==403)
 repository('oci-strict-group','oci',mode='group',review=True,settings={'members':['oci-local','oci-proxy']})
 req('/api/v1/repositories/oci-local/decisions',method='PUT',data={'path':'proof/manifests/'+local_digest,'digest':local_digest.removeprefix('sha256:'),'decision':'allowed'},key=uuid.uuid4().hex)
 check('OCI group review governs unassessed children of an allowed root',req('/v2/oci-strict-group/proof/manifests/v1')[0]==403)
 req('/api/v1/repositories/oci-local/decisions',method='PUT',data={'path':'proof/manifests/'+local_digest,'digest':local_digest.removeprefix('sha256:'),'decision':'denied'},key=uuid.uuid4().hex)
 check('OCI denied first-source tag cannot fall through',req('/v2/oci-group/proof/manifests/v1')[0]==403 and json.loads(req('/v2/oci-group/proof/tags/list')[1])['tags']==['v2'])
 check('OCI namespace owner blocks upstream fallback',req('/v2/oci-group/private/not-found/manifests/v1')[0]==404)
 repository('oci-reviewed','oci',mode='proxy',review=True,settings=settings)
 check('OCI proxy intake durably quarantines the complete graph',req('/v2/oci-reviewed/proof/manifests/v1')[0]==403)
 intake=json.loads(req('/api/v1/repositories/oci-reviewed/artifacts')[1])['items'];check('OCI quarantined intake retains canonical graph members',len(intake)>=4)
 for item in intake:req('/api/v1/repositories/oci-reviewed/decisions',method='PUT',data={'path':item['path'],'digest':item['digest'],'decision':'allowed'},key=uuid.uuid4().hex)
 check('OCI reviewed graph becomes consumable after explicit decisions',req('/v2/oci-reviewed/proof/manifests/v1')[0]==200)
 req('/api/v1/repositories/oci-proxy/decisions',method='PUT',data={'path':'proof/blobs/'+layer,'digest':layer.removeprefix('sha256:'),'decision':'denied'},key=uuid.uuid4().hex)
 check('OCI proxy fresh cache cannot bypass a child denial',req('/v2/oci-proxy/proof/manifests/v1')[0]==403 and req('/v2/oci-proxy/proof/blobs/'+layer)[0]==403)
 check('OCI denied source graph blocks proxied referrer discovery',req('/v2/oci-proxy/proof/referrers/'+root_digest)[0]==403)
 check('OCI cached tenant coordinates remain isolated',req('/v2/oci-proxy/proof/manifests/v1','other')[0]==404)

def maven():
 repository('java','maven');work=PRIVATE/'maven';work.mkdir();(work/'cache').mkdir()
 settings=work/'settings.xml';settings.write_text('<settings><servers><server><id>cratectl</id><username>token</username><password>'+tokens['admin']+'</password></server></servers></settings>');settings.chmod(0o600)
 def mvn(args):
  return run([ROOT/'.cache/apache-maven-3.10.0/bin/mvn','-B','-s',settings,'-Dmaven.repo.local='+str(work/'cache')]+args,work,{'JAVA_HOME':str(ROOT/'.cache/jdk-21.0.13+9/Contents/Home')})
 commands.append({'version':mvn(['--version'])})
 def deploy(name,version,dependency,repo='java',marker=None,local_cache=None):
  filename=name+'-'+version
  with zipfile.ZipFile(work/(filename+'.jar'),'w') as jar:jar.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\n');jar.writestr('fixture.txt',marker or filename)
  deps='<dependencies><dependency><groupId>dev.cratectl.proof</groupId><artifactId>proof-dep</artifactId><version>1.0.0</version></dependency></dependencies>' if dependency else ''
  (work/(filename+'.pom')).write_text('<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>dev.cratectl.proof</groupId><artifactId>'+name+'</artifactId><version>'+version+'</version>'+deps+'</project>')
  mvn((['-Dmaven.repo.local='+str(local_cache)]if local_cache else[])+['org.apache.maven.plugins:maven-deploy-plugin:3.1.4:deploy-file','-Dfile='+str(work/(filename+'.jar')),'-DpomFile='+str(work/(filename+'.pom')),'-DrepositoryId=cratectl','-Durl='+BASE+'/r/'+repo+'/'])
 for name,version,dependency in [('proof-dep','1.0.0',False),('proof-app','1.0.0',True),('proof-app','2.0.0',True),('proof-app','1.1-SNAPSHOT',True)]:deploy(name,version,dependency)
 # Distinct local repository forces package resolution through cratectl while
 # Maven build plugins themselves remain ordinary central tool dependencies.
 mvn(['org.apache.maven.plugins:maven-dependency-plugin:3.8.1:get','-Dmaven.repo.local='+str(work/'consumer-cache'),'-Dartifact=dev.cratectl.proof:proof-app:2.0.0','-DremoteRepositories=cratectl::default::'+BASE+'/r/java/','-Dtransitive=true'])
 target=work/'consumer-cache/dev/cratectl/proof'
 check('stock Maven resolves transitive dependency',all((target/name/'1.0.0'/(name+'-1.0.0.jar')).exists() for name in ['proof-dep']))
 check('stock Maven consumes exact published bytes',(target/'proof-app/2.0.0/proof-app-2.0.0.jar').read_bytes()==(work/'proof-app-2.0.0.jar').read_bytes())
 stop();start();check('Maven metadata replacement survives restart',b'2.0.0' in req('/r/java/dev/cratectl/proof/proof-app/maven-metadata.xml')[1])
 check('Maven snapshot metadata exists',b'SNAPSHOT' in req('/r/java/dev/cratectl/proof/proof-app/1.1-SNAPSHOT/maven-metadata.xml')[1])
 repository('java-remote','maven',mode='proxy',settings={'upstream':{'url':BASE+'/r/java/','networks':['127.0.0.1/32'],'credential_ref':'self'},'cache':{'fresh_seconds':60,'negative_seconds':2,'stale_seconds':0,'allow_no_store':True,'require_checksum':True}})
 repository('java-local','maven',access='restricted')
 req('/api/v1/repositories/java-local/grants',method='PUT',data={'actor':'reader','read':True,'write':False},key=uuid.uuid4().hex)
 repository('java-group','maven',mode='group',settings={'members':['java-local','java-remote'],'namespace_owners':{'dev/cratectl/private/':'java-local'}})
 reader_settings=work/'reader-settings.xml';reader_settings.write_text('<settings><servers><server><id>cratectl</id><username>token</username><password>'+tokens['reader']+'</password></server></servers></settings>');reader_settings.chmod(0o600)
 mvn(['-s',str(reader_settings),'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:get','-Dmaven.repo.local='+str(work/'consumer-proxy-cache'),'-Dartifact=dev.cratectl.proof:proof-app:2.0.0','-DremoteRepositories=cratectl::default::'+BASE+'/r/java-group/','-Dtransitive=true'])
 target_proxy=work/'consumer-proxy-cache/dev/cratectl/proof'
 check('stock Maven resolves transitive dependency through group and proxy',all((target_proxy/name/version/(name+'-'+version+'.jar')).read_bytes()==(work/(name+'-'+version+'.jar')).read_bytes() for name,version in [('proof-app','2.0.0'),('proof-dep','1.0.0')]))
 cached_items=json.loads(req('/api/v1/repositories/java-remote/artifacts')[1])['items']
 check('Maven proxy validates upstream checksums before publication',len(cached_items)>=4 and all(a['metadata'].get('upstream_checksum')=='sha256_verified' for a in cached_items))
 deploy('proof-app','3.0.0',True,'java-local')
 metadata_path='dev/cratectl/proof/proof-app/maven-metadata.xml'
 def maven_xml(data):
  root=XML.fromstring(data)
  for element in root.iter():element.tag=element.tag.rsplit('}',1)[-1]
  return root
 code,body,headers=req('/r/java-group/'+metadata_path,'reader');document=maven_xml(body)
 result['maven_first_union']={'status':code,'versions':[v.text for v in document.findall('./versioning/versions/version')],'source':headers.get('X-Cratectl-Repository'),'body_sha256':hashlib.sha256(body).hexdigest()}
 check('Maven group metadata unions versions from hosted and proxy members',code==200 and {v.text for v in document.findall('./versioning/versions/version')}>={'1.0.0','2.0.0','3.0.0','1.1-SNAPSHOT'})
 check('Maven merged checksum describes exact synthesized bytes',req('/r/java-group/'+metadata_path+'.sha256','reader')[1].decode()==hashlib.sha256(body).hexdigest())
 check('Maven merged metadata supports conditional and range requests',req('/r/java-group/'+metadata_path,'reader',headers={'If-None-Match':next(v for k,v in headers.items()if k.lower()=='etag')})[0]==304 and req('/r/java-group/'+metadata_path,'reader',headers={'Range':'bytes=0-15'})[:2]==(206,body[:16]))
 def consumer_cache(label):
  target=work/label;shutil.copytree(work/'cache',target);shutil.rmtree(target/'dev/cratectl/proof',ignore_errors=True);return target
 def consume(artifact,label,transitive=True,endpoint='java-group'):
  target=consumer_cache(label)
  mvn(['-U','-s',str(reader_settings),'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:get','-Dmaven.repo.local='+str(target),'-Dartifact='+artifact,'-DremoteRepositories=cratectl::default::'+BASE+'/r/'+endpoint+'/','-Dtransitive='+str(transitive).lower()])
  return target/'dev/cratectl/proof'/artifact.split(':')[1]
 target=consume('dev.cratectl.proof:proof-app:[1.0.0,4.0.0)','range-consumer')
 check('stock Maven resolves a version range spanning group members',(target/'3.0.0/proof-app-3.0.0.jar').read_bytes()==(work/'proof-app-3.0.0.jar').read_bytes())
 upstream=maven_xml(req('/r/java/'+metadata_path,'reader')[1]);proxied=maven_xml(req('/r/java-remote/'+metadata_path,'reader')[1])
 result['maven_proxy_hints']={'upstream_latest':upstream.findtext('./versioning/latest'),'proxy_latest':proxied.findtext('./versioning/latest'),'upstream_release':upstream.findtext('./versioning/release'),'proxy_release':proxied.findtext('./versioning/release')}
 check('Maven proxy preserves producer latest/release hints after an older POM cache fill',result['maven_proxy_hints']['upstream_latest']==result['maven_proxy_hints']['proxy_latest'] and result['maven_proxy_hints']['upstream_release']==result['maven_proxy_hints']['proxy_release'])
 target=consume('dev.cratectl.proof:proof-app:LATEST','latest-consumer',endpoint='java-remote')
 check('stock Maven LATEST resolves producer snapshot rather than the last cached older release',any(p.read_bytes()==(work/'proof-app-1.1-SNAPSHOT.jar').read_bytes()for p in target.glob('**/*.jar')))

 publishers=[('4.0.0',consumer_cache('publisher-four')),('5.0.0',consumer_cache('publisher-five'))]
 with ThreadPoolExecutor(max_workers=2)as executor:
  list(executor.map(lambda item:deploy('proof-app',item[0],True,'java-local',local_cache=item[1]),publishers))
 code,concurrent_metadata,_=req('/r/java-group/'+metadata_path,'reader')
 check('two concurrent stock Maven deployments retain both versions and accept their metadata checksums',code==200 and {v.text for v in maven_xml(concurrent_metadata).findall('./versioning/versions/version')}>={'3.0.0','4.0.0','5.0.0'})
 snapshot_path='dev/cratectl/proof/proof-app/1.1-SNAPSHOT/maven-metadata.xml'
 old_snapshot=req('/r/java-remote/'+snapshot_path,'reader')[1]
 deploy('proof-app','1.1-SNAPSHOT',True,marker='second unique snapshot publication')
 sources=work/'snapshot-sources.jar'
 with zipfile.ZipFile(sources,'w')as jar:jar.writestr('fixture-source.txt','owned classifier fixture')
 mvn(['org.apache.maven.plugins:maven-deploy-plugin:3.1.4:deploy-file','-Dfile='+str(sources),'-DgroupId=dev.cratectl.proof','-DartifactId=proof-app','-Dversion=1.1-SNAPSHOT','-Dpackaging=jar','-Dclassifier=sources','-DgeneratePom=false','-DrepositoryId=cratectl','-Durl='+BASE+'/r/java/'])
 code,snapshot_bytes,_=req('/r/java-group/'+snapshot_path,'reader',headers={'Cache-Control':'no-cache'});snapshot=maven_xml(snapshot_bytes)
 def snapshot_entries(data):return {(e.findtext('extension'),e.findtext('classifier')or''):e.findtext('value')for e in maven_xml(data).findall('./versioning/snapshotVersions/snapshotVersion')}
 entries=snapshot_entries(snapshot_bytes)
 check('Maven revalidation advances snapshots and retains extension/classifier mappings',code==200 and snapshot_bytes!=old_snapshot and all(key in entries for key in [('jar',''),('pom',''),('jar','sources')]))
 target=consume('dev.cratectl.proof:proof-app:1.1-SNAPSHOT','snapshot-consumer')
 check('stock Maven installs latest unique snapshot bytes through group and proxy',any(p.read_bytes()==(work/'proof-app-1.1-SNAPSHOT.jar').read_bytes()for p in (target/'1.1-SNAPSHOT').glob('*.jar')))
 target=consume('dev.cratectl.proof:proof-app:1.1-SNAPSHOT:jar:sources','classifier-consumer',False)
 check('stock Maven resolves the independent snapshot sources classifier',any(p.read_bytes()==sources.read_bytes()for p in (target/'1.1-SNAPSHOT').glob('*sources.jar')))
 stop();start();check('Maven native merged snapshot discovery survives restart',entries==snapshot_entries(req('/r/java-group/'+snapshot_path,'reader')[1]))
 parent=work/'proof-parent-1.0.0.pom';parent.write_text('<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>dev.cratectl.proof</groupId><artifactId>proof-parent</artifactId><version>1.0.0</version><packaging>pom</packaging><properties><proof.dep.version>1.0.0</proof.dep.version></properties></project>')
 mvn(['org.apache.maven.plugins:maven-deploy-plugin:3.1.4:deploy-file','-Dfile='+str(parent),'-DpomFile='+str(parent),'-Dpackaging=pom','-DrepositoryId=cratectl','-Durl='+BASE+'/r/java-local/'])
 mvn(['org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file','-Dfile='+str(parent),'-DpomFile='+str(parent),'-Dpackaging=pom'])
 child=work/'parent-child-1.0.0.jar'
 with zipfile.ZipFile(child,'w')as jar:jar.writestr('fixture-child.txt','owned parent inheritance fixture')
 child_pom=work/'parent-child-1.0.0.pom';child_pom.write_text('<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><parent><groupId>dev.cratectl.proof</groupId><artifactId>proof-parent</artifactId><version>1.0.0</version><relativePath/></parent><groupId>dev.cratectl.proof</groupId><artifactId>parent-child</artifactId><version>1.0.0</version><dependencies><dependency><groupId>dev.cratectl.proof</groupId><artifactId>proof-dep</artifactId><version>${proof.dep.version}</version></dependency></dependencies></project>')
 mvn(['org.apache.maven.plugins:maven-deploy-plugin:3.1.4:deploy-file','-Dfile='+str(child),'-DpomFile='+str(child_pom),'-DrepositoryId=cratectl','-Durl='+BASE+'/r/java/'])
 target=consume('dev.cratectl.proof:parent-child:1.0.0','parent-consumer')
 check('stock Maven resolves parent POM inheritance and its transitive version property across group sources',(target/'1.0.0/parent-child-1.0.0.jar').read_bytes()==child.read_bytes() and (target.parent/'proof-parent/1.0.0/proof-parent-1.0.0.pom').read_bytes()==parent.read_bytes() and (target.parent/'proof-dep/1.0.0/proof-dep-1.0.0.jar').exists())
 artifacts=json.loads(req('/api/v1/repositories/java/artifacts')[1])['items'];target=next(a for a in artifacts if a['path'].endswith('proof-app-2.0.0.jar'))
 req('/api/v1/repositories/java/decisions',method='PUT',data={'path':target['path'],'digest':target['digest'],'decision':'denied'},key=uuid.uuid4().hex)
 check('Maven denial blocks artifact and checksum',req('/r/java/'+target['path'])[0]==403 and req('/r/java/'+target['path']+'.sha1')[0]==403)

def proxy():
 repository('source','generic','other',access='restricted')
 check('upstream reader grant',req('/api/v1/repositories/source/grants','other','PUT',{'actor':'origin','read':True,'write':False},uuid.uuid4().hex)[0]==200)
 unauthorized={'name':'credential-escape','format':'generic','mode':'proxy','settings':{'upstream':{'url':BASE+'/r/source/','networks':['127.0.0.1/32'],'credential_ref':'fixture'},'cache':{'fresh_seconds':60,'allow_no_store':True}}}
 check('upstream credentials cannot cross tenant scope',req('/api/v1/repositories','other','POST',unauthorized,uuid.uuid4().hex)[0]==400)
 unauthorized['settings']['upstream']['url']=BASE+'/r/different-authority/'
 check('upstream credential is bound to its approved authority and base path',req('/api/v1/repositories',method='POST',data=unauthorized,key=uuid.uuid4().hex)[0]==400)
 payload=b'governed upstream bytes\n'*1024
 source=json.loads(req('/r/source/object','other','PUT',payload)[1])
 repository('remote','generic',mode='proxy',settings={'upstream':{'url':BASE+'/r/source/','networks':['127.0.0.1/32'],'credential_ref':'fixture'},'cache':{'fresh_seconds':60,'negative_seconds':2,'stale_seconds':60,'allow_no_store':True}})
 check('proxy never forwards caller credentials',req('/r/remote/object','reader')[1]==payload)
 check('fresh proxy hit is explicit',req('/r/remote/object','reader')[2].get('X-Cratectl-Cache')=='hit')
 check('proxy is read only',req('/r/remote/object',method='PUT',data=b'new')[0]==405)
 code,body,h=req('/r/remote/object','reader',headers={'Cache-Control':'no-cache'})
 check('conditional upstream revalidation preserves bytes',code==200 and body==payload and h.get('X-Cratectl-Cache')=='revalidated')
 check('negative miss returns not found',req('/r/remote/missing','reader')[0]==404)
 generation=json.loads(req('/api/v1/repositories/remote/cache?path=missing')[1])['generation']
 check('negative cache does not create a second retrieval',req('/r/remote/missing','reader')[0]==404 and json.loads(req('/api/v1/repositories/remote/cache?path=missing')[1])['generation']==generation)
 # Four simultaneous requests share one durable retrieval generation.
 req('/r/source/concurrent','other','PUT',payload)
 with ThreadPoolExecutor(max_workers=4) as pool:responses=list(pool.map(lambda _:req('/r/remote/concurrent','reader'),range(4)))
 check('concurrent proxy misses all receive exact bytes',all(x[0]==200 and x[1]==payload for x in responses))
 check('concurrent proxy misses coalesce through PostgreSQL',json.loads(req('/api/v1/repositories/remote/cache?path=concurrent')[1])['generation']==1)
 repository('local','generic',access='restricted')
 req('/api/v1/repositories/local/grants',method='PUT',data={'actor':'reader','read':True,'write':False},key=uuid.uuid4().hex)
 repository('combined','generic',mode='group',settings={'members':['local','remote'],'namespace_owners':{'private/':'local'}})
 check('group serves authorized fallback source',req('/r/combined/object','reader')[1]==payload)
 req('/r/source/private/absent','other','PUT',b'untrusted public collision')
 check('namespace ownership prevents dependency-confusion fallback',req('/r/combined/private/absent','reader')[0]==404)
 req('/api/v1/repositories/local/grants',method='PUT',data={'actor':'reader','read':False,'write':False},key=uuid.uuid4().hex)
 check('revoked underlying grant blocks group fallback',req('/r/combined/object','reader')[0]==403)
 check('restricted repository absent from unauthorized inventory',not any(x['name']=='local' for x in json.loads(req('/api/v1/repositories','reader')[1])['items']))
 check('reader cannot inspect unrelated tenant audit events',req('/api/v1/audit','reader')[0]==403)
 check('cache status does not reveal credentials or lease tokens',all(token.encode() not in req('/api/v1/repositories/remote/cache?path=object')[1] for token in tokens.values()))
 repository('reviewed','generic',review=True,mode='proxy',settings={'upstream':{'url':BASE+'/r/source/','networks':['127.0.0.1/32'],'credential_ref':'fixture'},'cache':{'fresh_seconds':60,'negative_seconds':2,'stale_seconds':0,'allow_no_store':True}})
 check('proxy intake is durable but quarantined before review',req('/r/reviewed/object','reader')[0]==403 and json.loads(req('/api/v1/repositories/reviewed/cache?path=object')[1])['state']=='ready')
 reviewed=json.loads(req('/api/v1/repositories/reviewed/artifacts')[1])['items'][0]
 req('/api/v1/repositories/reviewed/decisions',method='PUT',data={'path':'object','digest':reviewed['digest'],'decision':'allowed'},key=uuid.uuid4().hex)
 check('manual review allows exact proxy bytes',req('/r/reviewed/object','reader')[1]==payload)
 repository('strict','generic',mode='proxy',settings={'upstream':{'url':BASE+'/r/source/','networks':['127.0.0.1/32'],'credential_ref':'fixture'},'cache':{'fresh_seconds':60,'negative_seconds':2}})
 check('upstream no-store requires explicit operator override',req('/r/strict/object','reader')[0]==502)
 repository('bad-source','generic','other')
 req('/r/bad-source/library.jar','other','PUT',b'benign fixture bytes')
 req('/r/bad-source/library.jar.sha256','other','PUT',b'0'*64)
 repository('bad-cache','maven',mode='proxy',settings={'upstream':{'url':BASE+'/r/bad-source/','networks':['127.0.0.1/32'],'credential_ref':'bad-fixture'},'cache':{'fresh_seconds':60,'negative_seconds':2,'stale_seconds':60,'allow_no_store':True,'require_checksum':True}})
 check('Maven upstream checksum mismatch is rejected',req('/r/bad-cache/library.jar','reader')[0]==502)
 check('checksum mismatch publishes no artifact reference',json.loads(req('/api/v1/repositories/bad-cache/artifacts')[1])['items']==[])
 # Force the origin to return 503; cached bytes live in the other tenant's
 # independent namespace, so this cannot corrupt the cached copy.
 source_path=PRIVATE/'objects'/tenants['other']/'sha256'/source['digest'][:2]/source['digest'];source_path.write_bytes(b'X'*len(payload))
 req('/api/v1/repositories/remote/cache',method='PUT',data={'path':'object'},key=uuid.uuid4().hex)
 code,body,h=req('/r/remote/object','reader');check('explicit stale-on-503 preserves exact cached bytes',code==200 and body==payload and h.get('X-Cratectl-Cache')=='stale')
 cached=next(a for a in json.loads(req('/api/v1/repositories/remote/artifacts')[1])['items'] if a['path']=='object')
 req('/api/v1/repositories/remote/decisions',method='PUT',data={'path':'object','digest':cached['digest'],'decision':'denied'},key=uuid.uuid4().hex)
 check('stale cache cannot bypass a current digest denial',req('/r/remote/object','reader')[0]==403)
 check('an alias cannot bypass the same repository digest denial',req('/r/remote/concurrent','reader')[0]==403)
 stop();start();check('proxy denial and cache state survive restart',req('/r/remote/object','reader')[0]==403)
 source_path.write_bytes(payload)
 run([BIN/'cratectld','revoke','--token-file',PRIVATE/'origin.token'])
 req('/api/v1/repositories/reviewed/cache',method='PUT',data={'path':'object'},key=uuid.uuid4().hex)
 check('upstream authentication rejection cannot use stale bytes',req('/r/reviewed/object','reader')[0]==502)


def sourceconfig():
 """Separate native client caches prove each new source epoch supplies bytes."""
 work=PRIVATE/'source-config';work.mkdir()
 python=ROOT/'.cache/clients/bin/python';oras=ROOT/'.cache/bin/oras'
 def settings(fmt,side):
  prefix={'raw':'r','java':'r','js':'npm','py':'pypi','oci':'v2'}[fmt];base=BASE+'/'+prefix+'/config-'+fmt+'-'+side+'/'
  authority={'url':base+('simple/'if fmt=='py'else''),'networks':['127.0.0.1/32'],'credential_ref':'config-'+fmt+'-'+side}
  out={'upstream':authority,'cache':{'fresh_seconds':3600,'negative_seconds':30,'stale_seconds':3600,'allow_no_store':True,'require_checksum':fmt!='raw'}}
  if fmt=='py':out['download_sources']=[{**authority,'url':base+'files/'}]
  return out
 def change(fmt,side,revision):
  code,body,_=req('/api/v1/repositories/config-'+fmt+'/configuration',method='PUT',data={'expected_revision':revision,'settings':settings(fmt,side),'reason':'Owned native source replacement'},key=uuid.uuid4().hex)
  check(fmt+': configuration replacement advances exact revision',code==200 and json.loads(body)['current']['source_revision']==revision+1)
 for fmt,native in [('raw','generic'),('java','maven'),('js','npm'),('py','pypi'),('oci','oci')]:
  for side in ['a','b']:
   origin='config-'+fmt+'-'+side;repository(origin,native,'other',access='restricted')
   check(origin+': grant only the matching source reader',req('/api/v1/repositories/'+origin+'/grants','other','PUT',{'actor':'config-'+side,'read':True,'write':False},uuid.uuid4().hex)[0]==200)
   check(origin+': opposite source credential is denied',req('/api/v1/repositories/'+origin,'config-'+('b'if side=='a'else'a'))[0]in [403,404])
  repository('config-'+fmt,native,mode='proxy',settings=settings(fmt,'a'))
 for side in ['a','b']:check('raw source '+side+' publishes distinct bytes',req('/r/config-raw-'+side+'/file','other','PUT',('source '+side).encode())[0]==201)
 check('raw initial source cached',req('/r/config-raw/file','reader')[1]==b'source a')
 invalid=settings('raw','b');invalid['upstream']['credential_ref']='config-raw-a'
 check('changed URL cannot borrow the previous source credential',req('/api/v1/repositories/config-raw/configuration',method='PUT',data={'expected_revision':0,'settings':invalid,'reason':'Owned authority rejection'},key=uuid.uuid4().hex)[0]==400)
 change('raw','b',0);check('raw fresh cache is invalid after source replacement',req('/r/config-raw/file','reader')[1]==b'source b')
 change('raw','a',1);check('raw rollback revalidates first source under a new revision',req('/r/config-raw/file','reader')[1]==b'source a')
 # OCI uses independent registry credential files and pull directories.
 auth={}
 for role in ['other','reader']:
  auth[role]=work/(role+'-oras.json');run([oras,'login','--plain-http','--registry-config',auth[role],'--username','token','--password-stdin','127.0.0.1:38443'],input_text=tokens[role]+'\n')
 for side in ['a','b']:
  d=work/('oci-origin-'+side);d.mkdir();(d/'payload.txt').write_text('OCI source '+side)
  run([oras,'push','--plain-http','--registry-config',auth['other'],'127.0.0.1:38443/config-oci-'+side+'/app:latest','payload.txt:text/plain'],d)
 def pull(label,expected):
  d=work/('oci-pull-'+label);d.mkdir();run([oras,'pull','--plain-http','--registry-config',auth['reader'],'127.0.0.1:38443/config-oci/app:latest'],d)
  check('stock ORAS exact bytes after '+label,(d/'payload.txt').read_text()=='OCI source '+expected)
 pull('initial','a');change('oci','b',0);pull('replacement','b');change('oci','a',1);pull('rollback','a')
 # npm metadata, locator receipts and transitive archive bytes must all move.
 def npm_env(repo,label):
  rc=work/(label+'.npmrc');rc.write_text('registry='+BASE+'/npm/'+repo+'/\n//127.0.0.1:38443/npm/'+repo+'/:_authToken='+tokens['other'if repo.endswith(('-a','-b'))else'reader']+'\n');rc.chmod(0o600)
  return {'NPM_CONFIG_USERCONFIG':str(rc),'NPM_CONFIG_CACHE':str(work/(label+'-npm-cache'))}
 for side,version,number in [('a','1.0.0',1),('b','2.0.0',2)]:
  for name,dependencies,body in [('cratectl-config-dep',{},'module.exports=41;'),('cratectl-config-app',{'cratectl-config-dep':'1.0.0'},'module.exports=require("cratectl-config-dep")+'+str(number)+';')]:
   d=work/('npm-'+side+'-'+name);d.mkdir();(d/'package.json').write_text(json.dumps({'name':name,'version':version if dependencies else'1.0.0','main':'index.js','description':'Owned source configuration fixture','license':'MIT','dependencies':dependencies}));(d/'index.js').write_text(body)
   run(['npm','publish','--ignore-scripts','--access','public'],d,npm_env('config-js-'+side,'publish-'+side+'-'+name))
 def npm_install(label,version,number):
  d=work/('npm-consumer-'+label);d.mkdir();(d/'package.json').write_text('{"name":"owned-source-consumer","version":"1.0.0"}')
  run(['npm','install','--ignore-scripts','--no-audit','--no-fund','cratectl-config-app@latest'],d,npm_env('config-js','consume-'+label))
  run(['node','-e','if(require("cratectl-config-app")!=='+str(number)+'||require("cratectl-config-app/package.json").version!=="'+version+'")process.exit(1)'],d)
  check('stock npm resolves current source and dependency after '+label,True)
 npm_install('initial','1.0.0',42);old_npm=json.loads(req('/npm/config-js/cratectl-config-app','reader')[1])['versions']['1.0.0']['dist']['tarball'].replace(BASE,'')
 change('js','b',0);check('old npm download locator cannot reuse the old source epoch',req(old_npm,'reader')[0]==503);npm_install('replacement','2.0.0',43)
 change('js','a',1);npm_install('rollback','1.0.0',42)
 # Python puts credentials in private netrc files, never source URLs.
 for side,version,addend in [('a','1.0.0',1),('b','2.0.0',2)]:
  dep=wheel('cratectl_config_dep');app=wheel('cratectl_config_app','cratectl-config-dep',version,addend)
  run([python,'-m','twine','upload','--non-interactive','--repository-url',BASE+'/pypi/config-py-'+side+'/',dep,app],extra={'TWINE_USERNAME':'token','TWINE_PASSWORD':tokens['other'],'TWINE_DISABLE_PROGRESS_BAR':'1'})
 netrc=work/'pip-netrc';netrc.write_text('machine 127.0.0.1 login token password '+tokens['reader']+'\n');netrc.chmod(0o600)
 pip_env={'NETRC':str(netrc),'PIP_CONFIG_FILE':os.devnull,'PIP_KEYRING_PROVIDER':'disabled','PIP_DISABLE_PIP_VERSION_CHECK':'1','PIP_EXTRA_INDEX_URL':'','PIP_NO_INPUT':'1'}
 def pip_install(label,number):
  target=work/('pip-consumer-'+label)
  run([python,'-m','pip','install','--no-cache-dir','--index-url',BASE+'/pypi/config-py/simple/','--target',target,'cratectl-config-app'],extra=pip_env)
  run([python,'-c','import sys;sys.path.insert(0,'+repr(str(target))+');from cratectl_config_app import value;assert value=='+str(number)])
  check('stock pip resolves current source and dependency after '+label,True)
 pip_install('initial',42);change('py','b',0);pip_install('replacement',43);change('py','a',1);pip_install('rollback',42)
 # Maven publishes native HTTP coordinates, then resolves with independent
 # stock-client local repositories so downloaded application bytes cannot hide
 # a server cache mistake. Maven tool plugins remain ordinary Central inputs.
 expected={};group='dev/cratectl/source'
 for side in ['a','b']:
  for name,dependency in [('config-dep',False),('config-app',True)]:
   stream=io.BytesIO()
   with zipfile.ZipFile(stream,'w')as archive:archive.writestr('fixture.txt',side+' '+name)
   jar=stream.getvalue();deps='<dependencies><dependency><groupId>dev.cratectl.source</groupId><artifactId>config-dep</artifactId><version>1.0.0</version></dependency></dependencies>'if dependency else''
   pom=('<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>dev.cratectl.source</groupId><artifactId>'+name+'</artifactId><version>1.0.0</version>'+deps+'</project>').encode()
   for ext,data in [('jar',jar),('pom',pom)]:check('Maven origin '+side+' publishes '+name+'.'+ext,req('/r/config-java-'+side+'/'+group+'/'+name+'/1.0.0/'+name+'-1.0.0.'+ext,'other','PUT',data)[0]==201)
   expected[side,name]=jar
 maven_settings=work/'maven-settings.xml';maven_settings.write_text('<settings><servers><server><id>cratectl</id><username>token</username><password>'+tokens['reader']+'</password></server></servers></settings>');maven_settings.chmod(0o600)
 def maven_install(label,side):
  cache=work/('maven-consumer-'+label)
  run([ROOT/'.cache/apache-maven-3.10.0/bin/mvn','-B','-s',maven_settings,'-Dmaven.repo.local='+str(cache),'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:get','-Dartifact=dev.cratectl.source:config-app:1.0.0','-DremoteRepositories=cratectl::default::'+BASE+'/r/config-java/','-Dtransitive=true'],work,{'JAVA_HOME':str(ROOT/'.cache/jdk-21.0.13+9/Contents/Home')})
  check('stock Maven resolves exact source and dependency after '+label,all((cache/group/name/'1.0.0'/(name+'-1.0.0.jar')).read_bytes()==expected[side,name]for name in ['config-app','config-dep']))
 maven_install('initial','a');change('java','b',0);maven_install('replacement','b');change('java','a',1);maven_install('rollback','a')
 # Static private-provider values rotate during controlled suspension/restart.
 check('suspend before reloading the private provider',req('/api/v1/repositories/config-oci/state',method='PUT',data={'action':'suspend','expected_revision':0,'reason':'Owned controlled credential rotation'},key=uuid.uuid4().hex)[0]==200)
 stop();run([BIN/'cratectld','revoke','--token-file',PRIVATE/'config-a.token'])
 rotated=PRIVATE/'config-a-rotated.token';run([BIN/'cratectld','provision','--tenant',tenants['other'],'--actor','config-a','--role','reader','--token-file',rotated]);tokens['config-a']=rotated.read_text().strip();start()
 change('oci','a',2)
 check('resume after new epoch with reloaded credential',req('/api/v1/repositories/config-oci/state',method='PUT',data={'action':'resume','expected_revision':1,'reason':'Owned controlled credential rotation complete'},key=uuid.uuid4().hex)[0]==200)
 pull('credential-rotation','a');check('configuration history retains monotonic revisions through reload',len(json.loads(req('/api/v1/repositories/config-oci/configuration/history')[1])['items'])==3)

def build_identity(name):
 go=ROOT/'.cache/go/bin/go'
 output=subprocess.check_output([str(go) if go.exists() else 'go','version','-m',str(ROOT/name)],text=True)
 settings={}
 for line in output.splitlines():
  parts=line.strip().split('\t')
  if len(parts)==2 and parts[0]=='build' and '=' in parts[1]:
   key,value=parts[1].split('=',1);settings[key]=value
 return {'go_version':output.splitlines()[0].split()[-1],'settings':settings}

def nuget():
 from conformance_nuget_hosted import hosted
 hosted(sys.modules[__name__])

source_scope=['cmd','internal','scripts','api','go.mod','go.sum','Makefile']
result={'run':RUN,'candidate':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'source_scope':source_scope,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*source_scope],text=True).strip()),'artifact_digests':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in candidate_artifact_names()},'build_identity':{name:build_identity(name) for name in candidate_artifact_names()},'host':platform.platform(),'database_profile':database_profile,'topology':f'native {platform.platform()} server, PostgreSQL 16.15 {database_profile}, filesystem bytes, HTTP loopback only','checks':checks,'commands':commands,'limitations':['Not full format conformance or parity.','Proxy/group proof covers generic, Maven and early npm journeys; no complete mode, migration, HA, scale or scanner qualification.','Client fixture code executes only in the explicitly owned test consumer.','No claim of a separate-machine install.']}
result['build_source_matches_candidate']=all(meta['settings'].get('vcs.revision')==result['candidate'] and meta['settings'].get('vcs.modified')=='false' for meta in result['build_identity'].values())
tenants={}
try:
 mode=sys.argv[1] if len(sys.argv)>1 else 'all'
 if '--require-clean-build' in sys.argv[2:]:
  check('qualification source is clean',not result['source_dirty'])
  check('qualification binaries embed exact clean source commit',result['build_source_matches_candidate'])
 for label,role in [('admin','admin'),('reader','reader'),('other','admin'),('origin','reader'),('npm-meta-origin','reader'),('npm-files-origin','reader')]+([('config-a','reader'),('config-b','reader')]if mode in ['all','sourceconfig']else[]):
  tenant='proof-'+RUN+('-b' if label in ['other','origin','npm-meta-origin','npm-files-origin','config-a','config-b'] else '-a');tenants[label]=tenant;token_file=PRIVATE/(label+'.token')
  run([BIN/'cratectld','provision','--tenant',tenant,'--actor',label,'--role',role,'--token-file',token_file]);tokens[label]=token_file.read_text().strip()
 for label,lifetime in [('expired','1ms'),('revocable','1h')]:
  token_file=PRIVATE/(label+'.token');run([BIN/'cratectld','provision','--tenant',tenants['admin'],'--actor',label,'--role','reader','--expires-in',lifetime,'--token-file',token_file]);tokens[label]=token_file.read_text().strip()
 start();mode=sys.argv[1] if len(sys.argv)>1 else 'all'
 for name,fn in [('generic',generic),('npm',npm),('npmproxy',npmproxy),('pypi',pypi),('pypiproxy',pypiproxy),('oci',oci),('ociproxy',ociproxy),('maven',maven),('proxy',proxy),('sourceconfig',sourceconfig),('nuget',nuget)]:
  if mode in ('all',name):fn()
 result['status']='passed';print(f'PASS: {len(checks)} assertions; native mode {mode}')
except Exception as error:
 result['status']='failed';result['failure']=str(error);print('FAIL:',error);raise
finally:
 stop();result['input_digests']={str(p.relative_to(PRIVATE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in list(PRIVATE.rglob('*.whl'))+list(PRIVATE.glob('maven/*.jar'))+list(PRIVATE.glob('maven/*.pom'))}
 (EVIDENCE/('conformance-'+RUN+'.json')).write_text(json.dumps(result,indent=2)+'\n')
 print('Evidence:',EVIDENCE/('conformance-'+RUN+'.json'))
