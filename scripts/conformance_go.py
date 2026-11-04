#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned trusted-TLS Go download journey; never build or execute package contents."""
import argparse,datetime,hashlib,io,json,os,platform,re,ssl,subprocess,time,urllib.error,urllib.parse,urllib.request,uuid,zipfile
from pathlib import Path
from bounded_client import run_owned_client
from qualification_contract import candidate_binary_directory,candidate_artifact_names
from ci.go_module_evidence import STAGES,FIXTURES,CACHED_FIXTURES

ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT)
parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');args=parser.parse_args()
RUN=uuid.uuid4().hex[:10];BIN=candidate_binary_directory();GO=ROOT/'.cache/go/bin/go'
PRIVATE=ROOT/'.private/go-module-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
INSTALL=PRIVATE/'installation';BASE='https://localhost:38443';INSTANT='2026-01-02T03:04:05Z';MODULE='go.cratectl.invalid/Owned/application';DEPENDENCY='go.cratectl.invalid/Owned/dependency'
env=dict(os.environ);public_env={k:v for k,v in env.items()if k not in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']}
checks=[];commands=[];tokens={};process=None;server_log=None;database_created=False
contract={'profile':'hosted-module-v1','version':None,'go_binary_sha256':hashlib.sha256(GO.read_bytes()).hexdigest(),'fixture_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'completed':[],'publisher_sha256':{},'reference_sha256':{},'wire_sha256':{},'cached_sha256':{}}
EVIDENCE=ROOT/'evidence'/datetime.datetime.now(datetime.timezone.utc).date().isoformat();EVIDENCE.mkdir(parents=True,exist_ok=True)
def digest(b):return hashlib.sha256(b).hexdigest()
def check(label,condition):
 if not condition:raise AssertionError(label)
 checks.append(label)
def private(name,data):
 p=PRIVATE/name;p.parent.mkdir(parents=True,exist_ok=True)
 p.write_bytes(data if isinstance(data,bytes)else json.dumps(data).encode());p.chmod(0o600);return p

def command(argv,runenv=public_env,cwd=ROOT,ok=True):
 log=PRIVATE/('command-'+uuid.uuid4().hex+'.log')
 record={'tool':Path(str(argv[0])).name,'exit':None,'expected_failure':False,'private_log':str(log.relative_to(ROOT))}
 commands.append(record)
 with os.fdopen(os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb')as sink:
  code,output=run_owned_client([str(a)for a in argv],cwd,runenv,timeout=120,output_limit=8<<20,capture_limit=8<<20,output_sink=sink)
 record['exit']=code;record['expected_failure']=not ok and code==1
 for value in tokens.values():output=output.replace(value,'[REDACTED]')
 if (code==0)!=ok or not ok and code!=1:
  record['assertion_failed']=True
  raise AssertionError('bounded native command returned unexpected status: '+Path(str(argv[0])).name)
 return output

def settings(name):
 observed={}
 for line in subprocess.check_output([str(GO),'version','-m',str(ROOT/name)],text=True).splitlines():
  parts=line.strip().split('\t')
  if len(parts)==2 and parts[0]=='build'and'='in parts[1]:k,v=parts[1].split('=',1);observed[k]=v
 return observed
scope=['cmd','internal','scripts','api','web','go.mod','go.sum','Makefile']
result={'run':RUN,'candidate':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'source_scope':scope,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*scope],text=True).strip()),'artifact_digests':{name:digest((ROOT/name).read_bytes())for name in candidate_artifact_names()},'build_identity':{name:settings(name)for name in candidate_artifact_names()},'checks':checks,'commands':commands,'go_module_contract':contract,'topology':f'Native {platform.platform()}; owned fresh PostgreSQL database and nonsuperuser runtime; generated trusted loopback TLS on38443; private NETRC; fresh project/module caches; no VCS, public package fallback or package execution.','limits':['Hosted profile only. Proxy/group, warm caches, legacy modules without go.mod, broader version/query/race/fault/lifecycle/migration/scale/TLS-provider/platform outcomes remain required.','Owned dependency-bearing resource modules are downloaded/extracted by stock Go, never compiled or executed. This does not establish separate-host, full format or product readiness.','Fixture namespaces explicitly bypass the public checksum database using GONOSUMDB; Go still computes module sums. Public checksum-service mirroring and disconnected/public-module behavior remain separate.']}
result['build_source_matches_candidate']=all(v.get('vcs.revision')==result['candidate']and v.get('vcs.modified')=='false'for v in result['build_identity'].values())
def http(p,who='admin',method='GET',data=None,headers=None):
 h={'Authorization':'Bearer '+tokens[who]};h.update(headers or {})
 if isinstance(data,dict):data=json.dumps(data).encode();h['Content-Type']='application/json'
 if method in ['POST','PUT']and p.startswith('/api/'):h['Idempotency-Key']=uuid.uuid4().hex
 req=urllib.request.Request(BASE+p,data=data,headers=h,method=method)
 try:
  with urllib.request.urlopen(req,context=ssl.create_default_context(cafile=str(INSTALL/'ca.crt')),timeout=15)as response:return response.status,response.read(8<<20|1),dict(response.headers)
 except urllib.error.HTTPError as e:return e.code,e.read(8<<20|1),dict(e.headers)
def stop():
 global process,server_log
 if process is not None and process.poll()is None:
  process.terminate()
  try:process.wait(timeout=10)
  except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
 process=None
 if server_log is not None:server_log.close();server_log=None

def start():
 global process,server_log
 server_log=(PRIVATE/'server.log').open('ab')
 process=subprocess.Popen([str(BIN/'cratectld'),'serve','--config',str(INSTALL/'runtime.json')],env=public_env,stdout=server_log,stderr=subprocess.STDOUT)
 for _ in range(150):
  if process.poll()is not None:raise AssertionError('owned registry exited during startup')
  try:
   with urllib.request.urlopen(BASE+'/health/ready',context=ssl.create_default_context(cafile=str(INSTALL/'ca.crt')),timeout=1)as response:
    if response.status==200:return
  except (OSError,urllib.error.URLError):time.sleep(.05)
 raise AssertionError('trusted registry readiness deadline')
def psql(sql):return command([ROOT/'.cache/postgresql-16.15-install/bin/psql','-X','-v','ON_ERROR_STOP=1','-At','-c',sql],runenv=pgenv)
def with_database(dsn,name):
 u=urllib.parse.urlsplit(dsn)
 if u.scheme not in ['postgres','postgresql']or u.hostname!='127.0.0.1'or u.port!=35432:raise AssertionError('owned loopback PostgreSQL binding required')
 return urllib.parse.urlunsplit((u.scheme,u.netloc,'/'+name,u.query,u.fragment))
def escaped(m):return ''.join('!'+c.lower()if c.isupper()else c for c in m)
def fixture(module,version,payload,dependency=None):
 mod=('module '+module+'\n\ngo 1.26.0\n'+('require '+dependency+' v1.0.0\n'if dependency else '')).encode()
 output=io.BytesIO()
 with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED)as archive:
  for name,body in [('go.mod',mod),('assets/owned.txt',payload.encode())]:archive.writestr(module+'@'+version+'/'+name,body)
 return {'module':module,'version':version,'zip':output.getvalue(),'mod':mod,'info':json.dumps({'Version':version,'Time':INSTANT},separators=(',',':')).encode()}
fixtures={
 'dependency':fixture(DEPENDENCY,'v1.0.0','tenant-A-dependency'),
 'application_1':fixture(MODULE,'v1.0.0','tenant-A-application-one',DEPENDENCY),
 'application_2':fixture(MODULE,'v1.1.0','tenant-A-application-two',DEPENDENCY),
 'other_dependency':fixture(DEPENDENCY,'v1.0.0','tenant-B-dependency'),
 'other_application':fixture(MODULE,'v1.0.0','tenant-B-application',DEPENDENCY),
}
def publish(label,who='publisher',expected=201,replace=None):
 f=fixtures[label];code,body,_=http('/go/owned/'+escaped(f['module'])+'/@v/'+f['version']+'.zip',who,'PUT',replace or f['zip'],{'X-Cratectl-Module-Time':INSTANT})
 check(label+': publication status '+str(expected),code==expected)
 if expected==201:
  receipt=json.loads(body);check(label+': publication digest identity',receipt['representations_sha256']=={kind:digest(f[kind])for kind in ['zip','mod','info']})
  for kind in ['zip','mod','info']:contract['publisher_sha256'][label+'_'+kind]=digest(f[kind])
 return body

def approve(who='admin',decision='allowed',only=None):
 code,body,_=http('/api/v1/repositories/owned/artifacts',who)
 check(who+': complete exact reference inventory',code==200)
 for a in json.loads(body)['items']:
  if only is not None and not a['path'].endswith(only):continue
  check(who+': digest decision '+decision,http('/api/v1/repositories/owned/decisions',who,'PUT',{'path':a['path'],'digest':a['digest'],'decision':decision})[0]==200)

def bind(label,who='admin'):
 f=fixtures[label];code,body,_=http('/api/v1/repositories/owned/artifacts',who);check(label+': inventory for byte binding',code==200)
 refs={a['path']:a for a in json.loads(body)['items']}
 for kind in ['zip','mod','info']:
  p=escaped(f['module'])+'/@v/'+f['version']+'.'+kind;a=refs[p];code,body,_=http('/go/owned/'+p,who)
  check(label+' '+kind+': exact publisher/reference/HTTP bytes',code==200 and body==f[kind]and a['digest']==digest(body)and a['size']==len(body))
  contract['reference_sha256'][label+'_'+kind]=a['digest'];contract['wire_sha256'][label+'_'+kind]=digest(body)

def consume(label,dep='dependency',who='reader',ok=True):
 f=fixtures[label];consumer=PRIVATE/('consumer-'+uuid.uuid4().hex);consumer.mkdir()
 (consumer/'go.mod').write_text('module go.cratectl.invalid/consumer\n\ngo 1.26.0\nrequire '+MODULE+' '+f['version']+'\n')
 netrc=private(consumer.name+'/netrc',('machine localhost login token password '+tokens[who]+'\n').encode())
 client_env=dict(public_env,GOENV='off',GOWORK='off',GOFLAGS='',GOTOOLCHAIN='local',GOTELEMETRY='off',GOINSECURE='',GOPROXY=BASE+'/go/owned/',GOPRIVATE='go.cratectl.invalid',GONOPROXY='none',GONOSUMDB='go.cratectl.invalid',GOSUMDB='sum.golang.org',GOVCS='*:off',GOAUTH='netrc',NETRC=str(netrc),SSL_CERT_FILE=str(INSTALL/'ca.crt'),GOMODCACHE=str(consumer/'module-cache'),GOPATH=str(consumer/'gopath'),GOCACHE=str(consumer/'build-cache'))
 output=command([GO,'mod','download','-json','all'],runenv=client_env,cwd=consumer,ok=ok)
 check(label+': stock Go fresh-cache '+('download' if ok else 'blocked'),True)
 if not ok:return
 records=[];decoder=json.JSONDecoder();tail=output.strip()
 while tail:
  record,end=decoder.raw_decode(tail);records.append(record);tail=tail[end:].lstrip()
 check(label+': exact transitive module set',len(records)==2 and {(r['Path'],r['Version'])for r in records}=={(f['module'],f['version']),(DEPENDENCY,'v1.0.0')})
 for r in records:
  name=label if r['Path']==MODULE else dep;source=fixtures[name]
  check(name+': native Go checksums present',not r.get('Error')and all(re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=',r[k])for k in ['Sum','GoModSum']))
  for kind,key in [('zip','Zip'),('mod','GoMod')]:
   path=Path(r[key]);check(name+': native cache path confined',path.is_relative_to(consumer/'module-cache')and path.is_file())
   data=path.read_bytes();check(name+' '+kind+': exact native cached bytes',data==source[kind]);contract['cached_sha256'][name+'_'+kind]=digest(data)
  info_path=Path(r['Info']);check(name+': native info path confined',info_path.is_relative_to(consumer/'module-cache')and info_path.is_file());info=json.loads(info_path.read_text());check(name+': native info identity',info['Version']==source['version']and info['Time']==INSTANT)

database='cratectl_go_'+RUN
try:
 if args.require_clean_build:check('clean exact candidate and both native binaries',not result['source_dirty']and result['build_source_matches_candidate'])
 observed=command([GO,'version']).strip();version=re.fullmatch(r'go version go(\d+\.\d+\.\d+) (linux|darwin|windows)/(amd64|arm64)',observed)
 pin=re.search(r'^go (\d+\.\d+\.\d+)$',Path('go.mod').read_text(),re.M).group(1)
 check('actual pinned native Go runtime',version is not None and version.group(1)==pin);contract['version']=version.group(1);contract['completed'].append(STAGES[0])
 owner=urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN']);with_database(env['CRATECTL_OWNER_DSN'],database)
 pgenv=dict(env,PGHOST=owner.hostname,PGPORT=str(owner.port),PGUSER=urllib.parse.unquote(owner.username),PGPASSWORD=urllib.parse.unquote(owner.password),PGDATABASE=owner.path.lstrip('/'))
 psql('CREATE DATABASE '+database);database_created=True
 initial_env=dict(env,CRATECTL_OWNER_DSN=with_database(env['CRATECTL_OWNER_DSN'],database),CRATECTL_DSN=with_database(env['CRATECTL_DSN'],database))
 command([BIN/'cratectld','init','--directory',INSTALL,'--tenant','go-team'],initial_env);tokens['admin']=(INSTALL/'admin.token').read_text().strip()
 for actor,role,tenant in [('publisher','writer','go-team'),('reader','reader','go-team'),('other','admin','go-other')]:
  p=PRIVATE/(actor+'.token');command([BIN/'cratectld','provision','--tenant',tenant,'--actor',actor,'--role',role,'--token-file',p],initial_env);tokens[actor]=p.read_text().strip()
 start();check('trusted TLS installation readiness',http('/api/v1/session')[0]==200)
 for who in ['admin','other']:check(who+': create hosted Go repository',http('/api/v1/repositories',who,'POST',{'name':'owned','format':'go','access':'restricted','require_review':who=='admin'})[0]==201)
 for actor,write in [('publisher',True),('reader',False)]:check(actor+': explicit repository grant',http('/api/v1/repositories/owned/grants',method='PUT',data={'actor':actor,'read':True,'write':write})[0]==200)
 writer_client=json.loads((INSTALL/'client.json').read_text());writer_client['token_file']=str(PRIVATE/'publisher.token');writer_config=private('writer.json',writer_client)
 dependency_zip=private('dependency.zip',fixtures['dependency']['zip'])
 cli_receipt=json.loads(command([BIN/'cratectl','--config',writer_config,'--method','PUT','--path','/go/owned/'+escaped(DEPENDENCY)+'/@v/v1.0.0.zip','--upload-file',dependency_zip,'--go-module-time',INSTANT]))
 check('CLI publishes complete Go bundle over trusted TLS',cli_receipt['version']=='v1.0.0'and cli_receipt['representations_sha256']['zip']==digest(fixtures['dependency']['zip']))
 contract['completed'].append(STAGES[1])
 for label in ['dependency','application_1','application_2']:publish(label)
 contract['completed'].append(STAGES[2])
 consume('application_1',ok=False);approve(only='.mod');approve(only='.info');consume('application_1',ok=False);approve(only='.zip')
 for label in ['dependency','application_1','application_2']:bind(label)
 consume('application_1');consume('application_2');contract['completed'].append(STAGES[3])
 original=publish('application_1');check('identical immutable retry retains original response',publish('application_1')==original)
 changed=fixture(MODULE,'v1.0.0','changed forbidden publication',DEPENDENCY);publish('application_1',expected=409,replace=changed['zip']);publish('application_1',who='reader',expected=403)
 check('native version list',http('/go/owned/'+escaped(MODULE)+'/@v/list')[1]==b'v1.0.0\nv1.1.0\n')
 check('latest names exact approved release',json.loads(http('/go/owned/'+escaped(MODULE)+'/@latest')[1])['Version']=='v1.1.0')
 contract['completed'].append(STAGES[4])
 for label in ['other_dependency','other_application']:publish(label,who='other');bind(label,who='other')
 consume('other_application',dep='other_dependency',who='other');consume('application_1');contract['completed'].append(STAGES[5])
 approve(decision='denied',only='.zip');consume('application_2',ok=False)
 check('denied ZIP also blocks exact metadata',http('/go/owned/'+escaped(MODULE)+'/@v/v1.1.0.mod')[0]==403)
 approve(only='.zip');stop();start();consume('application_2');contract['completed'].append(STAGES[6])
 stop();command([BIN/'cratectld','revoke','--token-file',PRIVATE/'publisher.token'],initial_env);start();publish('application_1',expected=401)
 stop();command([BIN/'cratectld','revoke','--token-file',PRIVATE/'reader.token'],initial_env);start();consume('application_2',ok=False);consume('other_application',dep='other_dependency',who='other')
 check('revoked reader exact metadata denied',http('/go/owned/'+escaped(MODULE)+'/@v/v1.1.0.info','reader')[0]==401)
 contract['completed'].append(STAGES[7]);check('every exact publisher/reference/wire identity retained',set(contract['publisher_sha256'])==FIXTURES and contract['publisher_sha256']==contract['reference_sha256']==contract['wire_sha256']);check('every exact stock cache identity retained',set(contract['cached_sha256'])==CACHED_FIXTURES and all(v==contract['wire_sha256'][k]for k,v in contract['cached_sha256'].items()))
 result['status']='passed';print('PASS: native Go hosted/TLS journey,',len(checks),'checks')
except BaseException as error:
 result['failure']=str(error)[:8192];result['last_observation']=commands[-1]if commands else None;result['status']='failed';print('FAIL: native Go hosted/TLS journey; bounded details remain private');raise
finally:
 stop()
 if database_created:
  try:psql('DROP DATABASE '+database);result['owned_database_cleanup']='passed'
  except Exception:result['owned_database_cleanup']='failed';result['status']='failed'
 (EVIDENCE/('go-module-'+RUN+'.json')).write_text(json.dumps(result,indent=2)+'\n')
 if result.get('owned_database_cleanup')=='failed':raise SystemExit('Owned Go fixture database cleanup failed')
