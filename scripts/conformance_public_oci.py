# SPDX-License-Identifier: BUSL-1.1
"""Bounded real-provider OCI proof. Retain exact opaque bytes; never run an image."""
import argparse,hashlib,json,os,platform,re,subprocess,time,urllib.error,urllib.parse,urllib.request,uuid
from pathlib import Path
from qualification_contract import candidate_binary_directory, candidate_artifact_names
BIN = candidate_binary_directory()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT)
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--registry',required=True,help='Explicit HTTPS registry native base, without credentials or query')
parser.add_argument('--image',required=True)
parser.add_argument('--digest',required=True,help='Immutable SHA-256 manifest digest, not a mutable tag/index')
parser.add_argument('--token-realm',required=True)
parser.add_argument('--service',required=True)
parser.add_argument('--delivery-base',action='append',default=[],help='Explicit documented HTTPS delivery authority/base; repeat for each approved source')
parser.add_argument('--source-document',required=True,help='Official provider documentation supporting the configured authorities')
parser.add_argument('--require-clean-build',action='store_true')
args=parser.parse_args()
for raw in [args.registry,args.token_realm,args.source_document,*args.delivery_base]:
 parsed=urllib.parse.urlsplit(raw)
 if parsed.scheme!='https'or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:parser.error('Provider base URLs must be HTTPS without userinfo/query/fragment')
if not re.fullmatch(r'sha256:[a-f0-9]{64}',args.digest):parser.error('An immutable SHA-256 manifest digest is required')
if not re.fullmatch(r'[a-z0-9][a-z0-9._/-]{0,250}',args.image)or'..'in args.image:parser.error('Use a bounded native image path')
RUN=uuid.uuid4().hex[:10];PRIVATE=ROOT/'.private/public-oci'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
EVIDENCE=ROOT/'evidence/2026-10-28';EVIDENCE.mkdir(exist_ok=True)
BASE='http://127.0.0.1:38443';source_scope=['cmd','internal','scripts','api','go.mod','go.sum','Makefile']
checks=[];commands=[];token='';proc=None;log=None

def identity(name):
 output=subprocess.check_output([str(ROOT/'.cache/go/bin/go'),'version','-m',str(ROOT/name)],text=True);settings={}
 for line in output.splitlines():
  fields=line.strip().split('\t')
  if len(fields)==2 and fields[0]=='build'and'='in fields[1]:key,value=fields[1].split('=',1);settings[key]=value
 return {'go_version':output.splitlines()[0].split()[-1],'settings':settings}

result={'run':RUN,'candidate':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'source_scope':source_scope,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*source_scope],text=True).strip()),'artifact_digests':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()for name in candidate_artifact_names()},'build_identity':{name:identity(name)for name in candidate_artifact_names()},'host':platform.platform(),'database_profile':os.environ.get('CRATECTL_DEV_DATABASE','container'),'topology':'native process on HTTP loopback 38443, real PostgreSQL runtime/owner roles, filesystem CAS; HTTPS public registry/realm/CDN','source':{'registry':args.registry,'image':args.image,'manifest_digest':args.digest,'token_realm':args.token_realm,'service':args.service,'delivery_bases':args.delivery_base,'documentation':args.source_document},'checks':checks,'commands':commands,'limits':['One explicitly pinned public image and one configured provider combination; no full format, security or readiness verdict.','Image bytes are copied into private OCI layouts and never executed or extracted.','No Docker/Podman engine, private PKI, every provider/platform, lifecycle, HA, fault or scale qualification.']}
result['build_source_matches_candidate']=all(v['settings'].get('vcs.revision')==result['candidate']and v['settings'].get('vcs.modified')=='false'for v in result['build_identity'].values())

def check(name,condition):
 if not condition:raise AssertionError(name)
 checks.append(name)

def run(argv,stdin=None,expected_failure=False):
 command=subprocess.run([str(x)for x in argv],input=stdin,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
 output=command.stdout.replace(token,'[REDACTED]')if token else command.stdout
 commands.append({'argv':[str(x).replace(str(PRIVATE),'PRIVATE')for x in argv],'exit':command.returncode,'output':output[-8000:],'expected_failure':expected_failure})
 if expected_failure:
  if command.returncode==0:raise AssertionError('Denied native copy unexpectedly succeeded')
 elif command.returncode:raise AssertionError('Owned native command failed: '+str(argv[0]))
 return output

def request(path,method='GET',data=None):
 headers={'Authorization':'Bearer '+token}
 if isinstance(data,dict):data=json.dumps(data).encode();headers['Content-Type']='application/json';headers['Idempotency-Key']=uuid.uuid4().hex
 req=urllib.request.Request(BASE+path,data=data,headers=headers,method=method)
 try:
  with urllib.request.urlopen(req,timeout=30)as response:return response.status,response.read()
 except urllib.error.HTTPError as error:return error.code,error.read()

def stop():
 global proc,log
 if proc is not None:proc.terminate();proc.wait(timeout=15);proc=None
 if log:log.close();log=None

def start():
 global proc,log
 fd=os.open(PRIVATE/'server.log',os.O_CREAT|os.O_WRONLY|os.O_APPEND,0o600);log=os.fdopen(fd,'a')
 proc=subprocess.Popen([str(BIN/'cratectld'),'serve','--listen','127.0.0.1:38443','--public-url',BASE,'--dev-loopback-http','--objects',str(PRIVATE/'objects'),'--oci-graph-bytes',str(16<<20)],stdout=log,stderr=subprocess.STDOUT)
 for _ in range(100):
  if proc.poll()is not None:raise AssertionError('Owned registry failed to start; private server log retained')
  try:
   with urllib.request.urlopen(BASE+'/health/ready',timeout=1)as response:
    if response.status==200:return
  except Exception:time.sleep(.05)
 raise AssertionError('Owned registry readiness timeout')

def cache(path,repo='public-proxy'):
 code,body=request('/api/v1/repositories/'+repo+'/cache?'+urllib.parse.urlencode({'path':path}))
 if code!=200:raise AssertionError('Canonical provider cache state unavailable')
 return json.loads(body)

try:
 if args.require_clean_build:
  check('qualification source is clean',not result['source_dirty'])
  check('qualification binaries embed exact clean source commit',result['build_source_matches_candidate'])
 if not os.environ.get('CRATECTL_DSN')or not os.environ.get('CRATECTL_OWNER_DSN'):raise AssertionError('Owned PostgreSQL runtime and owner configuration required')
 token_file=PRIVATE/'admin.token';run([BIN/'cratectld','provision','--tenant','proof-public-'+RUN,'--actor','qualification','--role','admin','--token-file',token_file]);token=token_file.read_text().strip()
 start()
 settings={'upstream':{'url':args.registry,'networks':['0.0.0.0/0','::/0']},'oci_token_endpoint':{'url':args.token_realm,'networks':['0.0.0.0/0','::/0']},'oci_token_service':args.service,'download_sources':[{'url':base,'networks':['0.0.0.0/0','::/0'],'allow_signed_query':True}for base in args.delivery_base],'cache':{'fresh_seconds':60,'negative_seconds':30,'stale_seconds':0}}
 check('create bounded public OCI proxy',request('/api/v1/repositories','POST',{'name':'public-proxy','format':'oci','mode':'proxy','settings':settings})[0]==201)
 check('create governed public OCI group',request('/api/v1/repositories','POST',{'name':'public-group','format':'oci','mode':'group','settings':{'members':['public-proxy']}})[0]==201)
 oras=ROOT/'.cache/bin/oras';auth=PRIVATE/'registry.json';result['oras_version']=run([oras,'version']).strip()
 run([oras,'login','--plain-http','--registry-config',auth,'--username','token','--password-stdin','127.0.0.1:38443'],token+'\n');auth.chmod(0o600)
 graph=None
 def copy(repo,label,expected_failure=False):
  global graph
  layout=PRIVATE/label
  run([oras,'copy','--from-plain-http','--from-registry-config',auth,'--to-oci-layout','127.0.0.1:38443/'+repo+'/'+args.image+'@'+args.digest,str(layout)+':proof'],expected_failure=expected_failure)
  if expected_failure:return
  manifest=(layout/'blobs/sha256'/args.digest.removeprefix('sha256:')).read_bytes()
  check(label+': immutable root bytes match pinned digest','sha256:'+hashlib.sha256(manifest).hexdigest()==args.digest)
  parsed=json.loads(manifest);descriptors=[parsed['config'],*parsed['layers']]
  check(label+': complete native image graph',bool(descriptors)and all(re.fullmatch(r'sha256:[a-f0-9]{64}',d['digest'])for d in descriptors))
  for descriptor in descriptors:
   data=(layout/'blobs/sha256'/descriptor['digest'].removeprefix('sha256:')).read_bytes()
   check(label+': exact opaque blob '+descriptor['digest'],len(data)==descriptor['size']and'sha256:'+hashlib.sha256(data).hexdigest()==descriptor['digest'])
   if descriptor['digest']==parsed['config']['digest']:
    image=json.loads(data);observed={key:image.get(key)for key in ['os','architecture']}
    check(label+': bounded image platform metadata',all(isinstance(value,str)and 0<len(value)<=64 for value in observed.values()))
    result['image_platform']=observed
  graph=parsed
 root_path=args.image+'/manifests/'+args.digest
 if args.delivery_base:
  denied_settings={**settings,'download_sources':[{**source,'allow_signed_query':False}for source in settings['download_sources']]}
  check('create real-provider signed-query negative control',request('/api/v1/repositories','POST',{'name':'public-query-denied','format':'oci','mode':'proxy','settings':denied_settings})[0]==201)
  copy('public-query-denied','query-denied-layout',True)
  check('real provider requires explicitly approved signed delivery',cache(root_path,'public-query-denied')['last_error']=='upstream_authority_failure')
  code,body=request('/api/v1/repositories/public-query-denied/artifacts')
  check('real-provider query rejection publishes no partial graph',code==200 and json.loads(body)['items']==[])
  result['signed_delivery_negative_control']=True
 copy('public-proxy','proxy-layout');first=cache(root_path)
 copy('public-group','group-layout');check('fresh group uses the same canonical cache generation',cache(root_path)['generation']==first['generation'])
 stop();start();copy('public-group','restart-layout');check('exact pinned cache survives native process restart',cache(root_path)['generation']==first['generation'])
 layer=graph['layers'][0];member_path=args.image+'/blobs/'+layer['digest']
 check('public provider member invalidation is authorized',request('/api/v1/repositories/public-proxy/cache','PUT',{'path':member_path})[0]==200)
 invalidated=cache(member_path);copy('public-group','refresh-layout')
 check('member refresh retrieves a current public source graph',cache(member_path)['generation']>invalidated['generation']and cache(root_path)['generation']>first['generation'])
 check('explicit digest denial is recorded',request('/api/v1/repositories/public-proxy/decisions','PUT',{'path':root_path,'digest':args.digest.removeprefix('sha256:'),'decision':'denied'})[0]==200)
 copy('public-group','denied-layout',True)
 check('current policy blocks pinned source and group',request('/v2/public-proxy/'+root_path)[0]==403 and request('/v2/public-group/'+root_path)[0]==403)
 clean=lambda descriptor:{key:descriptor[key]for key in ['mediaType','digest','size']}
 result['graph']={'media_type':graph['mediaType'],'manifest_digest':args.digest,'config':clean(graph['config']),'layers':[clean(layer)for layer in graph['layers']]}
 result['status']='passed';print('PASS:',len(checks),'assertions; pinned public OCI provider proof')
except Exception as error:
 result['status']='failed';result['failure_type']=type(error).__name__
 # Exception strings from arbitrary HTTP clients can contain request URIs.
 result['failure']=str(error)if isinstance(error,AssertionError)else'Qualification stopped; inspect retained private logs and typed failure.'
 print('FAIL:',result['failure']);raise SystemExit(1)
finally:
 stop();target=EVIDENCE/('public-oci-'+RUN+'.json');target.write_text(json.dumps(result,indent=2)+'\n');print('Evidence:',target)
