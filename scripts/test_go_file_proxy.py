#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Stock Go downloads owned file-proxy stand-ins; no registry, database or network."""
import ast,hashlib,json,os,re,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT)
sys.path.insert(0,str(ROOT/'scripts'))
from bounded_client import run_owned_client
source=Path('scripts/conformance_go.py');tree=ast.parse(source.read_text());nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom))or isinstance(n,ast.FunctionDef)and n.name in ['fixture','escaped']]
ns={'INSTANT':'2026-01-02T03:04:05Z'};exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),ns)
module='go.cratectl.invalid/Owned/application';dependency='go.cratectl.invalid/Owned/dependency';fixture=ns['fixture'];escaped=ns['escaped']
go=str(Path('.cache/go/bin/go').resolve())if Path('.cache/go/bin/go').is_file()else shutil.which('go')
if not go:raise SystemExit('Native Go toolchain is required; this stand-in is not a skip')
observed=subprocess.check_output([go,'version'],text=True).strip();pin=re.search(r'^go (\d+\.\d+\.\d+)$',Path('go.mod').read_text(),re.M).group(1)
assert observed.startswith('go version go'+pin+' '),observed
Path('.cache').mkdir(exist_ok=True)
temporary=tempfile.TemporaryDirectory(prefix='cratectl-go-file-proxy-',dir='.cache');root=Path(temporary.name).resolve()
all_results=[]
for tenant in ['a','b']:
 proxy=root/tenant/'proxy';proxy.mkdir(parents=True)
 fixtures={'dependency':fixture(dependency,'v1.0.0','owned '+tenant+' dependency'),'application_1':fixture(module,'v1.0.0','owned '+tenant+' application one',dependency),'application_2':fixture(module,'v1.1.0','owned '+tenant+' application two',dependency)}
 for f in fixtures.values():
  p=proxy/escaped(f['module'])/'@v';p.mkdir(parents=True,exist_ok=True)
  for kind in ['zip','mod','info']:(p/(f['version']+'.'+kind)).write_bytes(f[kind])
 for label in ['application_1','application_2']:
  f=fixtures[label];consumer=root/tenant/label;consumer.mkdir();(consumer/'go.mod').write_text('module go.cratectl.invalid/consumer\n\ngo 1.26.0\nrequire '+module+' '+f['version']+'\n')
  env={k:v for k,v in os.environ.items()if k not in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']}
  env.update(GOENV='off',GOWORK='off',GOFLAGS='',GOTOOLCHAIN='local',GOTELEMETRY='off',GOINSECURE='',GOPROXY=proxy.as_uri(),GOPRIVATE='go.cratectl.invalid',GONOPROXY='none',GONOSUMDB='go.cratectl.invalid',GOSUMDB='sum.golang.org',GOVCS='*:off',GOAUTH='off',GOMODCACHE=str(consumer/'module-cache'),GOPATH=str(consumer/'gopath'),GOCACHE=str(consumer/'build-cache'))
  code,output=run_owned_client([go,'mod','download','-json','all'],consumer,env,timeout=60,output_limit=2<<20,capture_limit=2<<20)
  (consumer/'output.txt').write_text(output)
  assert code==0,(tenant,label,code,output[-3000:])
  records=[];decoder=json.JSONDecoder();tail=output.strip()
  while tail:r,end=decoder.raw_decode(tail);records.append(r);tail=tail[end:].lstrip()
  assert {(r['Path'],r['Version'])for r in records}=={(module,f['version']),(dependency,'v1.0.0')}
  for r in records:
   expected=f if r['Path']==module else fixtures['dependency']
   assert not r.get('Error')
   for kind,key in [('zip','Zip'),('mod','GoMod')]:assert Path(r[key]).read_bytes()==expected[kind],(tenant,label,kind)
   info=json.loads(Path(r['Info']).read_bytes());assert info['Version']==expected['version'] and info['Time']==ns['INSTANT']
  all_results.append({'standin_namespace':tenant,'application':label,'modules':len(records),'cached_zip_mod_bytes_match':True,'info_version_time_match':True,'publisher_sha256':{name+'_'+kind:hashlib.sha256(value[kind]).hexdigest()for name,value in [('application',f),('dependency',fixtures['dependency'])]for kind in ['zip','mod','info']}})
print(json.dumps({'status':'passed; native stock-Go against owned file-proxy stand-ins only','go':subprocess.check_output([go,'version'],text=True).strip(),'go_binary_sha256':hashlib.sha256(Path(go).read_bytes()).hexdigest(),'fixture_source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'results':all_results,'limits':['No HTTP, TLS, database, registry publication, policy, restart or revocation proof. Actual native GitHub jobs remain mandatory.','Only inert owned module fixture bytes were downloaded/extracted; no package code was compiled or executed.']},indent=2))

temporary.cleanup()
