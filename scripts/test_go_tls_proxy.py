#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Run the actual Go consumer against an owned TLS/auth stand-in, without a DB."""
import base64,hashlib,http.server,json,os,re,shutil,ssl,subprocess,tempfile,threading,urllib.parse
from pathlib import Path
from test_go_module_profile import helpers

ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT)
go=ROOT/'.cache/go/bin/go'
if not go.is_file():
 executable=shutil.which('go')
 if not executable:raise SystemExit('Native Go is required; TLS/auth stand-in cannot be skipped')
 go=Path(executable)
observed=subprocess.check_output([str(go),'version'],text=True).strip()
pin=re.search(r'^go (\d+\.\d+\.\d+)$',(ROOT/'go.mod').read_text(),re.M).group(1)
assert observed.startswith('go version go'+pin+' '),'Actual pinned native Go required'
mask=os.umask(0o077)
try:
 private_root=ROOT/'.private';private_root.mkdir(mode=0o700,exist_ok=True)
 if private_root.is_symlink()or private_root.stat().st_mode&0o777!=0o700:raise SystemExit('Owned .private must be an unlinked0700directory')
 with tempfile.TemporaryDirectory(prefix='cratectl-go-tls-',dir=ROOT/'.private')as directory:
  root=Path(directory);install=root/'installation';install.mkdir(mode=0o700)
  cert=install/'ca.crt';key=install/'server.key'
  generated=subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],capture_output=True,timeout=30)
  if generated.returncode:raise SystemExit('Owned TLS stand-in certificate creation failed')
  ns=helpers();ns.update(ROOT=ROOT,GO=go,PRIVATE=root,INSTALL=install,public_env={k:v for k,v in os.environ.items()if k not in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']},contract={'cached_sha256':{}})
  ns['fixtures']={'application_1':ns['fixture'](ns['MODULE'],'v1.0.0','owned TLS application',ns['DEPENDENCY']),'dependency':ns['fixture'](ns['DEPENDENCY'],'v1.0.0','owned TLS dependency')}
  files={}
  for f in ns['fixtures'].values():
   for kind in ['zip','mod','info']:files['/go/owned/'+ns['escaped'](f['module'])+'/@v/'+f['version']+'.'+kind]=f[kind]
  expected='Basic '+base64.b64encode(('token:'+ns['tokens']['reader']).encode()).decode()
  requests={'authorized':0,'unauthorized':0}
  gate_status=404;gate_list_status=200;fallback_requests=0
  class Handler(http.server.BaseHTTPRequestHandler):
   def do_GET(self):
    if self.headers.get('Authorization')!=expected:
     requests['unauthorized']+=1;self.send_response(401);self.send_header('WWW-Authenticate','Basic realm="owned-go-stand-in"');self.send_header('Content-Length','0');self.end_headers();return
    global fallback_requests
    requests['authorized']+=1;url=urllib.parse.urlsplit(self.path);path=urllib.parse.unquote(url.path)
    if path.startswith('/gate/'):
     status=gate_list_status if path.endswith('/@v/list')else gate_status;body=b''if status==200 else b'Owned policy/source gate\n'
     self.send_response(status);self.send_header('Content-Type','text/plain; charset=utf-8');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);return
    if path.startswith('/fallback/'):
     fallback_requests+=1;path='/go/owned/'+path.removeprefix('/fallback/')
    data=files.get(path)if not url.query else None
    if path.endswith('/@latest'):data=ns['fixtures']['application_1']['info']
    if path.endswith('/@v/list'):data=b'v1.0.0\n'
    self.send_response(200 if data is not None else 404);self.send_header('Content-Length',str(len(data or b'')));self.end_headers()
    if data is not None:self.wfile.write(data)
   def log_message(self,*args):pass
  server=http.server.ThreadingHTTPServer(('127.0.0.1',38443),Handler)
  context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(cert,key);server.socket=context.wrap_socket(server.socket,server_side=True)
  thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  wrong_machine=True
  def private(name,data):
   if name.endswith('/netrc')and wrong_machine:data=data.replace(b'localhost:38443',b'localhost')
   path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o600);return path
  ns['private']=private
  try:
   ns['consume']('application_1',ok=False)
   assert requests['unauthorized']>0 and requests['authorized']==0,'Hostname-only NETRC unexpectedly authorized a nondefault port'
   wrong_machine=False
   ns['consume']('application_1')
   assert requests['authorized']>=6,'Pinned Go did not request all six transitive representations'
   assert set(ns['contract']['cached_sha256'])=={'application_1_zip','application_1_mod','dependency_zip','dependency_mod'}
   hosted_requests=dict(requests)
   fallback_cases=[]
   for status,list_status,success in [(404,200,False),(404,404,True),(403,200,False)]:
    gate_status=status;gate_list_status=list_status;before=fallback_requests;consumer=root/('fallback-'+str(status)+'-'+str(list_status));consumer.mkdir()
    (consumer/'go.mod').write_text('module go.cratectl.invalid/fallback-consumer\n\ngo 1.26.0\n')
    netrc=private(consumer.name+'/netrc',('machine localhost:38443 login token password '+ns['tokens']['reader']+'\n').encode())
    env=dict(ns['public_env'],GOENV='off',GOWORK='off',GOFLAGS='',GOTOOLCHAIN='local',GOTELEMETRY='off',GOINSECURE='',GOPROXY='https://localhost:38443/gate/,https://localhost:38443/fallback/',GOPRIVATE='go.cratectl.invalid',GONOPROXY='none',GONOSUMDB='go.cratectl.invalid',GOSUMDB='sum.golang.org',GOVCS='*:off',GOAUTH='netrc',NETRC=str(netrc),SSL_CERT_FILE=str(cert),GOMODCACHE=str(consumer/'module-cache'),GOPATH=str(consumer/'gopath'),GOCACHE=str(consumer/'build-cache'))
    output=ns['command']([go,'list','-m','-json',ns['MODULE']+'@latest'],runenv=env,cwd=consumer,ok=success)
    contacts=fallback_requests-before
    if success:
     observed_module=json.loads(output);assert contacts>0 and observed_module['Path']==ns['MODULE']and observed_module['Version']=='v1.0.0','404 positive control did not exercise native fallback'
    else:
     assert contacts==0,'Terminal policy/empty-list response contacted the lower proxy'
     if status==404:assert 'no matching versions'in output,'Original empty-list behavior changed'
    fallback_cases.append({'primary_latest_status':status,'primary_list_status':list_status,'lower_proxy_requests':contacts,'expected_outcome_observed':True})
  except BaseException:
   observations=[]
   for command in ns['commands']:
    raw=(ROOT/command['private_log']).read_bytes()
    observations.append({'exit':command['exit'],'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'unauthorized':b'401 Unauthorized'in raw,'not_found':b'404 Not Found'in raw,'tls_error':b'x509:'in raw})
   print(json.dumps({'status':'failed owned TLS/auth stand-in','requests':requests,'commands':observations}),flush=True)
   raise
  finally:
   server.shutdown();server.server_close();thread.join(timeout=5)
  print(json.dumps({'status':'passed; actual Go consumer against owned HTTPS/auth stand-in only','go':observed,'go_binary_sha256':hashlib.sha256(go.read_bytes()).hexdigest(),'fixture_source_sha256':hashlib.sha256((ROOT/'scripts/conformance_go.py').read_bytes()).hexdigest(),'hostname_only_denied':True,'exact_host_port_authorized':True,'requests':hosted_requests,'cached_byte_bindings':len(ns['contract']['cached_sha256']),'comma_proxy_fallback_cases':fallback_cases,'limits':['No registry/PostgreSQL/publication/current-policy/restart/revocation proof; actual native GitHub jobs remain mandatory.','Generated CA/NETRC/command streams remain in one private owned temporary directory; no insecure TLS, URL credentials, VCS/direct/public package fallback or package execution.','Two owned same-authority proxy paths deliberately exercise comma fallback. The registry qualification client still uses one sole proxy; these controls do not establish real registry denial behavior.']},indent=2))
finally:
 os.umask(mask)
