#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Exercise the actual Go journey helpers with owned stand-ins, without a Go client or DB."""
import ast,json,os,tempfile,unittest,zipfile,io
from pathlib import Path

SCRIPT=Path(__file__).with_name('conformance_go.py')
def helpers():
 tree=ast.parse(SCRIPT.read_text());body=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom))or isinstance(n,ast.FunctionDef)and n.name in ['fixture','escaped','digest','check','consume','command']]
 ns={'public_env':{},'ROOT':Path(__file__).resolve().parents[1]};exec(compile(ast.Module(body=body,type_ignores=[]),str(SCRIPT),'exec'),ns)
 ns.update(INSTANT='2026-01-02T03:04:05Z',MODULE='go.cratectl.invalid/Owned/application',DEPENDENCY='go.cratectl.invalid/Owned/dependency',BASE='https://localhost:38443',GO=Path('/owned/go'),public_env={},checks=[],tokens={'reader':'owned-synthetic-reader'},commands=[])
 return ns
class GoModuleProfile(unittest.TestCase):
 def test_actual_fixture_prefix_and_dependency_identity(self):
  ns=helpers();f=ns['fixture'](ns['MODULE'],'v1.0.0','opaque fixture',ns['DEPENDENCY'])
  self.assertEqual(ns['escaped'](ns['MODULE']),'go.cratectl.invalid/!owned/application')
  with zipfile.ZipFile(io.BytesIO(f['zip']))as z:
   self.assertIsNone(z.testzip());self.assertEqual(set(z.namelist()),{ns['MODULE']+'@v1.0.0/go.mod',ns['MODULE']+'@v1.0.0/assets/owned.txt'})
   self.assertEqual(z.read(ns['MODULE']+'@v1.0.0/go.mod'),f['mod'])
  self.assertIn(('require '+ns['DEPENDENCY']+' v1.0.0').encode(),f['mod'])
  self.assertEqual(json.loads(f['info']),{'Version':'v1.0.0','Time':ns['INSTANT']})
 def test_actual_consumer_requires_exact_cache_bytes_and_no_fallback(self):
  for fault in [None,'bytes','extra-module','outside-cache','info']:
   with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix='cratectl-go-profile-')as directory:
    ns=helpers();root=Path(directory);ns.update(PRIVATE=root,INSTALL=root/'installation',contract={'cached_sha256':{}})
    ns['fixtures']={'application_1':ns['fixture'](ns['MODULE'],'v1.0.0','app',ns['DEPENDENCY']),'dependency':ns['fixture'](ns['DEPENDENCY'],'v1.0.0','dependency')}
    def private(name,data):
     p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(0o600);return p
    ns['private']=private
    def command(argv,runenv,cwd,ok):
     self.assertTrue(ok);self.assertEqual(argv[1:],['mod','download','-json','all'])
     for key,value in {'GOENV':'off','GOWORK':'off','GOTOOLCHAIN':'local','GOAUTH':'netrc','GOINSECURE':'','GOPROXY':'https://localhost:38443/go/owned/','GONOPROXY':'none','GONOSUMDB':'go.cratectl.invalid','GOSUMDB':'sum.golang.org','GOVCS':'*:off'}.items():self.assertEqual(runenv[key],value)
     self.assertEqual(Path(runenv['NETRC']).stat().st_mode&0o077,0)
     cache=Path(runenv['GOMODCACHE']);cache.mkdir();records=[]
     for label,f in ns['fixtures'].items():
      r={'Path':f['module'],'Version':f['version'],'Sum':'h1:'+'a'*43+'=','GoModSum':'h1:'+'b'*43+'='}
      for kind,key in [('zip','Zip'),('mod','GoMod'),('info','Info')]:
       p=(root if fault=='outside-cache'else cache)/(label+'.'+kind);p.write_bytes(b'wrong bytes'if fault=='bytes'and kind=='zip'else f[kind]);r[key]=str(p)
      if fault=='info':Path(r['Info']).write_text(json.dumps({'Version':f['version'],'Time':'2026-01-03T03:04:05Z'}))
      records.append(r)
     if fault=='extra-module':records.append({'Path':'public.invalid/hidden','Version':'v9.0.0'})
     return '\n'.join(json.dumps(r)for r in records)
    ns['command']=command
    if fault:
     with self.assertRaises(AssertionError):ns['consume']('application_1')
    else:
     ns['consume']('application_1');self.assertEqual(set(ns['contract']['cached_sha256']),{'application_1_zip','application_1_mod','dependency_zip','dependency_mod'})
 def test_expected_native_failure_cannot_pass_with_zero_exit(self):
  with tempfile.TemporaryDirectory(prefix='cratectl-go-command-')as directory:
   ns=helpers();ns['PRIVATE']=Path(directory);ns['ROOT']=Path(directory)
   for code in [0,-9,2]:
    ns['run_owned_client']=lambda *a,**k:(code,'owned command stand-in')
    with self.assertRaises(AssertionError):ns['command'](['/owned/go'],ok=False)
 def test_deadline_stream_is_preserved_in_a_private_owned_log(self):
  with tempfile.TemporaryDirectory(prefix='cratectl-go-stream-')as directory:
   ns=helpers();root=Path(directory);ns.update(PRIVATE=root,ROOT=root)
   def fail(*args,**kwargs):
    kwargs['output_sink'].write(b'owned partial stream before deadline')
    raise RuntimeError('owned deadline stand-in')
   ns['run_owned_client']=fail
   with self.assertRaises(RuntimeError):ns['command'](['/owned/go'])
   record=ns['commands'][-1];self.assertIsNone(record['exit'])
   p=root/record['private_log'];self.assertEqual(p.read_bytes(),b'owned partial stream before deadline')
   self.assertEqual(p.stat().st_mode&0o777,0o600)
   self.assertNotIn('partial stream',json.dumps(record))
if __name__=='__main__':unittest.main()
