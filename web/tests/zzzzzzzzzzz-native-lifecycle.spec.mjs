// SPDX-License-Identifier: BUSL-1.1
import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';

test('native materialized references retain holds, reject corrupt restore and preserve current authority',async({page,browser,request})=>{
 const fixture=JSON.parse(await fs.readFile(process.env.CRATECTL_CONSOLE_FIXTURE_JSON,'utf8'));
 const token=(await fs.readFile(fixture.native_admin_token,'utf8')).trim(),reader=(await fs.readFile(fixture.native_reader_token,'utf8')).trim(),writer=(await fs.readFile(fixture.native_writer_token,'utf8')).trim();
 const checks=[],accessibility=[],reason='Owned native <script>window.nativeLifecycleLeak=true</script> review';
 const api=(url,options={},credential=token)=>request.fetch(fixture.base_url+url,{...options,headers:{Authorization:'Bearer '+credential,'Idempotency-Key':'native-browser-'+crypto.randomUUID(),...options.headers}});
 async function axe(state){const a=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();expect(a.violations).toEqual([]);accessibility.push({state,violations:0})}
 async function login(file){await page.goto(fixture.base_url+'/console/');await page.getByLabel('Credential file').setInputFiles(file);await page.waitForFunction(()=>document.querySelector('#credential')?.value.length>=32);await page.getByRole('button',{name:'Connect to installation',exact:true}).click();await expect(page.getByRole('heading',{name:'Repositories',exact:true})).toBeVisible()}
 async function openRepository(name){await page.getByRole('link',{name:'Repositories',exact:true}).click();await page.getByRole('searchbox',{name:'Search repositories',exact:true}).fill(name);await page.getByRole('button',{name:'Search',exact:true}).click();await page.getByRole('link',{name,exact:true}).click();await expect(page.getByRole('heading',{name:'Packages',exact:true})).toBeVisible()}
 async function preview(action){await page.getByLabel('Action',{exact:true}).selectOption(action);await page.getByLabel('Reason',{exact:true}).fill(reason);await page.getByRole('button',{name:'Preview impact',exact:true}).click();await expect(page.getByText(/Previewed revision/)).toBeVisible()}
 async function apply(action){await page.getByRole('button',{name:'Apply '+action,exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0)}
 const source=path.join(fixture.private,'native-browser-inputs');await fs.mkdir(source,{mode:0o700});
 const pyName='cratectl_native_ui_'+fixture.run,pkgName='cratectl-native-ui-'+fixture.run;
 const create=String.raw`import base64,csv,hashlib,io,json,pathlib,sys,tarfile,zipfile
root=pathlib.Path(sys.argv[1]);pyname=sys.argv[2];npmname=sys.argv[3]
manifest=json.dumps({'name':npmname,'version':'1.0.0','main':'index.js'}).encode()
with tarfile.open(root/'package.tgz','w:gz') as archive:
 for name,data in [('package/package.json',manifest),('package/index.js',b'module.exports=42;\n')]:
  info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
dist=pyname+'-1.0.0.dist-info'
files={pyname+'/__init__.py':b'value=42\n',dist+'/METADATA':('Metadata-Version: 2.4\nName: '+pyname.replace('_','-')+'\nVersion: 1.0.0\n\n').encode(),dist+'/WHEEL':b'Wheel-Version: 1.0\nGenerator: cratectl-browser\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
record=io.StringIO();writer=csv.writer(record,lineterminator='\n')
for name,data in files.items():writer.writerow([name,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('='),len(data)])
writer.writerow([dist+'/RECORD','','']);files[dist+'/RECORD']=record.getvalue().encode()
with zipfile.ZipFile(root/(pyname+'-1.0.0-py3-none-any.whl'),'w',zipfile.ZIP_DEFLATED)as archive:
 for name,data in files.items():archive.writestr(name,data)
with zipfile.ZipFile(root/'native-ui-1.0.0.jar','w')as archive:archive.writestr('fixture.txt','Owned native browser bytes')
`;
 execFileSync(path.join(fixture.root,'.cache/clients/bin/python'),['-c',create,source,pyName,pkgName],{stdio:'pipe',timeout:15000});
 const tenant=(await(await api('/api/v1/session')).json()).tenant;
 try{
  await login(fixture.native_admin_token);
  for(const format of ['generic','maven','npm','pypi']){
   const name='native-ui-'+format+'-'+fixture.run;
   expect((await api('/api/v1/repositories',{method:'POST',data:{name,format}})).status()).toBe(201);
   let reference,bytes,native;
   if(format==='npm'){
    bytes=await fs.readFile(path.join(source,'package.tgz'));reference=pkgName+'/-/'+pkgName+'-1.0.0.tgz';native='/npm/'+name+'/'+reference;
    expect((await api('/npm/'+name+'/'+pkgName,{method:'PUT',data:{name:pkgName,versions:{'1.0.0':{name:pkgName,version:'1.0.0'}},'dist-tags':{latest:'1.0.0'},_attachments:{[pkgName+'-1.0.0.tgz']:{data:bytes.toString('base64'),length:bytes.length}}}})).status()).toBe(201);
   }else if(format==='pypi'){
    reference=pyName+'-1.0.0-py3-none-any.whl';bytes=await fs.readFile(path.join(source,reference));native='/pypi/'+name+'/files/'+reference;
    const response=await api('/pypi/'+name+'/',{method:'POST',multipart:{name:pyName.replaceAll('_','-'),version:'1.0.0',content:{name:reference,mimeType:'application/octet-stream',buffer:bytes}}});expect([200,201]).toContain(response.status());
   }else{
    reference=format==='maven'?'org/example/native-ui/1.0.0/native-ui-1.0.0.jar':'package.bin';bytes=format==='maven'?await fs.readFile(path.join(source,'native-ui-1.0.0.jar')):Buffer.from('Owned generic native browser bytes');native='/r/'+name+'/'+reference;
    expect((await api(native,{method:'PUT',data:bytes,headers:{'Content-Type':'application/octet-stream'}})).status()).toBe(201);
    if(format==='maven')expect((await api('/r/'+name+'/org/example/native-ui/maven-metadata.xml',{method:'PUT',data:'<metadata><groupId>org.example</groupId><artifactId>native-ui</artifactId><versioning><versions><version>1.0.0</version></versions></versioning></metadata>'})).status()).toBe(201);
   }
   const digest=createHash('sha256').update(bytes).digest('hex'),endpoint='/api/v1/repositories/'+name+'/artifacts/lifecycle';
   const state=async()=>(await(await api(endpoint+'?'+new URLSearchParams({path:reference}))).json());
   const row=()=>page.getByRole('row').filter({has:page.getByRole('button',{name:'Inspect',exact:true})}).filter({hasText:reference});
   const open=async()=>{await row().getByRole('button',{name:'Lifecycle',exact:true}).click();await expect(page.getByText(/Current state:/)).toBeVisible()};
   await openRepository(name);await expect(row().getByRole('button',{name:'Lifecycle',exact:true})).toBeVisible();await axe(format+' materialized package inventory');
   if(format==='maven')await expect(page.getByRole('row').filter({hasText:'org/example/native-ui/maven-metadata.xml'}).getByRole('button',{name:'Lifecycle',exact:true})).toHaveCount(0);
   await open();await expect(page.getByLabel('Action',{exact:true})).toBeFocused();await preview('hold');await axe(format+' exact native hold preview');await apply('hold');
   expect((await state()).held).toBe(true);expect((await api(native)).status()).toBe(200);
   await open();await preview('delete');await expect(page.getByRole('button',{name:'Apply delete',exact:true})).toHaveCount(0);await axe(format+' held deletion blocked');await page.keyboard.press('Escape');
   await open();await preview('release_hold');await apply('release hold');
   if(format==='generic'){
    await open();await preview('delete');const current=await state();expect((await api(endpoint,{method:'PUT',data:{path:reference,digest,expected_revision:current.revision,action:'hold',reason:'Concurrent current preservation'}})).status()).toBe(200);
    await page.getByRole('button',{name:'Apply delete',exact:true}).click();await expect(page.getByRole('alert').getByText('Request rejected',{exact:true})).toBeVisible();await axe('native stale destructive preview rejected');expect((await state()).deleted).toBe(false);await page.keyboard.press('Escape');
    const held=await state();expect((await api(endpoint,{method:'PUT',data:{path:reference,digest,expected_revision:held.revision,action:'release_hold',reason:'Finish concurrent preservation'}})).status()).toBe(200);checks.push('late native hold rejects an already displayed destructive preview without a partial transition');
   }
   await open();await preview('delete');await apply('delete');expect((await api(native)).status()).toBe(404);await expect(row().getByText('deleted',{exact:true})).toBeVisible();
   await open();await expect(page.getByLabel('Action',{exact:true})).toHaveValue('restore');await preview('restore');await axe(format+' retained byte restore preview');
   const object=path.join(fixture.private,'installation','objects',tenant,'sha256',digest.slice(0,2),digest);
   await fs.writeFile(object,Buffer.alloc(bytes.length,88));
   try{
    await page.getByRole('button',{name:'Apply restore',exact:true}).click();await expect(page.getByRole('alert').getByText('Outcome not confirmed',{exact:true})).toBeVisible();await expect(page.getByRole('button',{name:'Retry same request',exact:true})).toBeVisible();expect((await state()).deleted).toBe(true);await axe(format+' corrupt retained object recovery');
   }finally{await fs.writeFile(object,bytes)}
   await page.getByRole('button',{name:'Retry same request',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0);const recovered=await api(native);expect(recovered.status()).toBe(200);expect(Buffer.from(await recovered.body())).toEqual(bytes);await axe(format+' native byte restore confirmed');
   expect(await page.evaluate(()=>window.nativeLifecycleLeak)).toBeUndefined();checks.push(format+' console holds, blocks deletion, retains a discoverable tombstone and retries verified native-byte restoration');
   await login(fixture.native_writer_token);await openRepository(name);await open();await expect(page.getByLabel('Action',{exact:true}).locator('option[value="hold"]')).toHaveCount(0);await axe(format+' writer has no administrator hold action');await page.keyboard.press('Escape');
   await login(fixture.native_reader_token);await openRepository(name);await expect(row().getByRole('button',{name:'Lifecycle',exact:true})).toHaveCount(0);expect((await api(endpoint+'?'+new URLSearchParams({path:reference}),{},reader)).status()).toBe(403);await axe(format+' reader package view has no lifecycle mutation');
   for(const value of [token,reader,writer])expect(await page.content()).not.toContain(value);
   expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);checks.push(format+' console and server preserve current reader/writer/admin boundaries without credential persistence');
   await login(fixture.native_admin_token);
  }
  await page.setViewportSize({width:390,height:844});await axe('narrow native lifecycle administration');
 }finally{
  await fs.writeFile(path.join(fixture.private,'native-lifecycle-browser-proof.json'),JSON.stringify({checks,accessibility,browser:browser.version(),scope:'Named generic/Maven/npm/PyPI materialized reference console actions, actual native HTTP bytes, corruption retry, stale revision and reader/writer boundaries in Chromium. Stock-client proof is separate. Full format lifecycle, legal/bulk/GC, assistive technology, other browsers/providers/platforms and production recovery remain required.'},null,2),{mode:0o600})
 }
});
