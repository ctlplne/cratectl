// SPDX-License-Identifier: BUSL-1.1
import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';

test('administrator discovers holds, reads original receipts and recovers retained references',async({page,browser,request})=>{
 const fixture=JSON.parse(await fs.readFile(process.env.CRATECTL_CONSOLE_FIXTURE_JSON,'utf8'));
 const token=(await fs.readFile(fixture.hold_admin_token,'utf8')).trim(),recovery=(await fs.readFile(fixture.hold_recovery_token,'utf8')).trim(),name='holds-ui-'+fixture.run;
 const checks=[],accessibility=[],reason='Owned <script>window.ownedHoldLeak=true</script> review';
 const body=JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:[],annotations:{purpose:'owned hold administration browser fixture'}});
 const digest=createHash('sha256').update(body).digest('hex'),reference='app/manifests/sha256:'+digest,native='/v2/'+name+'/'+reference,endpoint='/api/v1/repositories/'+name+'/artifacts/lifecycle';
 const api=(url,options={},credential=token)=>request.fetch(fixture.base_url+url,{...options,headers:{Authorization:'Bearer '+credential,'Idempotency-Key':'hold-browser-'+crypto.randomUUID(),...options.headers}});
 const state=async(credential=token)=>(await(await api(endpoint+'?'+new URLSearchParams({path:reference}),{},credential)).json());
 async function axe(label){const result=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();expect(result.violations).toEqual([]);accessibility.push({state:label,violations:0})}
 async function login(file){await page.goto(fixture.base_url+'/console/');await page.getByLabel('Credential file').setInputFiles(file);await page.waitForFunction(()=>document.querySelector('#credential')?.value.length>=32);await page.getByRole('button',{name:'Connect to installation',exact:true}).click();await expect(page.getByRole('heading',{name:'Repositories',exact:true})).toBeVisible()}
 async function preview(action,text){await page.getByLabel('Action',{exact:true}).selectOption(action);await page.getByLabel('Reason',{exact:true}).fill(text);await page.getByRole('button',{name:'Preview impact',exact:true}).click();await expect(page.getByText(/Previewed revision/)).toBeVisible()}
 async function apply(action){await page.getByRole('button',{name:'Apply '+action,exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0)}
 async function inventory(){await page.getByRole('link',{name:'Storage',exact:true}).click();await page.getByRole('button',{name:'Reference holds',exact:true}).click();await page.getByLabel('Exact repository (optional)',{exact:true}).fill(name);await page.getByRole('button',{name:'Search holds',exact:true}).click()}
 const row=()=>page.getByRole('region',{name:'Hold records',exact:true}).getByRole('row').filter({hasText:digest});
 try{
  expect((await api('/api/v1/repositories',{method:'POST',data:{name,format:'oci'}})).status()).toBe(201);
  expect((await api('/v2/'+name+'/app/manifests/latest',{method:'PUT',data:body,headers:{'Content-Type':'application/vnd.oci.image.index.v1+json'}})).status()).toBe(201);
  await login(fixture.hold_admin_token);
  await page.getByRole('searchbox',{name:'Search repositories',exact:true}).fill(name);await page.getByRole('button',{name:'Search',exact:true}).click();await page.getByRole('link',{name,exact:true}).click();
  await page.getByRole('row').filter({hasText:digest}).getByRole('button',{name:'Lifecycle',exact:true}).click();await preview('hold',reason);await axe('hold placement preview');await apply('hold');
  expect((await api(native,{method:'DELETE'})).status()).toBe(409);checks.push('console places an exact hold and actual native OCI deletion is blocked');
  await inventory();await expect(row().getByText('active',{exact:true})).toBeVisible();await expect(row().getByRole('cell').nth(2)).toContainText(reason);expect(await page.evaluate(()=>window.ownedHoldLeak)).toBeUndefined();await axe('active tenant hold inventory');
  await page.screenshot({path:path.join(fixture.private,'holds-desktop.png')});
  await row().getByRole('button',{name:'Inspect hold history',exact:true}).click();await expect(page.getByRole('dialog').getByText('Hold placed',{exact:true})).toBeVisible();await axe('original hold journal receipt');await page.keyboard.press('Escape');checks.push('bounded hold inventory and immutable history expose exact reference and safely rendered original reason');
  expect((await api('/api/v1/repositories/'+name+'/state',{method:'PUT',data:{action:'remove',expected_revision:0,reason:'Retain repository during owned review'}})).status()).toBe(200);
  await page.getByRole('button',{name:'Refresh holds',exact:true}).click();await expect(row().getByText(/Repository removed/)).toBeVisible();await row().getByRole('button',{name:'Manage hold',exact:true}).click();await expect(page.getByLabel('Action',{exact:true})).toHaveValue('release_hold');await preview('release_hold','Review complete in retained repository');await axe('retained repository hold release preview');await apply('release hold');expect((await api(native)).status()).toBe(404);
  await page.getByRole('combobox',{name:'Hold state',exact:true}).selectOption('released');await expect(row().getByText('released',{exact:true})).toBeVisible();await axe('released hold retained inventory');checks.push('administrator releases a discovered hold while repository remains removed and native serving stays fenced');
  expect((await api('/api/v1/repositories/'+name+'/state',{method:'PUT',data:{action:'restore',expected_revision:1,reason:'Restore repository after completed review'}})).status()).toBe(200);
  expect((await api(native)).status()).toBe(200);
  const current=await state(),expires=new Date(Date.now()+6000).toISOString();
  expect((await api(endpoint,{method:'PUT',data:{action:'hold',path:reference,digest,expected_revision:current.revision,reason:'Real elapsed expiry review',hold_until:expires}})).status()).toBe(200);
  await expect.poll(async()=>{const r=await api('/api/v1/holds?'+new URLSearchParams({repository:name,state:'expired'}));expect(r.status()).toBe(200);return(await r.json()).items.length},{timeout:12000}).toBe(1);
  await page.getByRole('combobox',{name:'Hold state',exact:true}).selectOption('expired');await expect(row().getByText('expired',{exact:true})).toBeVisible();await axe('actual-time expired hold inventory');
  const history=await(await api(endpoint+'/history?'+new URLSearchParams({path:reference}))).json(),original=history.items.find(v=>v.state.hold_until&&Date.parse(v.state.hold_until)===Date.parse(expires));expect(original.state.held).toBe(true);expect((await state()).held).toBe(false);checks.push('real elapsed expiry changes the current list while the original timed-hold journal snapshot remains held');
  const expired=await state();expect((await api(endpoint,{method:'PUT',data:{action:'hold',path:reference,digest,expected_revision:expired.revision,reason:'Hold survives credential revocation'}})).status()).toBe(200);
  const database=JSON.parse(await fs.readFile(fixture.owner_config,'utf8'));
  execFileSync(path.join(fixture.root,'bin/cratectld'),['revoke','--token-file',fixture.hold_admin_token],{env:{...process.env,CRATECTL_OWNER_DSN:database.owner},stdio:'pipe',timeout:30000});
  await page.getByRole('button',{name:'Refresh holds',exact:true}).click();await expect(page.getByRole('button',{name:'Connect to installation',exact:true})).toBeVisible();await axe('revoked hold administrator reconnect');
  expect((await api(native,{method:'DELETE'},recovery)).status()).toBe(409);
  await login(fixture.hold_recovery_token);await inventory();await expect(row().getByText('active',{exact:true})).toBeVisible();await axe('current administrator hold recovery');
  await row().getByRole('button',{name:'Manage hold',exact:true}).click();await preview('release_hold','Current administrator completes retained review');await apply('release hold');expect((await api(native,{},recovery)).status()).toBe(200);
  await page.getByRole('combobox',{name:'Hold state',exact:true}).selectOption('released');await expect(row().getByText('released',{exact:true})).toBeVisible();await axe('recovery release preserves held-reference history');
  await page.setViewportSize({width:390,height:844});await axe('narrow hold administration inventory');await page.screenshot({path:path.join(fixture.private,'holds-narrow.png')});
  expect(await page.content()).not.toContain(token);expect(await page.content()).not.toContain(recovery);expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);checks.push('revoked authority clears the workspace; an independent current administrator recovers the persistent hold without credential exposure');
 }finally{
  await fs.writeFile(path.join(fixture.private,'hold-browser-proof.json'),JSON.stringify({checks,accessibility,browser:browser.version(),scope:'Existing per-reference OCI holds: native denial, tenant inventory, original history, retained-repository recovery, actual expiry and revoked-actor recovery in Chromium. Multiple independent cases, bulk/legal workflow, other formats, assistive technology, scale and production recovery remain required.'},null,2),{mode:0o600})
 }
});
