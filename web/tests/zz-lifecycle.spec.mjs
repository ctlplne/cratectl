// SPDX-License-Identifier: BUSL-1.1
import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';

test('retained lifecycle previews, holds and recovery in the operator console',async({page,browser,request})=>{
  const fixture=JSON.parse(await fs.readFile(process.env.CRATECTL_CONSOLE_FIXTURE_JSON,'utf8'));
  const token=(await fs.readFile(fixture.other_token,'utf8')).trim(),name='browser-life-'+fixture.run;
  const checks=[],accessibility=[];
  const api=(url,options={})=>request.fetch(fixture.base_url+url,{...options,headers:{Authorization:'Bearer '+token,'Idempotency-Key':'browser-lifecycle-'+crypto.randomUUID(),...options.headers}});
  const data=JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:[]});
  const digest=createHash('sha256').update(data).digest('hex'),native='/v2/'+name+'/app/manifests/sha256:'+digest;
  async function axe(state){const a=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();expect(a.violations).toEqual([]);accessibility.push({state,violations:0})}
  async function openRepository(){await page.getByRole('link',{name:'Repositories',exact:true}).click();await page.getByRole('searchbox',{name:'Search repositories',exact:true}).fill(name);await page.getByRole('button',{name:'Search',exact:true}).click();const row=page.getByRole('row').filter({has:page.getByRole('link',{name,exact:true})});await row.getByRole('button',{name:'Lifecycle',exact:true}).click();await expect(page.getByText(/Current state:/)).toBeVisible()}
  async function preview(action){await page.getByLabel('Action',{exact:true}).selectOption(action);await page.getByLabel('Reason',{exact:true}).fill('Owned browser lifecycle verification');await page.getByRole('button',{name:'Preview impact',exact:true}).click();await expect(page.getByText(/Previewed revision/)).toBeVisible()}
  async function apply(action){await page.getByRole('button',{name:'Apply '+action,exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0)}
  try{
    expect((await api('/api/v1/repositories',{method:'POST',data:{name,format:'oci'}})).status()).toBe(201);
    expect((await api('/v2/'+name+'/app/manifests/latest',{method:'PUT',data,headers:{'Content-Type':'application/vnd.oci.image.index.v1+json'}})).status()).toBe(201);
    await page.goto(fixture.base_url+'/console/');await page.getByLabel('Credential file').setInputFiles(fixture.other_token);await page.waitForFunction(()=>document.querySelector('#credential')?.value.length>=32);await page.getByRole('button',{name:'Connect to installation',exact:true}).click();
    await openRepository();await expect(page.getByLabel('Action',{exact:true})).toBeFocused();await axe('repository lifecycle action');
    await preview('suspend');await axe('repository suspension impact preview');await apply('suspend');expect((await api(native)).status()).toBe(503);checks.push('administrator previews and suspends an actual repository');
    await openRepository();await preview('remove');await apply('remove');expect((await api(native)).status()).toBe(404);
    await openRepository();await expect(page.getByLabel('Action',{exact:true})).toHaveValue('restore');await preview('restore');await axe('removed repository restoration preview');await apply('restore');expect((await api(native)).status()).toBe(200);checks.push('removed repository remains discoverable for explicit retained restore');
    await page.getByRole('link',{name,exact:true}).click();await expect(page.getByRole('heading',{name:'Packages',exact:true})).toBeVisible();
    const row=page.getByRole('row').filter({has:page.getByRole('button',{name:'Inspect',exact:true})}).filter({hasText:digest});
    await row.getByRole('button',{name:'Lifecycle',exact:true}).click();await expect(page.getByText(/Current state:/)).toBeVisible();await preview('hold');await apply('hold');expect((await api(native,{method:'DELETE'})).status()).toBe(409);
    await row.getByRole('button',{name:'Lifecycle',exact:true}).click();await expect(page.getByText(/Current state:/)).toBeVisible();await preview('delete');await expect(page.getByText('This operation is blocked by an active hold or incoming manifest reference. Inspect the lifecycle record and parent references before trying again.')).toBeVisible();await expect(page.getByRole('button',{name:'Apply delete',exact:true})).toHaveCount(0);await axe('held artifact deletion blocked');await page.keyboard.press('Escape');checks.push('hold protects actual native deletion and console blocks its previewed apply');
    await row.getByRole('button',{name:'Lifecycle',exact:true}).click();await expect(page.getByText(/Current state:/)).toBeVisible();await preview('release_hold');await apply('release hold');
    await row.getByRole('button',{name:'Lifecycle',exact:true}).click();await expect(page.getByText(/Current state:/)).toBeVisible();await preview('delete');await apply('delete');expect((await api(native)).status()).toBe(404);await expect(row.getByText('deleted',{exact:true})).toBeVisible();
    await row.getByRole('button',{name:'Lifecycle',exact:true}).click();await expect(page.getByLabel('Action',{exact:true})).toHaveValue('restore');await preview('restore');await axe('deleted artifact verified restore preview');await apply('restore');expect((await api(native)).status()).toBe(200);checks.push('administrator deletes and verifies restoration of exact retained OCI bytes');
    expect(await page.content()).not.toContain(token);expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);checks.push('lifecycle workflow exposes no credential in DOM or persistent browser storage');
  }finally{await fs.writeFile(path.join(fixture.private,'lifecycle-browser-proof.json'),JSON.stringify({checks,accessibility,browser:browser.version(),scope:'Named repository/reference lifecycle workflows in Chromium. Full lifecycle, assistive technologies, native browsers, scale and production recovery remain open.'},null,2))}
});
