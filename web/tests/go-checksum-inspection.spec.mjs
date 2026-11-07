// SPDX-License-Identifier: BUSL-1.1
import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'node:fs/promises';
import path from 'node:path';

test('checksum inspection explains bounded private evidence without approving or resetting trust',async({page,browser})=>{
  const fixture=JSON.parse(await fs.readFile(process.env.CRATECTL_CONSOLE_FIXTURE_JSON,'utf8'));
  const name='checksum-inspection-owned',base='/api/v1/repositories/'+name+'/go/checksum';
  const credential='owned-ui-response-standin-'+ 'x'.repeat(32);
  const root='example.org/owned/module/@v/v1.0.0.zip';
  const row=(sequence,generation,classification)=>({root_path:root,source_revision:1,generation,key_digest:'1'.repeat(64),classification,evidence_sha256:'2'.repeat(64),sequence,created_at:'2026-11-06T00:00:00Z'});
  const repo={name,source_revision:3,format:'go',mode:'proxy',access:'restricted',require_review:true,settings:{}};
  const checks=[],accessibility=[],errors=[],calls=[];let mode='blocked',role='admin',phase='connect';
  async function axe(state){const result=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();expect(result.violations).toEqual([]);accessibility.push({state,violations:0})}
  page.on('pageerror',e=>errors.push(e.message));
  // Only the embedded console is real here. Every management response is an
  // owned stand-in while public Go proxy creation remains gated. Real auth,
  // PostgreSQL and exact-byte evidence routes have separate integration tests.
  await page.route('**/api/v1/**',async route=>{
    const request=route.request(),u=new URL(request.url());calls.push({path:u.pathname,query:u.search,method:request.method()});
    const send=(json,status=200)=>route.fulfill({status,json,headers:{'Cache-Control':'private, no-store'}});
    if(request.method()!=='GET')return send({error:{code:'unexpected_mutation',action:'Inspection must remain read-only.'}},500);
    if(u.pathname==='/api/v1/session')return send({tenant:'owned-ui',actor:'inspector',role,public_url:fixture.base_url,formats:['go']});
    if(u.pathname==='/api/v1/repositories')return send({items:[repo]});
    if(u.pathname===base)return send({source_revision:3,authority:{blocked:mode!=='unblocked',checkpoint:{key_digest:'1'.repeat(64),revision:2}},package_admission:false});
    if(u.pathname===base+'/failures'){
      if(mode==='denied')return send({error:{code:'forbidden',action:'Current tenant administrator access is required.'}},403);
      if(mode==='unsafe')return send({items:[row(7,Number.MAX_SAFE_INTEGER+1,'fork')],more:true,next_after:Number.MAX_SAFE_INTEGER+1});
      if(u.searchParams.get('after')==='9')return send({items:[row(11,4,'unverified')],more:false,next_after:0});
      return send({items:[row(7,2,'fork'),row(9,3,'unverified')],more:true,next_after:9});
    }
    return send({error:{code:'unexpected_route',action:'Only owned inspection response stand-ins are available.'}},404);
  });
  const modal=()=>page.getByRole('dialog');
  async function connect(){await page.getByLabel('Tenant credential',{exact:true}).fill(credential);await page.getByRole('button',{name:'Connect to installation',exact:true}).click();await page.getByRole('button',{name:'Checksum inspection',exact:true}).click()}
  try{
    await page.goto(fixture.base_url+'/console/');await connect();phase='blocked';
    await expect(modal()).toContainText('Authenticated fork: this authority key is blocked.');await expect(modal()).toContainText('Unverified observation');await axe('checksum blocked authority and bounded summaries');
    expect(calls.some(c=>c.path===base&&c.query==='?source_revision=3')).toBe(true);checks.push('checksum UI stand-ins preserve the observed source epoch and distinguish authenticated fork from unverified observation');
    await modal().getByRole('button',{name:'Evidence commands',exact:true}).first().click();await expect(modal()).toContainText('--raw-response');await expect(modal()).toContainText('source_revision=1');await expect(modal()).toContainText('generation=2');await expect(modal()).toContainText('CRATECTL_CHECKSUM_PUBLIC_KEY');await expect(modal()).toContainText('CRATECTL_TRUSTED_EVIDENCE_SHA256');await expect(modal()).toContainText('umask 077');await axe('checksum private offline evidence commands');checks.push('checksum UI stand-ins require private exact-byte download plus separately supplied offline key and journal digest');
    await modal().getByRole('button',{name:'Next failure page',exact:true}).click();await expect(modal().getByRole('button',{name:'Evidence commands',exact:true})).toHaveCount(1);expect(calls.some(c=>c.path===base+'/failures'&&c.query.includes('after=9'))).toBe(true);await expect(modal().getByRole('button',{name:'Next failure page',exact:true})).toBeDisabled();await modal().getByRole('button',{name:'First failure page',exact:true}).click();await expect(modal().getByRole('button',{name:'Evidence commands',exact:true})).toHaveCount(2);checks.push('checksum UI stand-ins traverse a bounded advancing journal cursor and explicitly restart at the first page');
    mode='denied';phase='denied';await modal().getByRole('button',{name:'Refresh checksum inspection',exact:true}).click();await expect(modal().getByRole('alert')).toContainText('Access denied');await expect(modal().getByRole('button',{name:'Evidence commands',exact:true})).toHaveCount(0);await expect(modal()).not.toContainText(root);await axe('checksum revoked history access clears old summaries');checks.push('checksum UI stand-in denial removes previously rendered sensitive history');
    mode='unsafe';phase='unsafe';await modal().getByRole('button',{name:'Refresh checksum inspection',exact:true}).click();await expect(modal()).toContainText('The next journal position exceeds exact console precision');await expect(modal().getByRole('button',{name:'Next failure page',exact:true})).toBeDisabled();await modal().getByRole('button',{name:'Evidence commands',exact:true}).click();await expect(modal()).toContainText('Use the API and CLI without copying rounded numbers');await expect(modal().getByRole('button',{name:'Copy private evidence commands',exact:true})).toHaveCount(0);await axe('checksum unsafe integer refuses commands and pagination');checks.push('checksum UI stand-ins fail closed for journal and generation values outside exact browser integer precision');
    mode='unblocked';await modal().getByRole('button',{name:'Refresh checksum inspection',exact:true}).click();await expect(modal()).toContainText('This is not a health check');
    await page.getByRole('button',{name:'Close dialog',exact:true}).click();await page.getByRole('button',{name:'Disconnect',exact:true}).click();role='reader';const historyCalls=calls.filter(c=>c.path===base+'/failures').length;phase='reader';await connect();await expect(modal()).toContainText('Raw failure history and upstream response bodies require a current tenant administrator credential.');await expect(modal().getByRole('button',{name:'Evidence commands',exact:true})).toHaveCount(0);expect(calls.filter(c=>c.path===base+'/failures').length).toBe(historyCalls);await axe('checksum reader safe state only');
    expect(calls.every(c=>c.method==='GET')).toBe(true);expect(calls.some(c=>c.path===base+'/failures/evidence')).toBe(false);expect(await page.content()).not.toContain(credential);expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);expect(errors).toEqual([]);checks.push('checksum UI stand-ins make no mutation or automatic raw download and keep reader credentials out of DOM and persistent storage');phase='complete';
  }finally{await fs.writeFile(path.join(fixture.private,'go-checksum-browser-proof.json'),JSON.stringify({phase,checks,accessibility,browser:browser.version(),scope:'Real x86 Chromium and embedded console with explicitly owned management response stand-ins only. No actual Go proxy creation, PostgreSQL authentication, key enforcement or exact download claim from this UI test; separate Go integration tests cover those. No full Go, browser, WCAG or readiness verdict.'},null,2))}
});
