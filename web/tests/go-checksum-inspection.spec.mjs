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

test('legacy checksum recovery preserves explicit trust decisions and lost-response identity',async({page,browser})=>{
  const fixture=JSON.parse(await fs.readFile(process.env.CRATECTL_CONSOLE_FIXTURE_JSON,'utf8'));
  const name='legacy-checksum-owned',base='/api/v1/repositories/'+name+'/go/checksum',legacy='/api/v1/go/checksum/legacy-incidents';
  const credential='owned-legacy-ui-standin-'+'x'.repeat(32),key='1'.repeat(64),hash='2'.repeat(64),pin='3'.repeat(64),reference='4'.repeat(64);
  const repo={name,source_revision:4,format:'go',mode:'proxy',access:'restricted',require_review:true,settings:{}};
  const checks=[],accessibility=[],calls=[],errors=[],applies=[];let phase='connect',mode='pending',reviewed=false;
  const incident={sequence:7,event_hash:hash,created_at:'2026-11-07T00:00:00Z'};
  async function axe(state){const r=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();expect(r.violations).toEqual([]);accessibility.push({state,violations:0})}
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/v1/**',async route=>{
    const r=route.request(),u=new URL(r.url());calls.push({method:r.method(),path:u.pathname});
    const send=(json,status=200,headers={})=>route.fulfill({status,json,headers:{'Cache-Control':'private, no-store',...headers}});
    if(u.pathname==='/api/v1/session')return send({tenant:'owned-legacy-ui',actor:'reviewer',role:'admin',public_url:fixture.base_url,formats:['go']});
    if(u.pathname==='/api/v1/repositories')return send({items:[repo]});
    if(u.pathname===base)return send({source_revision:4,authority:{blocked:mode==='blocked',legacy_review_required:!reviewed,checkpoint_sha256:pin,checkpoint:{key_digest:key,revision:2}},package_admission:false});
    if(u.pathname===base+'/failures')return send({items:[],more:false,next_after:0});
    if(u.pathname===legacy){
      if(mode==='denied')return send({error:{code:'forbidden',action:'Current administrator access is required.'}},403);
      if(mode==='unsafe')return send({items:[{...incident,sequence:Number.MAX_SAFE_INTEGER+1,reviewed_for_key:false}],more:true,next_after:Number.MAX_SAFE_INTEGER+1});
      return send({items:[{...incident,reviewed_for_key:reviewed}],more:false,next_after:0});
    }
    if(u.pathname===legacy+'/7')return send({incident,classification:'unattributed_fork_label',original_event:{sequence:7,payload:'owned retained journal context',hash,previous_hash:'5'.repeat(64)}});
    if(u.pathname===legacy+'/7/reviews'&&r.method()==='GET')return send({review:{incident_hash:hash,key_digest:key,source_revision:4,review_reference_sha256:reference},verifier_key:'owned separately trusted public verifier stand-in',checkpoint:'owned signed checkpoint stand-in',package_admission:false});
    if(u.pathname===legacy+'/7/reviews'&&r.method()==='POST'){
      const body=r.postDataJSON();expect(body.incident_hash).toBe(hash);expect(body.key_digest).toBe(key);expect(body.expected_source_revision).toBe(4);expect(body.expected_checkpoint_revision).toBe(2);expect(body.checkpoint_sha256).toBe(pin);
      if(body.dry_run){expect(body.accept_unattributed_history).toBe(false);return send({incident,repository:name,key_digest:key,source_revision:4,checkpoint_revision:2,checkpoint_sha256:pin,review_reference_sha256:reference,package_admission:false})}
      expect(body.accept_unattributed_history).toBe(true);applies.push({body:r.postData(),key:r.headers()['idempotency-key']});
      if(applies.length===1)return send({error:{code:'outcome_unknown',action:'The connection did not confirm the result.'}},503);
      reviewed=true;return send({review:{incident_sequence:7,incident_hash:hash,key_digest:key,sequence:12},package_admission:false},200,{'Idempotent-Replayed':'true'});
    }
    return send({error:{code:'unexpected_route',action:'Only explicit owned legacy-recovery stand-ins are available.'}},404);
  });
  const modal=()=>page.getByRole('dialog');
  try{
    await page.goto(fixture.base_url+'/console/');await page.getByLabel('Tenant credential',{exact:true}).fill(credential);await page.getByRole('button',{name:'Connect to installation',exact:true}).click();await page.getByRole('button',{name:'Checksum inspection',exact:true}).click();phase='pending';
    await expect(modal()).toContainText('Unattributed historical incident: external trust review is required.');await expect(modal()).not.toContainText('Authenticated fork: this authority key is blocked.');await expect(modal()).toContainText('It cannot clear an authenticated fork or approve package bytes.');expect(calls.some(c=>c.method!=='GET')).toBe(false);await axe('legacy incident remains unattributed and pending');checks.push('legacy UI stand-ins distinguish missing original proof from authenticated fork and make no automatic trust mutation');
    await modal().getByRole('button',{name:'Inspect legacy incident 7',exact:true}).click();await expect(modal().getByText('Original event and local hash link',{exact:true})).toBeVisible();await modal().getByLabel('SHA-256 of separate external trust review',{exact:true}).fill(reference);await modal().getByLabel('External trust decision reason',{exact:true}).fill('Separately reviewed public authority despite unknown old attribution');await modal().getByRole('button',{name:'Preview external trust review',exact:true}).click();phase='preview';await expect(modal()).toContainText('Every other unresolved incident still requires review.');await axe('legacy external trust preview and explicit acknowledgment');checks.push('legacy UI stand-ins bind preview to exact incident key source and checkpoint plus separate external review');
    await modal().getByRole('button',{name:'Record external trust review',exact:true}).click();expect(applies).toHaveLength(0);await modal().getByRole('checkbox').check();await modal().getByRole('button',{name:'Record external trust review',exact:true}).click();phase='unknown';await expect(modal()).toContainText('Outcome not confirmed');await axe('legacy lost-response request retains exact identity');await modal().getByRole('button',{name:'Retry same request',exact:true}).click();await expect(page.getByRole('status').filter({hasText:'Original request confirmed.'})).toBeVisible();expect(applies).toHaveLength(2);expect(applies[1]).toEqual(applies[0]);checks.push('legacy UI stand-ins require explicit acknowledgment and replay exact retained bytes and idempotency key after unconfirmed response');
    await page.getByRole('button',{name:'Checksum inspection',exact:true}).click();await modal().getByRole('button',{name:'Inspect retained legacy incidents',exact:true}).click();await modal().getByRole('button',{name:'Read retained review 7',exact:true}).click();phase='receipt';await expect(modal()).toContainText('Retained external trust review');await modal().getByText('Historical review and signed checkpoint',{exact:true}).click();await expect(modal()).toContainText(reference);await expect(modal()).toContainText('do not report current key usability');await axe('legacy immutable historical review outcome');checks.push('legacy UI stand-ins show retained trust review separately from current key and package admission');
    reviewed=false;mode='blocked';await modal().getByRole('button',{name:'Refresh checksum inspection',exact:true}).click();await expect(modal()).toContainText('Authenticated fork: this authority key is blocked.');await modal().getByRole('button',{name:'Inspect legacy incident 7',exact:true}).click();phase='fork';await expect(modal()).toContainText('External review cannot unblock it.');await expect(modal().getByRole('button',{name:'Preview external trust review',exact:true})).toHaveCount(0);await axe('legacy review cannot override authenticated fork');checks.push('legacy UI stand-ins prioritize authenticated fork and refuse its review form');
    mode='denied';await modal().getByRole('button',{name:'Refresh checksum inspection',exact:true}).click();phase='denied';await expect(modal().getByRole('alert')).toContainText('Access denied');await expect(modal()).not.toContainText('owned retained journal context');await expect(modal().getByRole('button',{name:'Inspect legacy incident 7',exact:true})).toHaveCount(0);await axe('legacy revoked inspection clears original context');checks.push('legacy UI stand-in denial clears previously rendered sensitive original context');
    mode='unsafe';await modal().getByRole('button',{name:'Refresh checksum inspection',exact:true}).click();phase='precision';await expect(modal()).toContainText('The legacy journal cursor cannot be represented exactly');await expect(modal().getByRole('button',{name:'Next legacy page',exact:true})).toBeDisabled();await expect(modal().getByRole('button',{name:/Inspect legacy incident /})).toBeDisabled();await axe('legacy unsafe incident sequence refuses review');expect(errors).toEqual([]);expect(await page.content()).not.toContain(credential);expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);checks.push('legacy UI stand-ins refuse rounded incident selectors and keep credentials out of rendered or persistent storage');phase='complete';
  }finally{await fs.writeFile(path.join(fixture.private,'go-checksum-legacy-browser-proof.json'),JSON.stringify({phase,checks,accessibility,browser:browser.version(),scope:'Real x86 Chromium with explicitly owned management response stand-ins. No actual PostgreSQL, authorization, migration, signature or package-admission claim from this UI test; those have separate Go integration tests.'},null,2))}
});
