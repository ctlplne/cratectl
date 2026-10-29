// SPDX-License-Identifier: BUSL-1.1
import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile);
const fixture=JSON.parse(await fs.readFile(process.env.CRATECTL_CONSOLE_FIXTURE_JSON,'utf8'));
test('blank operator workflow, policy, isolation, recovery and accessibility',async({page,browser,request})=>{
  const checks=[],accessibility=[],consoleErrors=[],requests=[];
  const tokens={};for(const role of ['admin','reader','writer','worker','other'])tokens[role]=(await fs.readFile(fixture[role+'_token'],'utf8')).trim();
  async function check(label,body){await body();checks.push(label)}
  async function axe(label,target=page){const result=await new AxeBuilder({page:target}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();accessibility.push({state:label,violations:result.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.map(n=>({target:n.target,failureSummary:n.failureSummary}))}))});expect(result.violations.map(v=>({id:v.id,impact:v.impact,targets:v.nodes.map(n=>n.target)}))).toEqual([])}
  async function login(target,role='admin'){
    await target.goto(fixture.base_url+'/console/');await target.getByLabel('Credential file').setInputFiles(fixture[role+'_token']);
    await target.waitForFunction(()=>document.querySelector('#credential')?.value.length>=32);
    await target.getByRole('button',{name:'Connect to installation',exact:true}).click();await expect(target.getByRole('heading',{name:'Repositories',exact:true})).toBeVisible();
  }
  async function api(url,options={},role='admin'){
    const r=await request.fetch(fixture.base_url+url,{...options,headers:{Authorization:'Bearer '+tokens[role],...(options.method&&options.method!=='GET'?{'Idempotency-Key':'browser-fixture-'+crypto.randomUUID()}:{}),...options.headers}});
    return r;
  }
  async function native(args,{cwd=fixture.private,env={},expectSuccess=true}={}){
    let success=true,output='';try{const r=await exec(args[0],args.slice(1),{cwd,env:{...process.env,NPM_CONFIG_USERCONFIG:path.join(fixture.private,'npmrc'),NPM_CONFIG_CACHE:path.join(fixture.private,'npm-cache'),NPM_CONFIG_AUDIT:'false',NPM_CONFIG_FUND:'false',NPM_CONFIG_UPDATE_NOTIFIER:'false',...env},timeout:60000});output=r.stdout+r.stderr}catch(e){success=false;output=(e.stdout??'')+(e.stderr??'')}
    await fs.appendFile(path.join(fixture.private,'native-client.log'),output);expect(success).toBe(expectSuccess);return output;
  }
  async function create(name,format='npm',access='tenant'){
    await page.getByRole('link',{name:'Repositories',exact:true}).click();await page.getByRole('button',{name:'＋ Create repository',exact:true}).click();
    await page.getByLabel('Repository name',{exact:true}).fill(name);await page.getByLabel('Format',{exact:true}).selectOption(format);await page.getByLabel('Access',{exact:true}).selectOption(access);
    await page.getByRole('dialog').getByRole('button',{name:'Create repository',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0);await expect(page.getByRole('link',{name,exact:true})).toBeVisible();
  }
  page.on('pageerror',e=>consoleErrors.push(e.message));page.on('request',r=>requests.push(r.url()));
  try{
    await page.clock.install();await page.goto(fixture.base_url+'/console/');await axe('empty connection');
    await check('packaged login shell makes only same-origin requests',async()=>{expect(requests.every(u=>new URL(u).origin===fixture.base_url)).toBe(true)});
    await login(page);await expect(page.getByRole('heading',{name:'Create your first repository'})).toBeVisible();await axe('blank tenant');
    await check('keyboard skip link reaches content and native dialog returns focus',async()=>{
      await page.keyboard.press('Tab');await expect(page.getByRole('link',{name:'Skip to content'})).toBeFocused();await page.keyboard.press('Enter');await expect(page.locator('#main-content')).toBeFocused();
      await page.keyboard.press('Tab');await expect(page.getByRole('button',{name:'＋ Create repository',exact:true})).toBeFocused();await page.keyboard.press('Enter');await expect(page.getByLabel('Repository name',{exact:true})).toBeFocused();await page.keyboard.press('Escape');await expect(page.getByRole('dialog')).toHaveCount(0);await expect(page.getByRole('button',{name:'＋ Create repository',exact:true})).toBeFocused();
    });
    const mutationKeys=[],mutationBodies=[];let cut=true;
    await page.route('**/api/v1/repositories',async route=>{
      if(route.request().method()==='POST'){mutationKeys.push(route.request().headers()['idempotency-key']);mutationBodies.push(route.request().postData());if(cut){cut=false;const r=await route.fetch();expect(r.status()).toBe(201);await route.abort('connectionfailed');return}}
      await route.continue();
    });
    await check('lost response after actual commit retries the original request and does not duplicate a repository',async()=>{
      await page.getByRole('button',{name:'＋ Create repository',exact:true}).click();await page.getByLabel('Repository name',{exact:true}).fill('web-packages');await axe('repository creation dialog');
      await page.getByRole('dialog').getByRole('button',{name:'Create repository',exact:true}).click();await expect(page.getByRole('alert')).toContainText('Outcome not confirmed');await page.getByRole('button',{name:'Retry same request'}).click();
      await expect(page.getByRole('dialog')).toHaveCount(0);await expect(page.getByRole('status').filter({hasText:'Original request confirmed.'})).toBeVisible();expect(mutationKeys).toHaveLength(2);expect(mutationKeys[0]).toBe(mutationKeys[1]);expect(mutationBodies[0]).toBe(mutationBodies[1]);
      const r=await api('/api/v1/repositories');expect((await r.json()).items.filter(x=>x.name==='web-packages')).toHaveLength(1);
    });await page.unroute('**/api/v1/repositories');
    await check('native configuration templates omit the active credential',async()=>{
      await page.getByRole('button',{name:'Client setup'}).click();await expect(page.getByRole('dialog')).toContainText('${CRATECTL_TOKEN}');expect((await page.getByRole('dialog').textContent()).includes(tokens.admin)).toBe(false);await page.getByRole('button',{name:'Close dialog'}).click();
    });
    await native(['npm','publish','--ignore-scripts','--access','public'],{cwd:path.join(fixture.private,'npm-package')});
    const denied=path.join(fixture.private,'denied-consumer');await fs.mkdir(denied);const deniedOutput=await native(['npm','install','--ignore-scripts','--no-audit','--no-fund','cratectl-console-proof@1.0.0'],{cwd:denied,expectSuccess:false});expect(deniedOutput).toMatch(/npm error (?:code E404|404 Not Found)/);
    await page.getByRole('link',{name:'web-packages',exact:true}).click();await expect(page.getByText('Unassessed',{exact:true})).toBeVisible();
    const r=await api('/api/v1/repositories/web-packages/artifacts');const artifact=(await r.json()).items[0];
    await check('console binds manual approval to the observed exact path and digest',async()=>{
      await page.getByRole('button',{name:'Allow',exact:true}).click();await expect(page.getByRole('dialog')).toContainText(artifact.digest);await expect(page.getByRole('dialog')).toContainText(artifact.path);await axe('exact-digest approval dialog');await page.getByRole('button',{name:'Allow exact digest',exact:true}).click();await expect(page.getByText('Manually allowed',{exact:true})).toBeVisible();
    });
    const consumer=path.join(fixture.private,'approved-consumer');await fs.mkdir(consumer);await native(['npm','install','--ignore-scripts','--no-audit','--no-fund','cratectl-console-proof@1.0.0'],{cwd:consumer});await native(['node','-e','if(require("cratectl-console-proof")!==42)process.exit(1)'],{cwd:consumer});checks.push('stock npm publishes, review policy denies, then exact approval permits a real install');await axe('populated package table');
    await check('current console denial blocks a fresh native-client install',async()=>{
      await page.getByRole('button',{name:'Deny',exact:true}).click();await page.getByRole('button',{name:'Deny exact digest',exact:true}).click();await expect(page.getByText('denied',{exact:true})).toBeVisible();
      const target=path.join(fixture.private,'fresh-denied-consumer');await fs.mkdir(target);const output=await native(['npm','install','--ignore-scripts','--no-audit','--no-fund','cratectl-console-proof@1.0.0'],{cwd:target,expectSuccess:false,env:{NPM_CONFIG_CACHE:path.join(fixture.private,'fresh-denied-cache')}});expect(output).toMatch(/npm error (?:code E404|404 Not Found)/);
    });
    await page.getByRole('link',{name:'Jobs',exact:true}).click();await expect(page.getByRole('region',{name:'Durable jobs'})).toBeVisible();await axe('jobs');await page.getByRole('button',{name:'Inspect job'}).first().click();await axe('job detail');await page.getByRole('button',{name:'Close dialog'}).click();checks.push('durable jobs and recorded observations are accessible from the console');
    await page.getByRole('link',{name:'Storage',exact:true}).click();await expect(page.getByRole('heading',{name:'No inventories on this page'})).toBeVisible();await axe('empty storage');
    await page.getByRole('button',{name:'Start inventory',exact:true}).click();await page.getByRole('button',{name:'Start filesystem inventory',exact:true}).click();await expect(page.getByRole('status').filter({hasText:'is admitted'})).toBeVisible();
    await expect(async()=>{await page.getByRole('button',{name:'Refresh inventories'}).click();await expect(page.getByText('succeeded',{exact:true})).toBeVisible()}).toPass({timeout:15000});
    await page.getByRole('button',{name:'Inspect inventory'}).click();await expect(page.getByText('Supported layout accounted',{exact:true})).toBeVisible();await axe('completed inventory');await page.getByRole('button',{name:'Close dialog'}).click();checks.push('UI admits and inspects a real completed inventory without security/deletion approval');
    await page.getByRole('button',{name:'Referenced integrity',exact:true}).click();await expect(page.getByRole('region',{name:'Referenced sweep preview'})).toBeVisible();await axe('reference sweep preview');
    await page.getByRole('button',{name:'Transfer leases',exact:true}).click();await expect(page.getByRole('heading',{name:'Expired lease candidates'})).toBeVisible();await axe('lease preview');
    await page.getByRole('link',{name:'Audit',exact:true}).click();await expect(page.getByRole('region',{name:'Tenant audit events'})).toBeVisible();await axe('audit');
    await check('audit export contains this tenant and explicitly states its page scope',async()=>{const download=page.waitForEvent('download');await page.getByRole('button',{name:'Export this page · JSON'}).click();const saved=await (await download).path();const data=JSON.parse(await fs.readFile(saved,'utf8'));expect(data.tenant).toBe('console-a');expect(data.scope).toContain('This loaded audit page only');expect(data.items.length).toBeGreaterThan(0)});
    await create('hostile-paths','generic');
    const injection='<img src=x onerror=window.__cratectlInjected=1>';
    expect((await api('/r/hostile-paths/'+encodeURIComponent(injection),{method:'PUT',data:Buffer.from('owned benign fixture'),headers:{'Content-Type':'application/octet-stream'}})).status()).toBe(201);
    await page.getByRole('link',{name:'hostile-paths',exact:true}).click();await expect(page.getByText(injection,{exact:true})).toBeVisible();expect(await page.locator('img[src="x"]').count()).toBe(0);expect(await page.evaluate(()=>window.__cratectlInjected)).toBeUndefined();checks.push('hostile package path is rendered as text and cannot inject DOM/script');
    await create('private-packages','generic','restricted');expect((await api('/r/private-packages/private-file',{method:'PUT',data:Buffer.from('private fixture'),headers:{'Content-Type':'application/octet-stream'}})).status()).toBe(201);
    const settings=page.getByRole('row').filter({has:page.getByRole('link',{name:'private-packages',exact:true})});await settings.getByRole('button',{name:'Settings',exact:true}).click();await page.getByLabel('Actor name',{exact:true}).fill('reader');await page.getByRole('button',{name:'Save actor grant'}).click();await expect(page.getByRole('dialog')).toHaveCount(0);
    const readerContext=await browser.newContext();const reader=await readerContext.newPage();await login(reader,'reader');await expect(reader.getByRole('link',{name:'private-packages',exact:true})).toBeVisible();await reader.getByRole('link',{name:'private-packages',exact:true}).click();
    // The repository requires review. Authorize the owned fixture before checking
    // that removal of its repository grant clears already visible metadata.
    const refs=(await (await api('/api/v1/repositories/private-packages/artifacts')).json()).items;await api('/api/v1/repositories/private-packages/decisions',{method:'PUT',data:{path:refs[0].path,digest:refs[0].digest,decision:'allowed'}});await reader.getByRole('button',{name:'Refresh packages'}).click();await expect(reader.getByText('private-file',{exact:true})).toBeVisible();expect(await reader.getByRole('button',{name:'Allow',exact:true}).count()).toBe(0);
    await settings.getByRole('button',{name:'Settings',exact:true}).click();await page.getByLabel('Actor name',{exact:true}).fill('reader');await page.getByRole('checkbox',{name:'Read',exact:true}).uncheck();await page.getByRole('button',{name:'Save actor grant'}).click();await reader.getByRole('button',{name:'Refresh packages'}).click();await expect(reader.getByRole('alert')).toContainText('Access denied');await expect(reader.getByText('private-file',{exact:true})).toHaveCount(0);await axe('reader permission removed',reader);
    await reader.getByRole('link',{name:'Jobs',exact:true}).click();await expect(reader.getByRole('heading',{name:'Administrator access required'})).toBeVisible();expect((await api('/api/v1/jobs',{},'reader')).status()).toBe(403);checks.push('reader grant changes clear stale package data and administrative jobs remain denied');await readerContext.close();
    await page.getByRole('link',{name:'Repositories',exact:true}).click();
    await check('partial and stale response states remain explicit',async()=>{
      await page.route('**/api/v1/repositories',async route=>{const r=await route.fetch();const body=await r.json();body.limit=1;await route.fulfill({response:r,json:body})});await page.getByRole('button',{name:'Refresh',exact:true}).click();await expect(page.getByRole('status').filter({hasText:'Result ceiling reached'})).toBeVisible();await page.unroute('**/api/v1/repositories');
      await page.clock.fastForward(65000);await expect(page.getByText('Stale observation',{exact:false})).toBeVisible();
      await page.route('**/api/v1/repositories',route=>route.fulfill({status:503,json:{error:{code:'owned_fault',action:'Owned service fault; retry after recovery.'}}}));await page.getByRole('button',{name:'Refresh',exact:true}).click();await expect(page.getByRole('alert')).toContainText('showing an older observation');await page.unroute('**/api/v1/repositories');await page.getByRole('button',{name:'Try again',exact:true}).click();await expect(page.getByRole('alert')).toHaveCount(0);
    });
    await page.setViewportSize({width:390,height:844});await axe('mobile repository view');expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await page.screenshot({path:path.join(fixture.private,'console-mobile.png'),fullPage:true});await page.setViewportSize({width:1440,height:1000});await page.screenshot({path:path.join(fixture.private,'console-repositories.png'),fullPage:true});
    let release;const gate=new Promise(resolve=>{release=resolve});let intercepted;const arrived=new Promise(resolve=>{intercepted=resolve});
    await page.route('**/api/v1/repositories',async route=>{if(route.request().method()!=='GET')return route.continue();const r=await route.fetch();intercepted();await gate;try{await route.fulfill({response:r})}catch{}});
    await page.getByRole('button',{name:'Refresh',exact:true}).click();await arrived;await page.getByRole('button',{name:'Disconnect',exact:true}).click();await login(page,'other');release();await page.unroute('**/api/v1/repositories');
    await expect(page.getByRole('heading',{name:'Create your first repository'})).toBeVisible();expect(await page.getByText('web-packages',{exact:true}).count()).toBe(0);expect(await page.getByText('private-file',{exact:true}).count()).toBe(0);checks.push('late prior-tenant responses cannot populate a newly connected tenant');
    await page.getByRole('button',{name:'Disconnect',exact:true}).click();await login(page);
    const db=JSON.parse(await fs.readFile(fixture.owner_config,'utf8'));await native([path.join(fixture.root,'bin/cratectld'),'revoke','--token-file',fixture.admin_token],{env:{CRATECTL_OWNER_DSN:db.owner}});
    await page.getByRole('button',{name:'Refresh',exact:true}).click();await expect(page.getByRole('heading',{name:'Your repositories. Under your control.'})).toBeVisible();await expect(page.getByRole('status').filter({hasText:'expired or was revoked'})).toBeVisible();expect(await page.getByText('web-packages',{exact:true}).count()).toBe(0);checks.push('actual credential revocation clears the workspace and requires reconnect');
    await check('unauthorized responses clear the session even when an intermediary returns a non-JSON body',async()=>{
      await login(page,'other');await page.route('**/api/v1/repositories',route=>route.fulfill({status:401,contentType:'text/html',body:'<p>Unauthorized</p>'}));await page.getByRole('button',{name:'Refresh',exact:true}).click();await expect(page.getByRole('heading',{name:'Your repositories. Under your control.'})).toBeVisible();await expect(page.getByRole('status').filter({hasText:'expired or was revoked'})).toBeVisible();await page.unroute('**/api/v1/repositories');
    });
    await check('credentials are absent from browser storage, cookies, URLs and templates',async()=>{
      const stored=await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage},cookies:document.cookie,url:location.href}));expect(Object.values(tokens).some(t=>stored.includes(t))).toBe(false);expect(Object.values(tokens).some(t=>requests.some(u=>u.includes(t)))).toBe(false);expect((await page.context().cookies()).length).toBe(0);
    });
    expect(consoleErrors).toEqual([]);checks.push('no uncaught browser errors');checks.push('all named accessibility states have zero automated WCAG A/AA findings');
  }finally{
    await fs.writeFile(path.join(fixture.private,'browser-proof.json'),JSON.stringify({checks,accessibility,uncaught_errors:consoleErrors,browser:browser.version(),automated_accessibility_scope:'axe WCAG 2/2.1/2.2 A/AA tags on named states, supplemented by tested keyboard actions; not a full WCAG conformance result.',controlled_faults:['response dropped after actual repository commit','partial legacy response ceiling','503 stale-data recovery','delayed response across tenant reconnect'],screenshots:['console-repositories.png','console-mobile.png']},null,2));
  }
});
