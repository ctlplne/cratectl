// SPDX-License-Identifier: BUSL-1.1
import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile);

test('operator explicitly authorizes future retirement and recovers fenced automatic work',async({page,browser,request})=>{
  const fixture=JSON.parse(await fs.readFile(process.env.CRATECTL_CONSOLE_FIXTURE_JSON,'utf8'));
  const original=(await fs.readFile(fixture.retention_auto_admin_token,'utf8')).trim(),replacement=(await fs.readFile(fixture.retention_auto_recovery_token,'utf8')).trim();let token=original;
  const repo='retention-auto-ui-'+fixture.run,name='age',endpoint='/api/v1/repositories/'+repo+'/retention-policies/'+name,schedulePath=endpoint+'/schedule',checks=[],accessibility=[];
  const api=(url,options={})=>request.fetch(fixture.base_url+url,{...options,headers:{Authorization:'Bearer '+token,'Idempotency-Key':'browser-retention-auto-'+crypto.randomUUID(),...options.headers}});
  const value=async url=>{const response=await api(url);expect(response.status()).toBe(200);return response.json()};
  const schedule=()=>value(schedulePath),runs=async()=>(await value(schedulePath+'/runs?limit=100')).items;
  const detail=id=>value('/api/v1/maintenance/retention-runs/'+id),modal=()=>page.getByRole('dialog');
  const consent=()=>page.getByRole('checkbox',{name:'I authorize future complete target captures under these policy and source revisions',exact:true});
  let paused=false,lockProcess,sql,pgenv,barrierInstalled=false;
  const timingState=path.join(fixture.private,'retention-schedule-timing.json'),timingHelpers=[];
  async function axe(state){const result=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();expect(result.violations).toEqual([]);accessibility.push({state,violations:0})}
  async function control(action){
    const id=crypto.randomUUID(),temporary=fixture.worker_control_request+'.next';
    await fs.writeFile(temporary,JSON.stringify({id,action}),{mode:0o600});await fs.rename(temporary,fixture.worker_control_request);
    await expect.poll(async()=>{try{const v=JSON.parse(await fs.readFile(fixture.worker_control_reply,'utf8'));return v.id===id?v.state:''}catch{return''}},{timeout:20000}).toBe(action==='pause'?'stopped':'running');paused=action==='pause';
  }
  async function login(file){
    await page.goto(fixture.base_url+'/console/');await page.getByLabel('Credential file').setInputFiles(file);await page.waitForFunction(()=>document.querySelector('#credential')?.value.length>=32);await page.getByRole('button',{name:'Connect to installation',exact:true}).click();
    await page.getByRole('link',{name:'Storage',exact:true}).click();await page.getByRole('button',{name:'Retention',exact:true}).click();await page.getByLabel('OCI repository',{exact:true}).fill(repo);await page.getByRole('button',{name:'Load retention policies',exact:true}).click();
    await expect(page.getByRole('region',{name:'Retention policies',exact:true}).getByRole('row').filter({hasText:name})).toBeVisible();
  }
  async function openSchedule(){
    await page.getByRole('button',{name:'Refresh retention policies',exact:true}).click();await page.getByRole('region',{name:'Retention policies',exact:true}).getByRole('row').filter({hasText:name}).getByRole('button',{name:'Inspect retention policy',exact:true}).click();
    await page.getByRole('button',{name:'Inspect automatic retirement',exact:true}).click();await expect(page.getByRole('button',{name:'Refresh automatic retirement',exact:true})).toBeVisible();
  }
  async function editor({enabled=true,immediate=true,limit=100,reason='Explicitly approve future bounded retirement'}={}){
    await page.getByRole('button',{name:/^(Configure|Edit) automatic retirement$/}).click();await expect(page.getByLabel('Retirement interval in seconds',{exact:true})).toBeFocused();
    await page.getByLabel('Retirement interval in seconds',{exact:true}).fill('60');await page.getByLabel('Maximum live manifests per run',{exact:true}).fill(String(limit));
    await page.getByRole('checkbox',{name:'Enable automatic retirement',exact:true}).setChecked(enabled);await expect(consent()).not.toBeChecked();
    if(enabled){await consent().check();await page.getByRole('checkbox',{name:'Make the first retirement slot due immediately',exact:true}).setChecked(immediate)}
    await page.getByLabel('Automatic retirement change reason',{exact:true}).fill(reason);await page.getByRole('button',{name:'Preview automatic retirement',exact:true}).click();await expect(modal().getByText(/Automatic retirement preview:/)).toBeVisible();
  }
  async function apply(enabled=true){await page.getByRole('button',{name:enabled?'Authorize scheduled retirement':'Apply retirement pause',exact:true}).click();await expect(modal()).toBeHidden()}
  async function publish(label){
    const body=JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:[],annotations:{label}}),digest=createHash('sha256').update(body).digest('hex');
    expect((await api('/v2/'+repo+'/app/manifests/latest',{method:'PUT',data:body,headers:{'Content-Type':'application/vnd.oci.image.index.v1+json'}})).status()).toBe(201);return{body,digest,path:'app/manifests/sha256:'+digest};
  }
  async function completedAfter(previous){
    await expect.poll(async()=>(await schedule()).last_job??'',{timeout:30000}).not.toBe(previous??'');const id=(await schedule()).last_job;
    await expect.poll(async()=>(await detail(id)).job.state,{timeout:30000}).toBe('succeeded');return detail(id);
  }
  async function dropBarrier(){
    try{
      if(barrierInstalled){await sql('DROP TRIGGER IF EXISTS cratectl_retention_console_claim_barrier ON cratectl.jobs; DROP FUNCTION IF EXISTS cratectl.retention_console_claim_barrier()');barrierInstalled=false}
    }finally{
      if(lockProcess){
        const child=lockProcess;lockProcess=undefined;
        if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');
        try{await new Promise((resolve,reject)=>{if(child.exitCode!==null||child.signalCode!==null){resolve();return}const timer=setTimeout(()=>reject(new Error('Owned timing controller did not stop')),10000);child.once('exit',()=>{clearTimeout(timer);resolve()})})}
        finally{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');await exec('python3',[path.join(fixture.root,'scripts/sql_timing.py'),'close','--state',timingState],{env:pgenv,timeout:15000})}
        const state=JSON.parse(await fs.readFile(timingState,'utf8'));
        expect(child.exitCode).toBe(0);expect(state.status).toBe('closed');expect(state.cleanup.backend_absent).toBe(true);expect(Number.isSafeInteger(state.backend.pid)).toBe(true);
        const stamp=state.backend.backend_start.replaceAll("'","''");
        expect((await sql(`SELECT count(*) FROM pg_stat_activity WHERE pid=${state.backend.pid} AND backend_start='${stamp}'::timestamptz`)).stdout.trim()).toBe('0');
        timingHelpers.push(state);checks.push('owned SQL timing backend is absent before the browser resumes worker recovery');
      }
    }
  }
  try{
    await control('pause');
    expect((await api('/api/v1/repositories',{method:'POST',data:{name:repo,format:'oci'}})).status()).toBe(201);
    const eligible=await publish('old-eligible'),held=await publish('old-held'),current=await publish('current');
    expect((await api('/api/v1/repositories/'+repo+'/artifacts/lifecycle',{method:'PUT',data:{path:held.path,digest:held.digest,action:'hold',expected_revision:0,reason:'Keep the owned held release'}})).status()).toBe(200);
    const session=await value('/api/v1/session'),database=JSON.parse(await fs.readFile(fixture.owner_config,'utf8')),owner=new URL(database.owner);
    expect(repo).toMatch(/^[a-z][a-z0-9-]{0,62}$/);expect(session.tenant).toMatch(/^[a-z][a-z0-9-]{0,62}$/);
    pgenv={...process.env,PGHOST:owner.hostname,PGPORT:owner.port,PGUSER:decodeURIComponent(owner.username),PGPASSWORD:decodeURIComponent(owner.password),PGDATABASE:owner.pathname.slice(1)};const psql=path.join(fixture.root,'.cache/postgresql-16.15-install/bin/psql');
    sql=command=>exec(psql,['-X','-At','-v','ON_ERROR_STOP=1','-c',command],{env:pgenv});
    await sql(`UPDATE cratectl.artifacts SET created_at=created_at-interval '600 seconds' WHERE tenant='${session.tenant}' AND repository='${repo}'`);
    const policy={expected_revision:0,min_age_seconds:60,keep_last:1,protect_tagged:true,enabled:true,reason:'Protect held and current tagged releases'};
    expect((await api(endpoint,{method:'PUT',data:policy})).status()).toBe(200);
    await login(fixture.retention_auto_admin_token);await openSchedule();await expect(page.getByRole('heading',{name:'Automatic retirement is not configured',exact:true})).toBeVisible();await axe('automatic retirement absent with explicit future authority explanation');
    await page.getByRole('button',{name:'Configure automatic retirement',exact:true}).click();await expect(consent()).not.toBeChecked();await page.getByLabel('Automatic retirement change reason',{exact:true}).fill('Approval requires deliberate future consent');
    let previews=0;const count=request=>{if(new URL(request.url()).pathname===schedulePath&&request.method()==='PUT')previews++};page.on('request',count);
    await page.getByRole('button',{name:'Preview automatic retirement',exact:true}).click();expect(await consent().evaluate(input=>input.validity.valueMissing)).toBe(true);expect(previews).toBe(0);page.off('request',count);await axe('future-capture consent starts unchecked and is required');await page.keyboard.press('Escape');
    await openSchedule();await editor({limit:2});expect((await api(schedulePath)).status()).toBe(404);await axe('future-capture configuration preview has no durable effects');await page.screenshot({path:path.join(fixture.private,'retention-schedule-preview.png')});
    const attempts=[];let cut=true;
    await page.route('**'+schedulePath,async route=>{
      const r=route.request();if(r.method()==='PUT'&&!r.postDataJSON().dry_run){attempts.push({key:r.headers()['idempotency-key'],body:r.postData()});if(cut){cut=false;expect((await route.fetch()).status()).toBe(201);await route.abort('connectionfailed');return}}await route.continue();
    });
    await page.getByRole('button',{name:'Authorize scheduled retirement',exact:true}).click();await expect(modal().getByRole('alert')).toContainText('Automatic retirement approval not confirmed');await expect(page.getByRole('button',{name:'Edit automatic retirement plan',exact:true})).toBeDisabled();await axe('uncertain future approval freezes original request and key');
    await page.getByRole('button',{name:'Retry same automatic retirement request',exact:true}).click();await expect(modal()).toBeHidden();await page.unroute('**'+schedulePath);expect(attempts).toHaveLength(2);expect(attempts[0]).toEqual(attempts[1]);expect((await schedule()).revision).toBe(1);expect(await runs()).toHaveLength(0);
    checks.push('required fresh future consent; read-only preview; lost actual 201 reply retries identical request bytes/key and retains one approval without worker admission');
    const due=(await schedule()).next_due_at;await control('resume');await expect.poll(async()=>(await schedule()).last_error,{timeout:30000}).toBe('plan_budget_exceeded');expect((await schedule()).next_due_at).toBe(due);expect(await runs()).toHaveLength(0);
    await openSchedule();await expect(modal().getByText('plan_budget_exceeded',{exact:true})).toBeVisible();await axe('complete-set budget deferral admits no partial automatic run');await editor();await apply();
    const first=await completedAfter();expect(first.plan.schedule.revision).toBe(2);expect(first.plan.targets).toBe(3);expect(first.retired).toBe(1);expect(first.skipped).toBe(2);expect(first.bytes_reclaimed).toBe(0);
    expect((await api('/v2/'+repo+'/'+eligible.path)).status()).toBe(404);for(const item of[held,current])expect((await api('/v2/'+repo+'/'+item.path)).status()).toBe(200);
    await openSchedule();await page.getByRole('button',{name:'Inspect last scheduled run',exact:true}).click();await expect(modal().getByText(/Scheduled capture · schedule revision 2/)).toBeVisible();await expect(modal().getByText(/All captured targets have committed outcomes\./)).toBeVisible();await axe('automatic capture provenance and immutable native outcomes');await page.getByRole('button',{name:'Review current retirement schedule',exact:true}).click();await editor({enabled:false});await apply(false);
    checks.push('real worker defers an oversized complete capture without advancing its due slot; new bounded approval retires one target and preserves current tag/hold with zero reclaimed bytes');
    await openSchedule();await expect(modal().getByText('Future captures are paused.',{exact:false})).toBeVisible();await axe('automatic retirement paused with retained outcomes');await page.setViewportSize({width:390,height:844});await axe('paused automatic retirement at a narrow Chromium viewport');await page.screenshot({path:path.join(fixture.private,'retention-schedule-paused-narrow.png')});await page.setViewportSize({width:1440,height:1000});await page.getByRole('button',{name:'Inspect last scheduled run',exact:true}).click();
    await page.getByRole('region',{name:'Retirement outcomes',exact:true}).getByRole('row').filter({hasText:eligible.digest}).getByRole('button',{name:'Inspect lifecycle or restore',exact:true}).click();await page.getByLabel('Reason',{exact:true}).fill('Restore exact retained bytes while automatic captures are paused');await page.getByRole('button',{name:'Preview impact',exact:true}).click();await page.getByRole('button',{name:'Apply restore',exact:true}).click();await expect(modal()).toBeHidden();
    const restored=await api('/v2/'+repo+'/'+eligible.path);expect(restored.status()).toBe(200);expect(createHash('sha256').update(await restored.body()).digest('hex')).toBe(eligible.digest);
    // Owned SQL claim barrier creates an actual admitted pending job. It is a timing fixture,
    // not a product configuration, authority bypass, or metadata repair mechanism.
    await control('pause');const lock=1000000+parseInt(fixture.run.slice(0,6),16);
    const timingLog=await fs.open(path.join(fixture.private,'retention-schedule-timing.log'),'wx',0o600);
    lockProcess=spawn('python3',[path.join(fixture.root,'scripts/sql_timing.py'),'hold','--state',timingState,'--label','cratectl-barrier-browser-'+fixture.run,'--lock',String(lock),'--seconds','180'],{env:pgenv,stdio:['ignore',timingLog.fd,timingLog.fd]});await timingLog.close();
    await expect.poll(async()=>{if(lockProcess.exitCode!==null||lockProcess.signalCode!==null)throw new Error('Owned timing controller exited before readiness');try{return JSON.parse(await fs.readFile(timingState,'utf8')).status}catch(error){if(error.code==='ENOENT')return'';throw error}},{timeout:15000}).toBe('ready');
    const ownedTiming=JSON.parse(await fs.readFile(timingState,'utf8'));expect(Number.isSafeInteger(ownedTiming.backend.pid)).toBe(true);
    await expect.poll(async()=>(await sql(`SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=${ownedTiming.backend.pid} AND locktype='advisory' AND objid=${lock} AND classid=0 AND objsubid=1 AND granted)`)).stdout.trim()).toBe('t');
    await sql(`CREATE FUNCTION cratectl.retention_console_claim_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='repository.retention' AND NEW.state='running' AND NEW.payload->'policy'->>'repository'='${repo}' THEN PERFORM pg_advisory_xact_lock(${lock}); END IF; RETURN NEW; END $$; CREATE TRIGGER cratectl_retention_console_claim_barrier BEFORE UPDATE ON cratectl.jobs FOR EACH ROW EXECUTE FUNCTION cratectl.retention_console_claim_barrier()`);barrierInstalled=true;
    await openSchedule();await editor();await apply();const prior=first.job.sequence+':'+first.job.task;await control('resume');
    await expect.poll(async()=>(await schedule()).last_job??'',{timeout:30000}).not.toBe(prior);const pending=(await schedule()).last_job;await expect.poll(async()=>(await detail(pending)).job.state).toBe('pending');await control('pause');
    await openSchedule();await editor({enabled:false});await apply(false);await dropBarrier();await control('resume');await expect.poll(async()=>(await detail(pending)).job.state,{timeout:30000}).toBe('failed');expect((await detail(pending)).retired).toBe(0);
    await openSchedule();await page.getByRole('button',{name:'Inspect last scheduled run',exact:true}).click();await expect(modal().getByText(/The schedule was paused or replaced/)).toBeVisible();await expect(page.getByRole('button',{name:'Retry retirement run',exact:true})).toBeDisabled();await axe('paused schedule fences a real pending capture and directs new approval');await page.keyboard.press('Escape');
    checks.push('paused schedule permits exact native restore; owned SQL timing barrier exposes actual pending automatic capture; process stop plus explicit pause fences it with retention_schedule_changed and zero effects');
    await control('pause');await openSchedule();await editor();await apply();
    await exec(path.join(fixture.binary_directory??path.join(fixture.root,'bin'),'cratectld'),['revoke','--token-file',fixture.retention_auto_admin_token],{env:{...process.env,CRATECTL_OWNER_DSN:database.owner}});token=replacement;await control('resume');
    await page.getByRole('button',{name:'Refresh retention policies',exact:true}).click();await expect(page.getByRole('button',{name:'Connect to installation',exact:true})).toBeVisible();await expect.poll(async()=>(await schedule()).last_error,{timeout:30000}).toBe('requester_authorization_unavailable');expect((await schedule()).last_job).toBe(pending);
    await login(fixture.retention_auto_recovery_token);await openSchedule();await expect(modal().getByText('requester_authorization_unavailable',{exact:true})).toBeVisible();await axe('revoked authorizing credential blocks future captures');await editor();await apply();const recovered=await completedAfter(pending);expect(recovered.retired).toBe(1);expect((await detail(pending)).job.state).toBe('failed');
    await openSchedule();await editor({enabled:false});await apply(false);checks.push('revoked credential logs out the browser and blocks admission; replacement administrator supplies a fresh future approval; previous failed capture stays immutable');
    await control('pause');await openSchedule();await editor();await apply();expect((await api(endpoint,{method:'PUT',data:{...policy,expected_revision:1,reason:'New exact policy revision requires new future approval'}})).status()).toBe(200);await control('resume');
    await expect.poll(async()=>(await schedule()).last_error,{timeout:30000}).toBe('policy_changed');await openSchedule();await expect(modal().getByText('policy_changed',{exact:true})).toBeVisible();await axe('changed policy binding requires explicit future reapproval');
    await control('pause');await editor({immediate:false});await expect(modal().getByText(/This approval binds current policy revision 2 and source revision 0/)).toBeVisible();await apply();expect((await schedule()).policy.revision).toBe(2);await openSchedule();await editor({enabled:false});await apply(false);await control('resume');
    checks.push('changed policy blocks old future authority; console binds the current exact policy/source revisions and demands fresh consent');
    // Seed real immutable configuration pages through the public API, while paused.
    let currentSchedule=await schedule();while(currentSchedule.revision<53){const response=await api(schedulePath,{method:'PUT',data:{expected_revision:currentSchedule.revision,expected_policy_revision:2,expected_source_revision:0,interval_seconds:60,max_targets:100,enabled:false,authorize_future_retirements:false,reason:'Owned immutable configuration paging fixture'}});expect(response.status()).toBe(200);currentSchedule=await response.json()}
    await openSchedule();await page.getByRole('combobox',{name:'Automatic retirement records',exact:true}).selectOption('history');await expect(modal().getByRole('heading',{name:/^Schedule configuration revision /})).toHaveCount(50);const pages=page.getByRole('navigation',{name:'Automatic retirement record pages',exact:true});await pages.getByRole('button',{name:'Next page',exact:true}).click();await expect(modal().getByRole('heading',{name:/^Schedule configuration revision /})).toHaveCount(3);await axe('automatic configuration history final server page');await pages.getByRole('button',{name:'Previous page',exact:true}).click();
    await modal().locator('section.message').filter({has:page.getByRole('heading',{name:'Schedule configuration revision 1',exact:true})}).getByRole('button',{name:'Prepare these settings for new approval',exact:true}).click();await expect(consent()).not.toBeChecked();await expect(page.getByLabel('Maximum live manifests per run',{exact:true})).toHaveValue('2');await expect(modal().getByText(/This approval binds current policy revision 2 and source revision 0/)).toBeVisible();await axe('historical settings copy uses current bindings and unchecked future consent');
    checks.push('53 real schedule revisions page forward/backward; copying historical settings keeps current bindings and requires new future consent');
    await consent().check();await page.getByLabel('Automatic retirement change reason',{exact:true}).fill('Review historical settings under current bindings');await page.getByRole('button',{name:'Preview automatic retirement',exact:true}).click();await expect(modal().getByText(/Automatic retirement preview:/)).toBeVisible();
    expect((await api(schedulePath,{method:'PUT',data:{expected_revision:53,expected_policy_revision:2,expected_source_revision:0,interval_seconds:60,max_targets:100,enabled:false,authorize_future_retirements:false,reason:'A second administrator preserves the paused schedule'}})).status()).toBe(200);
    await page.getByRole('button',{name:'Authorize scheduled retirement',exact:true}).click();await expect(modal().getByRole('alert')).toContainText('Automatic retirement approval rejected');await expect(modal().getByRole('alert')).toContainText('retention_schedule_changed');await expect(page.getByRole('button',{name:'Edit automatic retirement plan',exact:true})).toBeEnabled();expect((await schedule()).revision).toBe(54);expect((await schedule()).enabled).toBe(false);await axe('stale exact schedule revision rejects future approval without effects');await page.keyboard.press('Escape');checks.push('actual concurrent schedule replacement rejects an older browser preview with 409 and preserves the newer paused revision');
    // An empty proxy proves source-binding administration without performing an upstream fetch.
    await control('pause');const proxy='retention-auto-source-'+fixture.run,proxyBase='/api/v1/repositories/'+proxy,proxyPolicy=proxyBase+'/retention-policies/'+name;
    const settings={upstream:{url:'https://first.invalid/approved/',networks:['0.0.0.0/0']},cache:{fresh_seconds:300,negative_seconds:30,stale_seconds:0,require_checksum:true}};
    expect((await api('/api/v1/repositories',{method:'POST',data:{name:proxy,format:'oci',mode:'proxy',settings}})).status()).toBe(201);expect((await api(proxyPolicy,{method:'PUT',data:policy})).status()).toBe(200);
    expect((await api(proxyPolicy+'/schedule',{method:'PUT',data:{expected_revision:0,expected_policy_revision:1,expected_source_revision:0,interval_seconds:60,max_targets:100,enabled:true,authorize_future_retirements:true,run_immediately:true,reason:'Approve future captures only for the original source'}})).status()).toBe(201);
    expect((await api(proxyBase+'/configuration',{method:'PUT',data:{expected_revision:0,settings:{...settings,upstream:{...settings.upstream,url:'https://second.invalid/approved/'}},reason:'Replace the owned empty proxy source'}})).status()).toBe(200);await control('resume');
    await expect.poll(async()=>(await value(proxyPolicy+'/schedule')).last_error,{timeout:30000}).toBe('source_changed');expect((await value(proxyPolicy+'/schedule/runs?limit=100')).items).toHaveLength(0);
    await page.getByLabel('OCI repository',{exact:true}).fill(proxy);await page.getByRole('button',{name:'Load retention policies',exact:true}).click();await openSchedule();await expect(modal().getByText('source_changed',{exact:true})).toBeVisible();await axe('changed source binding blocks future captures');
    await editor({immediate:false});await expect(modal().getByText(/This approval binds current policy revision 1 and source revision 1/)).toBeVisible();await apply();expect((await value(proxyPolicy+'/schedule')).source_revision).toBe(1);await openSchedule();await editor({enabled:false});await apply(false);checks.push('actual source replacement blocks an empty proxy schedule; console reapproval binds current source revision without fetching upstream content or claiming byte verification');
    expect(await page.content()).not.toContain(original);expect(await page.content()).not.toContain(replacement);expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);checks.push('credentials remain absent from console DOM and persistent browser storage');
  }finally{
    if(barrierInstalled||lockProcess){if(!paused)await control('pause');await dropBarrier()}
    if(paused)await control('resume');
    await fs.writeFile(path.join(fixture.private,'retention-schedule-browser-proof.json'),JSON.stringify({checks,accessibility,timing_helpers:timingHelpers,browser:browser.version(),scope:'Real PostgreSQL, Chromium and owned registry/worker. Future-authority consent, exact lost-response retry, complete-set deferral, scheduled native retirement/restore, process-stop pause fence using a declared owned SQL claim timing barrier, revoked-credential/changed-policy/empty-proxy-source reapproval, concurrent revision rejection and immutable configuration pages. Artifact age and claim timing are owned SQL fixtures. Empty proxy source administration performs no upstream fetch or byte verification. Real scheduled-retirement cadence, other browsers/assistive technology, physical GC, scale and broad readiness are not established.'},null,2));
  }
});
