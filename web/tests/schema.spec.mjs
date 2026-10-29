// SPDX-License-Identifier: BUSL-1.1
import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import {spawn,execFileSync} from 'node:child_process';

test('schema maintenance preserves browser credential and recovers on retry',async({page,browser})=>{
  const fixture=JSON.parse(await fs.readFile(process.env.CRATECTL_CONSOLE_FIXTURE_JSON,'utf8'));
  const database=JSON.parse(await fs.readFile(fixture.owner_config,'utf8'));
  const dsn=new URL(database.owner);
  const name='cratectl-schema-browser-'+fixture.run;
  const env={...process.env,PGHOST:dsn.hostname,PGPORT:dsn.port,PGDATABASE:dsn.pathname.slice(1),PGUSER:decodeURIComponent(dsn.username),PGPASSWORD:decodeURIComponent(dsn.password),PGAPPNAME:name};
  const psql=path.join(fixture.root,'.cache/postgresql-16.15-install/bin/psql');
  const query=sql=>execFileSync(psql,['-X','-v','ON_ERROR_STOP=1','-At','-c',sql],{env,encoding:'utf8'}).trim();
  const checks=[],accessibility=[];
  let blocker;
  try{
    await page.goto(fixture.base_url+'/console/');await page.getByLabel('Credential file').setInputFiles(fixture.other_token);
    await page.waitForFunction(()=>document.querySelector('#credential')?.value.length>=32);
    await page.getByRole('button',{name:'Connect to installation',exact:true}).click();
    await expect(page.getByRole('heading',{name:'Repositories',exact:true})).toBeVisible();
    await expect(page.getByRole('region',{name:'Repository list'})).toBeVisible();
    blocker=spawn(psql,['-X','-v','ON_ERROR_STOP=1','-At'],{env,stdio:['pipe','ignore','ignore']});
    blocker.stdin.write('BEGIN;SELECT pg_advisory_xact_lock(731445922);\n');
    await expect.poll(()=>query(`SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name='${name}' AND l.locktype='advisory' AND l.objid=731445922 AND l.granted`)).toBe('1');
    const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/repositories'&&r.request().method()==='GET');
    await page.getByRole('button',{name:'Refresh',exact:true}).click();
    expect((await response).status()).toBe(503);
    await expect(page.getByRole('alert')).toContainText('Keep the credential');
    await expect(page.getByRole('button',{name:'Disconnect',exact:true})).toBeVisible();
    await expect(page.getByRole('button',{name:'Connect to installation',exact:true})).toHaveCount(0);
    checks.push('real database maintenance returns 503 and browser keeps the active credential');
    const result=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();
    expect(result.violations).toEqual([]);accessibility.push({state:'schema maintenance with stale repository data',violations:0});
    blocker.stdin.end('ROLLBACK;\n\\q\n');
    await new Promise((resolve,reject)=>{blocker.once('exit',code=>code===0?resolve():reject(new Error('owned lock session failed'))) });blocker=undefined;
    const recovered=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/repositories'&&r.request().method()==='GET');
    await page.getByRole('button',{name:'Try again',exact:true}).click();expect((await recovered).status()).toBe(200);
    await expect(page.getByRole('alert')).toHaveCount(0);await expect(page.getByRole('region',{name:'Repository list'})).toBeVisible();
    checks.push('browser retry succeeds with its original credential after maintenance releases admission');
    const token=(await fs.readFile(fixture.other_token,'utf8')).trim();expect(await page.content()).not.toContain(token);
    expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
    checks.push('maintenance recovery retains no credential in DOM or browser persistent storage');
  }finally{
    if(blocker){blocker.stdin.end('ROLLBACK;\n\\q\n');await new Promise(resolve=>blocker.once('exit',resolve))}
    await fs.writeFile(path.join(fixture.private,'schema-browser-proof.json'),JSON.stringify({checks,accessibility,browser:browser.version(),scope:'One real database admission interruption and credential-preserving retry in Chromium. Full rolling-upgrade and accessibility qualification remain open.'},null,2));
  }
});
