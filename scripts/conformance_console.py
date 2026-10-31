#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned real-database/browser journey. --serve holds a fixture for manual UI review."""
import argparse,datetime,hashlib,json,os,subprocess,time,urllib.parse,urllib.request,uuid
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');parser.add_argument('--serve',action='store_true');parser.add_argument('--binary-directory',type=Path,help='Owned candidate binary directory; defaults to bin without replacing active primary binaries');args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT);RUN=uuid.uuid4().hex[:10];PRIVATE=ROOT/'.private/console-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
BIN=(args.binary_directory or ROOT/'bin').resolve();BIN.relative_to(ROOT)
ARTIFACTS=[str((BIN/name).relative_to(ROOT))for name in ['cratectld','cratectl']]
env=dict(os.environ);runtime_env=dict(env)
for name in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']:runtime_env.pop(name,None)
base='http://127.0.0.1:38443';processes={};logs={};checks=[];worker_controls=[];worker_command=[]
def settings(name):
    out={}
    for line in subprocess.check_output(['.cache/go/bin/go','version','-m',name],text=True).splitlines():
        p=line.strip().split('\t')
        if len(p)==2 and p[0]=='build'and '='in p[1]:k,v=p[1].split('=',1);out[k]=v
    return out
scope=['cmd','internal','scripts','web','api','go.mod','go.sum','Makefile']
result={'run':RUN,'candidate':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'source_scope':scope,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*scope],text=True).strip()),'artifact_digests':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest()for n in ARTIFACTS},'build_identity':{n:settings(n)for n in ARTIFACTS},'checks':checks,'topology':'Real Chromium, native registry/worker and nonowner forced-RLS PostgreSQL. An empty owned database and two newly provisioned tenants; explicit loopback-only HTTP development profile on port 38443.','limits':['This browser run exercises the explicit loopback HTTP test profile. Normal native TLS trust remains separately qualified; browser CA deployment and network/production PKI are not established by this run.','Only tested views and named interactions are qualified. Full console, all WCAG behavior/assistive technologies/native browsers, production packaging and complete product scope remain open.','Management repository/artifact pages use current grants/policy, scoped encrypted scan cursors, bounded live traversal and server search. This is not a multi-page snapshot or full native-format index qualification.']}
result['build_source_matches_candidate']=all(s.get('vcs.modified')=='false'and s.get('vcs.revision')==result['candidate']for s in result['build_identity'].values())
def check(label,value):
    if not value:raise AssertionError(label)
    checks.append(label)
def private(path,data):
    p=PRIVATE/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data if isinstance(data,bytes)else json.dumps(data).encode());p.chmod(0o600);return p
def command(argv,runenv=env,cwd=ROOT):
    if Path(str(argv[0])).name=='playwright':
        with (PRIVATE/'commands.log').open('ab')as log:
            p=subprocess.Popen([str(a)for a in argv],env=runenv,cwd=cwd,stdout=log,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+300
            try:
                while p.poll()is None:
                    if time.monotonic()>deadline:raise TimeoutError('owned browser suite exceeded 300 seconds')
                    worker_control();time.sleep(.05)
            finally:
                if p.poll()is None:
                    p.terminate()
                    try:p.wait(timeout=10)
                    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
        if p.returncode:raise AssertionError('real browser suite failed; inspect its private report')
        return b''
    p=subprocess.run([str(a)for a in argv],env=runenv,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
    with (PRIVATE/'commands.log').open('ab')as log:log.write(p.stdout)
    if p.returncode:raise AssertionError('native fixture command failed: '+Path(str(argv[0])).name)
    return p.stdout
def start(name,argv):
    log=(PRIVATE/(name+'.log')).open('ab');logs[name]=log;processes[name]=subprocess.Popen([str(x)for x in argv],env=runtime_env,stdout=log,stderr=subprocess.STDOUT)
def stop(name):
    p=processes.pop(name,None)
    if p and p.poll()is None:
        p.terminate()
        try:p.wait(timeout=10)
        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
    if name in logs:logs.pop(name).close()
def worker_control():
    path=PRIVATE/'worker-control-request.json'
    if not path.exists():return
    if path.stat().st_size>4096:raise AssertionError('owned worker control input exceeded budget')
    request=json.loads(path.read_text());identity=str(uuid.UUID(request['id']));action=request['action']
    if worker_controls and worker_controls[-1]['id']==identity:return
    if action not in ['pause','resume']:raise AssertionError('owned worker control accepts pause/resume only')
    if action=='pause':stop('worker')
    elif 'worker'not in processes:start('worker',worker_command)
    response={'id':identity,'action':action,'state':'stopped'if action=='pause'else'running'}
    worker_controls.append(response);private('worker-control-reply.json',response)
try:
    if args.require_clean_build:check('console source and binaries match a clean candidate',not result['source_dirty']and result['build_source_matches_candidate'])
    owner=urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN']);database='cratectl_console_'+RUN
    pgenv=dict(env,PGHOST=owner.hostname,PGPORT=str(owner.port or 5432),PGUSER=urllib.parse.unquote(owner.username),PGPASSWORD=urllib.parse.unquote(owner.password),PGDATABASE=owner.path.lstrip('/'))
    command([ROOT/'.cache/postgresql-16.15-install/bin/psql','-X','-v','ON_ERROR_STOP=1','-At','-c','CREATE DATABASE '+database],pgenv)
    def database_dsn(dsn):
        u=urllib.parse.urlsplit(dsn);return urllib.parse.urlunsplit((u.scheme,u.netloc,'/'+database,u.query,u.fragment))
    initial=dict(env,CRATECTL_OWNER_DSN=database_dsn(env['CRATECTL_OWNER_DSN']),CRATECTL_DSN=database_dsn(env['CRATECTL_DSN']))
    owner_config=private('database.json',{'owner':initial['CRATECTL_OWNER_DSN'],'runtime':initial['CRATECTL_DSN']})
    receipt=json.loads(command([BIN/'cratectld','init','--directory',PRIVATE/'installation','--tenant','console-a'],initial))
    for identity,tenant,role in [('reader','console-a','reader'),('writer','console-a','writer'),('repair-admin','console-a','admin'),('schedule-admin','console-a','admin'),('schedule-recovery','console-a','admin'),('retention-admin','console-a','admin'),('retention-recovery','console-a','admin'),('retention-auto-admin','console-a','admin'),('retention-auto-recovery','console-a','admin'),('hold-admin','console-a','admin'),('hold-recovery','console-a','admin'),('case-admin','console-a','admin'),('case-recovery','console-a','admin'),('matter-admin','console-a','admin'),('matter-approver','console-a','admin'),('matter-recovery','console-a','admin'),('other','console-b','admin')]:
        command([BIN/'cratectld','provision','--tenant',tenant,'--actor',identity,'--role',role,'--token-file',PRIVATE/(identity+'.token')],initial)
    install=PRIVATE/'installation'
    fixture={'run':RUN,'base_url':base,'root':str(ROOT),'binary_directory':str(BIN),'private':str(PRIVATE),'owner_config':str(owner_config),'admin_token':str(install/'admin.token'),'worker_token':str(install/'worker.token'),'reader_token':str(PRIVATE/'reader.token'),'writer_token':str(PRIVATE/'writer.token'),'other_token':str(PRIVATE/'other.token'),'repair_admin_token':str(PRIVATE/'repair-admin.token'),'schedule_admin_token':str(PRIVATE/'schedule-admin.token'),'schedule_recovery_token':str(PRIVATE/'schedule-recovery.token')}
    fixture.update(retention_admin_token=str(PRIVATE/'retention-admin.token'),retention_recovery_token=str(PRIVATE/'retention-recovery.token'),worker_control_request=str(PRIVATE/'worker-control-request.json'),worker_control_reply=str(PRIVATE/'worker-control-reply.json'))
    fixture.update(retention_auto_admin_token=str(PRIVATE/'retention-auto-admin.token'),retention_auto_recovery_token=str(PRIVATE/'retention-auto-recovery.token'))
    fixture.update(hold_admin_token=str(PRIVATE/'hold-admin.token'),hold_recovery_token=str(PRIVATE/'hold-recovery.token'))
    fixture.update(case_admin_token=str(PRIVATE/'case-admin.token'),case_recovery_token=str(PRIVATE/'case-recovery.token'))
    fixture.update(matter_admin_token=str(PRIVATE/'matter-admin.token'),matter_approver_token=str(PRIVATE/'matter-approver.token'),matter_recovery_token=str(PRIVATE/'matter-recovery.token'))
    fixture_path=private('browser-fixture.json',fixture)
    token=(install/'admin.token').read_text().strip()
    private('npmrc',f'registry={base}/npm/web-packages/\n//127.0.0.1:38443/npm/web-packages/:_authToken={token}\n'.encode())
    package=PRIVATE/'npm-package';package.mkdir();(package/'package.json').write_text(json.dumps({'name':'cratectl-console-proof','version':'1.0.0','main':'index.js','description':'Owned console native-client fixture','license':'MIT'}));(package/'index.js').write_text('module.exports=42;\n')
    start('registry',[BIN/'cratectld','serve','--config',receipt['runtime_config'],'--dev-loopback-http','--public-url',base])
    for _ in range(150):
        if processes['registry'].poll()is not None:raise AssertionError('owned registry exited')
        try:
            with urllib.request.urlopen(base+'/health/ready',timeout=1)as r:
                if r.status==200:break
        except Exception:time.sleep(.05)
    else:raise AssertionError('owned console readiness timeout')
    check('packaged console shell is public and contains no tenant credential',token.encode()not in urllib.request.urlopen(base+'/console/').read())
    worker_command=[BIN/'cratectld','worker','--config',receipt['runtime_config'],'--poll','50ms']
    start('worker',worker_command)
    if args.serve:
        print('Owned console fixture ready: '+str(fixture_path),flush=True)
        while all(p.poll()is None for p in processes.values()):worker_control();time.sleep(.05)
        raise AssertionError('owned process exited during UI review')
    browser_env=dict(runtime_env,CRATECTL_CONSOLE_FIXTURE_JSON=str(fixture_path),PLAYWRIGHT_BROWSERS_PATH=str(ROOT/'.cache/playwright-browsers'),PLAYWRIGHT_JSON_OUTPUT_NAME=str(PRIVATE/'browser-results.json'))
    command([ROOT/'web/node_modules/.bin/playwright','test','--config',ROOT/'web/playwright.config.mjs'],browser_env)
    report=json.loads((PRIVATE/'browser-results.json').read_text());check('real-browser workflow suite passed without skips or flaky results',report['stats']['unexpected']==0 and report['stats']['skipped']==0 and report['stats']['flaky']==0 and report['stats']['expected']==13)
    matters=json.loads((PRIVATE/'hold-matters-browser-proof.json').read_text());result['hold_matters_browser']=matters;checks.extend(matters['checks'])
    cases=json.loads((PRIVATE/'hold-cases-browser-proof.json').read_text());result['hold_cases_browser']=cases;checks.extend(cases['checks'])
    holds=json.loads((PRIVATE/'hold-browser-proof.json').read_text());result['hold_browser']=holds;checks.extend(holds['checks'])
    retention_schedule=json.loads((PRIVATE/'retention-schedule-browser-proof.json').read_text());result['retention_schedule_browser']=retention_schedule;checks.extend(retention_schedule['checks'])
    retention=json.loads((PRIVATE/'retention-browser-proof.json').read_text());result['retention_browser']=retention;checks.extend(retention['checks']);result['worker_controls']=worker_controls
    schedule=json.loads((PRIVATE/'schedule-browser-proof.json').read_text());result['schedule_browser']=schedule;checks.extend(schedule['checks'])
    repair=json.loads((PRIVATE/'repair-browser-proof.json').read_text());result['repair_browser']=repair;checks.extend(repair['checks'])
    configuration=json.loads((PRIVATE/'source-configuration-browser-proof.json').read_text());result['source_configuration_browser']=configuration;checks.extend(configuration['checks'])
    lifecycle=json.loads((PRIVATE/'lifecycle-browser-proof.json').read_text());result['lifecycle_browser']=lifecycle;checks.extend(lifecycle['checks'])
    schema=json.loads((PRIVATE/'schema-browser-proof.json').read_text());result['schema_browser']=schema;checks.extend(schema['checks'])
    paging=json.loads((PRIVATE/'pagination-browser-proof.json').read_text());result['pagination_browser']=paging;checks.extend(paging['checks']);proof=json.loads((PRIVATE/'browser-proof.json').read_text());result['browser_stats']=report['stats'];result['browser']=proof;checks.extend(proof['checks']);result['database']=database
    runtime_config=json.loads(Path(receipt['runtime_config']).read_text());key_file=Path(runtime_config['pagination_key_file']);key_bytes=key_file.read_bytes()
    check('pagination key is a private durable file outside the artifact root',key_file.stat().st_mode&0o077==0 and key_file.parent==install)
    def list_request(cursor=''):
        request=urllib.request.Request(base+'/api/v1/repositories?limit=1'+('&cursor='+urllib.parse.quote(cursor)if cursor else''),headers={'Authorization':'Bearer '+(PRIVATE/'other.token').read_text().strip()})
        with urllib.request.urlopen(request,timeout=10)as response:return json.loads(response.read())
    first=list_request();check('native management first page has a continuation beyond the page bound',bool(first['next'])and len(first['items'])==1)
    stop('registry');start('registry',[BIN/'cratectld','serve','--config',receipt['runtime_config'],'--dev-loopback-http','--public-url',base])
    for _ in range(150):
        try:
            with urllib.request.urlopen(base+'/health/ready',timeout=1)as response:
                if response.status==200:break
        except Exception:time.sleep(.05)
    else:raise AssertionError('restarted registry readiness timeout')
    second=list_request(first['next']);check('actual registry restart preserves key and accepts the earlier opaque cursor',key_file.read_bytes()==key_bytes and len(second['items'])==1 and second['items'][0]['name']!=first['items'][0]['name'])
    result['status']='passed'
except KeyboardInterrupt:
    result['status']='manual-review-stopped'if args.serve else'failed'
except BaseException as e:result['status']='failed';result['failure']=type(e).__name__+': '+str(e)
finally:
    for name in list(processes):stop(name)
    target=ROOT/'evidence'/datetime.datetime.now(datetime.timezone.utc).date().isoformat();target.mkdir(parents=True,exist_ok=True);path=target/('console-'+RUN+'.json');path.write_text(json.dumps(result,indent=2)+'\n')
    print(result['status'].upper()+': '+str(len(checks))+' assertions; real operator console; '+str(path))
if result['status']=='failed':raise SystemExit(result.get('failure','browser workflow failed'))
