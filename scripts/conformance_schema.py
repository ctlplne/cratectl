#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Real legacy-binary adoption, process interruption and preserved npm consumption."""
import argparse,datetime,hashlib,json,os,subprocess,time,urllib.parse,urllib.request,uuid
from pathlib import Path

parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');options=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT);RUN=uuid.uuid4().hex[:10]
PRIVATE=ROOT/'.private/schema-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
OLD=ROOT/'.cache/pagination-production/cratectld';NEW=ROOT/'bin/cratectld';BASE='http://127.0.0.1:38443'
env=dict(os.environ);public=dict(env)
for name in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']:public.pop(name,None)
checks=[];processes={};logs={};started=time.monotonic()
def identity(binary):
    settings={}
    for line in subprocess.check_output([ROOT/'.cache/go/bin/go','version','-m',binary],text=True).splitlines():
        values=line.strip().split('\t')
        if len(values)==2 and values[0]=='build' and '='in values[1]:key,value=values[1].split('=',1);settings[key]=value
    return settings
candidate=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
scope=['cmd','internal','scripts','web','api','go.mod','go.sum','Makefile']
result={'run':RUN,'candidate':candidate,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*scope]).strip()),'artifact_digests':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in [OLD,NEW,ROOT/'bin/cratectl']},'build_identity':{str(p.relative_to(ROOT)):identity(p)for p in [OLD,NEW,ROOT/'bin/cratectl']},'checks':checks,'topology':'Native macOS legacy/current registry CLI processes, actual SIGKILL during uncommitted DDL, real PostgreSQL 16.15 restricted runtime, stock npm; explicit loopback HTTP fixture.','limits':['Legacy adoption is a controlled maintenance operation with registry and workers stopped. Pre-gate binaries do not cooperate with new transaction admission.','The fault is an owned database event trigger and advisory barrier; no production pause hook is compiled into the runtime.','This is not rolling/zero-downtime adoption, whole-transfer draining, expand/contract compatibility, HA, downgrade, backup/restore or independent-host qualification.']}
result['build_source_matches_candidate']=all(result['build_identity'][str(p.relative_to(ROOT))].get('vcs.revision')==candidate and result['build_identity'][str(p.relative_to(ROOT))].get('vcs.modified')=='false'for p in [NEW,ROOT/'bin/cratectl'])
def check(label,condition):
    if not condition:raise AssertionError(label)
    checks.append(label)
def command(argv,runenv=public,cwd=ROOT,ok=True):
    completed=subprocess.run([str(x)for x in argv],env=runenv,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90)
    with (PRIVATE/'commands.log').open('ab')as log:log.write(completed.stdout)
    if (completed.returncode==0)!=ok:raise AssertionError('native command returned unexpected status: '+Path(str(argv[0])).name)
    return completed.stdout
def start(name,argv,runenv=public,pipe=False):
    logs[name]=(PRIVATE/(name+'.log')).open('ab')
    processes[name]=subprocess.Popen([str(x)for x in argv],env=runenv,stdin=subprocess.PIPE if pipe else subprocess.DEVNULL,stdout=logs[name],stderr=subprocess.STDOUT)
    return processes[name]
def stop(name):
    process=processes.pop(name,None)
    if process and process.poll()is None:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
    if name in logs:logs.pop(name).close()
def wait_for(label,condition):
    for _ in range(250):
        if condition():return
        time.sleep(.02)
    raise AssertionError(label)
def private(name,data):
    p=PRIVATE/name;p.write_bytes(data if isinstance(data,bytes)else json.dumps(data).encode());p.chmod(0o600);return p
try:
    if options.require_clean_build:check('new CLI and runtime have clean matching candidate identities',not result['source_dirty']and result['build_source_matches_candidate'])
    check('legacy executable is the retained clean pagination source',result['build_identity'][str(OLD.relative_to(ROOT))].get('vcs.revision')=='51a74bd42866a6e33c77a670259ed0b4d9a959a8'and result['build_identity'][str(OLD.relative_to(ROOT))].get('vcs.modified')=='false')
    owner=urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN']);database='cratectl_schema_'+RUN
    pgenv=dict(env,PGHOST=owner.hostname,PGPORT=str(owner.port or 5432),PGUSER=urllib.parse.unquote(owner.username),PGPASSWORD=urllib.parse.unquote(owner.password),PGDATABASE=owner.path.lstrip('/'))
    PSQL=ROOT/'.cache/postgresql-16.15-install/bin/psql'
    command([PSQL,'-X','-v','ON_ERROR_STOP=1','-At','-c','CREATE DATABASE '+database],pgenv)
    pgenv['PGDATABASE']=database
    def psql(sql):return command([PSQL,'-X','-v','ON_ERROR_STOP=1','-At','-c',sql],pgenv).decode().strip()
    def fixture_dsn(dsn):
        u=urllib.parse.urlsplit(dsn);return urllib.parse.urlunsplit((u.scheme,u.netloc,'/'+database,u.query,u.fragment))
    initial=dict(env,CRATECTL_OWNER_DSN=fixture_dsn(env['CRATECTL_OWNER_DSN']),CRATECTL_DSN=fixture_dsn(env['CRATECTL_DSN']))
    private('database.json',{'owner':initial['CRATECTL_OWNER_DSN'],'runtime':initial['CRATECTL_DSN']})
    install=PRIVATE/'installation'
    receipt=json.loads(command([OLD,'init','--directory',install,'--tenant','upgrade-team'],initial));token=(install/'admin.token').read_text().strip()
    def server(binary):
        start('registry',[binary,'serve','--config',receipt['runtime_config'],'--dev-loopback-http','--public-url',BASE])
        def ready():
            if processes['registry'].poll()is not None:raise AssertionError('registry exited before readiness')
            try:return urllib.request.urlopen(BASE+'/health/ready',timeout=.5).status==200
            except Exception:return False
        wait_for('registry readiness',ready)
    def api(path,body=None,method='GET'):
        request=urllib.request.Request(BASE+path,data=json.dumps(body).encode()if body is not None else None,method=method,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','Idempotency-Key':'schema-'+uuid.uuid4().hex})
        with urllib.request.urlopen(request,timeout=10)as response:return json.loads(response.read())
    server(OLD)
    api('/api/v1/repositories',{'name':'packages','format':'npm','require_review':False},'POST')
    api('/api/v1/repositories',{'name':'private-files','format':'generic','access':'restricted'},'POST')
    package=PRIVATE/'package';package.mkdir();name='cratectl-schema-'+RUN
    (package/'package.json').write_text(json.dumps({'name':name,'version':'1.0.0','main':'index.js','license':'MIT'}));(package/'index.js').write_text('module.exports=42;\n')
    npmrc=private('npmrc',(f'registry={BASE}/npm/packages/\n//127.0.0.1:38443/npm/packages/:_authToken={token}\n').encode())
    npm_env=dict(public,NPM_CONFIG_USERCONFIG=str(npmrc),NPM_CONFIG_CACHE=str(PRIVATE/'npm-cache'),NPM_CONFIG_AUDIT='false',NPM_CONFIG_FUND='false')
    command(['npm','publish','--ignore-scripts','--access','public'],npm_env,package)
    artifacts_before=api('/api/v1/repositories/packages/artifacts')['items'];audit_before=api('/api/v1/audit?limit=100')['items']
    check('legacy runtime publishes real npm bytes before adoption',len(artifacts_before)==1)
    stop('registry')
    state=psql("SELECT jsonb_build_object('tenants',(SELECT jsonb_agg(t)FROM cratectl.tenants t),'repositories',(SELECT jsonb_agg(t ORDER BY t.name)FROM cratectl.repositories t),'artifacts',(SELECT jsonb_agg(t ORDER BY t.path)FROM cratectl.artifacts t),'events',(SELECT jsonb_agg(t ORDER BY t.sequence)FROM cratectl.events t),'tokens',(SELECT jsonb_agg(t ORDER BY t.hash)FROM cratectl_private.tokens t))::text")
    private('pre-adoption-state.json',state.encode())
    plan=json.loads(command([NEW,'migrate','--plan'],initial));check('owner plan identifies unversioned data and explicit adoption requirement',plan['database_state']=='legacy'and plan['requires_legacy_adoption']and plan['pending']==[1,2,3,4,5,6])
    command([NEW,'migrate'],initial,ok=False);check('ordinary migration refuses legacy data without acknowledgement',psql("SELECT to_regclass('cratectl_private.schema_migrations') IS NULL")=='t')
    psql("CREATE FUNCTION cratectl_private.schema_fault_pause() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF EXISTS(SELECT 1 FROM pg_event_trigger_ddl_commands() WHERE object_identity='cratectl.schema_state()') THEN PERFORM pg_advisory_xact_lock(731445924); END IF; END $$;CREATE EVENT TRIGGER cratectl_schema_fault ON ddl_command_end WHEN TAG IN ('CREATE FUNCTION') EXECUTE FUNCTION cratectl_private.schema_fault_pause()")
    blocker_env=dict(pgenv,PGAPPNAME='cratectl-schema-barrier-'+RUN)
    blocker=start('barrier',[PSQL,'-X','-v','ON_ERROR_STOP=1','-At'],blocker_env,pipe=True);blocker.stdin.write(b'BEGIN;SELECT pg_advisory_xact_lock(731445924);\n');blocker.stdin.flush()
    wait_for('owned DDL barrier not held',lambda:psql("SELECT count(*)FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name='cratectl-schema-barrier-"+RUN+"' AND l.objid=731445924 AND l.granted")=='1')
    migrating_dsn=urllib.parse.urlsplit(initial['CRATECTL_OWNER_DSN']);q=urllib.parse.parse_qsl(migrating_dsn.query)+[('application_name','cratectl-schema-killed-'+RUN)]
    migration_env=dict(initial,CRATECTL_OWNER_DSN=urllib.parse.urlunsplit((*migrating_dsn[:3],urllib.parse.urlencode(q),migrating_dsn.fragment)))
    migrator=start('migrator',[NEW,'migrate','--adopt-legacy'],migration_env)
    wait_for('migration did not execute DDL before fault',lambda:psql("SELECT count(*)FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name='cratectl-schema-killed-"+RUN+"' AND l.objid=731445924 AND NOT l.granted")=='1')
    migrator.kill();migrator.wait(timeout=5);stop('migrator')
    blocker.stdin.write(b'ROLLBACK;\n\\q\n');blocker.stdin.flush();blocker.wait(timeout=5);stop('barrier')
    wait_for('killed migration backend did not release its transaction',lambda:psql("SELECT count(*)FROM pg_stat_activity WHERE application_name='cratectl-schema-killed-"+RUN+"'")=='0')
    check('actual killed migration process rolls back baseline DDL and receipts',psql("SELECT to_regclass('cratectl_private.schema_migrations') IS NULL AND to_regprocedure('cratectl.schema_state()') IS NULL")=='t')
    psql('DROP EVENT TRIGGER cratectl_schema_fault;DROP FUNCTION cratectl_private.schema_fault_pause()')
    command([NEW,'migrate','--adopt-legacy'],initial)
    plan=json.loads(command([NEW,'migrate','--plan'],initial));check('adoption commits all six known receipts with safe RLS',plan['database_state']=='current'and len(plan['applied'])==6 and not plan['pending']and plan['safety_valid'])
    after=psql("SELECT jsonb_build_object('tenants',(SELECT jsonb_agg(t)FROM cratectl.tenants t),'repositories',(SELECT jsonb_agg(t ORDER BY t.name)FROM cratectl.repositories t),'artifacts',(SELECT jsonb_agg(t ORDER BY t.path)FROM cratectl.artifacts t),'events',(SELECT jsonb_agg(t ORDER BY t.sequence)FROM cratectl.events t),'tokens',(SELECT jsonb_agg(t ORDER BY t.hash)FROM cratectl_private.tokens t))::text")
    expected=json.loads(state)
    for table in ['repositories','artifacts']:
        for row in expected[table]:row['source_revision']=0
    check('every original tenant, repository, artifact, audit and token field is preserved; new source revisions start at zero',json.loads(after)==expected)
    server(NEW)
    expected_artifacts=[dict(artifact,source_revision=0)for artifact in artifacts_before]
    check('new runtime authenticates original credential and returns original stored reference with source revision zero',api('/api/v1/repositories/packages/artifacts')['items']==expected_artifacts)
    check('adoption does not alter existing audit sequence or hashes',api('/api/v1/audit?limit=100')['items']==audit_before)
    for n in range(3):command([NEW,'migrate'],initial)
    check('current migration repeats while new registry serves requests',len(api('/api/v1/repositories')['items'])==2)
    consumer=PRIVATE/'consumer';consumer.mkdir();command(['npm','install','--ignore-scripts','--no-audit','--no-fund',name+'@1.0.0'],npm_env,consumer)
    command(['node','-e','if(require('+json.dumps(name)+')!==42)process.exit(1)'],public,consumer)
    check('stock npm installs preserved legacy bytes through new runtime',True)
    stop('registry');server(NEW)
    check('current schema and original credentials survive actual registry restart',api('/api/v1/session')['tenant']=='upgrade-team')
    check('retained installation files exclude owner DSN and password',all(initial['CRATECTL_OWNER_DSN'].encode()not in p.read_bytes()and urllib.parse.unquote(owner.password).encode()not in p.read_bytes()for p in install.iterdir()if p.is_file()))
    result['database']=database;result['plan']=plan;result['elapsed_seconds']=round(time.monotonic()-started,3);result['status']='passed'
except BaseException as error:result['status']='failed';result['failure']=type(error).__name__+': '+str(error)
finally:
    if 'blocker'in locals()and blocker.poll()is None:
        try:blocker.stdin.write(b'ROLLBACK;\n\\q\n');blocker.stdin.flush();blocker.wait(timeout=5)
        except Exception:pass
    for process in list(processes):stop(process)
    evidence=ROOT/'evidence'/datetime.datetime.now(datetime.timezone.utc).date().isoformat();evidence.mkdir(parents=True,exist_ok=True)
    target=evidence/('schema-'+RUN+'.json');target.write_text(json.dumps(result,indent=2)+'\n')
    print(result['status'].upper()+': '+str(len(checks))+' assertions; schema adoption; '+str(target))
if result['status']=='failed':raise SystemExit(result.get('failure','schema conformance failed'))
