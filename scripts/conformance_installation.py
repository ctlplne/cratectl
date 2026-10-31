#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Blank native operator journey; TLS stays verified and no development tenants are seeded."""
import argparse,datetime,hashlib,json,os,signal,ssl,subprocess,time,urllib.parse,urllib.request,urllib.error,uuid
from pathlib import Path
from qualification_contract import candidate_binary_directory, candidate_artifact_names
BIN = candidate_binary_directory()
parser=argparse.ArgumentParser();parser.add_argument('--require-clean-build',action='store_true');args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT);RUN=uuid.uuid4().hex[:10]
PRIVATE=ROOT/'.private/installation-conformance'/RUN;PRIVATE.mkdir(parents=True,mode=0o700);PRIVATE.chmod(0o700)
INSTALL=PRIVATE/'installation profile';BASE='https://localhost:38443';checks=[];processes={};logs={}
env=dict(os.environ);public_env=dict(env)
for key in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']:public_env.pop(key,None)
start=time.monotonic();evidence=ROOT/'evidence'/datetime.datetime.now(datetime.timezone.utc).date().isoformat();evidence.mkdir(parents=True,exist_ok=True)
def settings(name):
    out={}
    for line in subprocess.check_output(['.cache/go/bin/go','version','-m',name],text=True).splitlines():
        parts=line.strip().split('\t')
        if len(parts)==2 and parts[0]=='build' and '='in parts[1]:key,value=parts[1].split('=',1);out[key]=value
    return out
scope=['cmd','internal','scripts','api','go.mod','go.sum','Makefile']
result={'run':RUN,'candidate':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'source_scope':scope,'source_dirty':bool(subprocess.check_output(['git','status','--porcelain','--',*scope],text=True).strip()),'artifact_digests':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()for name in candidate_artifact_names()},'build_identity':{name:settings(name)for name in candidate_artifact_names()},'checks':checks,'topology':'Native macOS process; new empty database in owned PostgreSQL 16.15 cluster; HTTPS on loopback 38443; stock npm and node; config-only runtime processes without owner/runtime DSN environment.','limits':['Database server and restricted login are supplied by the operator; no claim of blank-machine, Compose/Helm or offline-bundle qualification.','Generated local CA and certificate expire after 30 days; initial credentials default to 24 hours; production PKI and credential lifecycle remain required.','Single native host and filesystem; broader OS, outage/restore, production scale and full security qualification remain open.']}
result['build_source_matches_candidate']=all(v.get('vcs.revision')==result['candidate']and v.get('vcs.modified')=='false'for v in result['build_identity'].values())
def check(label,condition):
    if not condition:raise AssertionError(label)
    checks.append(label)
def private(name,data):
    p=PRIVATE/name;p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(data if isinstance(data,bytes)else json.dumps(data).encode());p.chmod(0o600);return p
def command(argv,runenv=public_env,cwd=ROOT,ok=True):
    with (PRIVATE/'commands.log').open('ab')as log:
        p=subprocess.run([str(x)for x in argv],cwd=cwd,env=runenv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90);log.write(p.stdout)
    if (p.returncode==0)!=ok:raise AssertionError('native command returned unexpected status: '+Path(str(argv[0])).name)
    return p.stdout
def stop(name):
    p=processes.pop(name,None)
    if p and p.poll()is None:
        p.terminate()
        try:p.wait(timeout=10)
        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
    if name in logs:logs.pop(name).close()
def start_process(name,argv,runenv=public_env):
    log=(PRIVATE/(name+'.log')).open('ab');logs[name]=log
    processes[name]=subprocess.Popen([str(x)for x in argv],env=runenv,stdout=log,stderr=subprocess.STDOUT)
    return processes[name]
def cli(path,method='GET',body=None,key=None,extra=(),ok=True):
    argv=[BIN/'cratectl','--config',INSTALL/'client.json','--path',path,'--method',method]
    if body is not None:argv+=['--body-file',private('request-'+uuid.uuid4().hex+'.json',body)]
    if key:argv+=['--idempotency-key',key]
    return command([*argv,*extra],ok=ok)
def start_server():
    start_process('registry',[BIN/'cratectld','serve','--config',INSTALL/'runtime.json'])
    for _ in range(150):
        if processes['registry'].poll()is not None:raise AssertionError('registry stopped during startup')
        try:
            with urllib.request.urlopen(BASE+'/health/ready',context=ssl.create_default_context(cafile=str(INSTALL/'ca.crt')),timeout=1)as response:
                if response.status==200:return
        except Exception:time.sleep(.05)
    raise AssertionError('trusted registry readiness timeout')
def psql(sql):
    return command([ROOT/'.cache/postgresql-16.15-install/bin/psql','-X','-v','ON_ERROR_STOP=1','-At','-c',sql],runenv=pgenv).decode().strip()
def with_database(dsn,name):
    u=urllib.parse.urlsplit(dsn)
    if u.scheme not in ['postgres','postgresql']:raise AssertionError('native fixture requires URL database configuration')
    return urllib.parse.urlunsplit((u.scheme,u.netloc,'/'+name,u.query,u.fragment))
database='cratectl_blank_'+RUN
try:
    if args.require_clean_build:check('source and both binary identities match a clean candidate',not result['source_dirty']and result['build_source_matches_candidate'])
    owner=urllib.parse.urlsplit(env['CRATECTL_OWNER_DSN']);pgenv=dict(env,PGHOST=owner.hostname,PGPORT=str(owner.port or 5432),PGUSER=urllib.parse.unquote(owner.username),PGPASSWORD=urllib.parse.unquote(owner.password),PGDATABASE=owner.path.lstrip('/'))
    psql('CREATE DATABASE '+database)
    pgenv['PGDATABASE']=database
    check('new database has no cratectl schema or seeded tenant',psql("SELECT count(*) FROM pg_namespace WHERE nspname='cratectl'")=='0')
    initial_env=dict(env,CRATECTL_OWNER_DSN=with_database(env['CRATECTL_OWNER_DSN'],database),CRATECTL_DSN=with_database(env['CRATECTL_DSN'],database))
    psql('CREATE TABLE public.cratectl_owned_existing_fixture(value text); INSERT INTO public.cratectl_owned_existing_fixture VALUES (\'preserved\')')
    command([BIN/'cratectld','init','--directory',INSTALL,'--tenant','first-team'],initial_env,ok=False)
    check('nonempty database is rejected before any cratectl schema migration',psql("SELECT count(*) FROM pg_namespace WHERE nspname='cratectl'")=='0'and psql('SELECT value FROM public.cratectl_owned_existing_fixture')=='preserved')
    psql('DROP TABLE public.cratectl_owned_existing_fixture')
    # Hold the documented initialization lock in this owned empty database,
    # kill the real initializer after durable preparation, then release it.
    blocker_name='cratectl-init-blocker-'+RUN
    blocker=start_process('blocker',[ROOT/'.cache/postgresql-16.15-install/bin/psql','-X','-v','ON_ERROR_STOP=1','-At','-c','SELECT pg_advisory_lock(731445923); SELECT pg_sleep(120)'],dict(pgenv,PGAPPNAME=blocker_name))
    for _ in range(100):
        if psql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name='"+blocker_name+"' AND l.locktype='advisory' AND l.granted")=='1':break
        time.sleep(.02)
    check('owned database lock is held before initializer fault',psql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name='"+blocker_name+"' AND l.locktype='advisory' AND l.granted")=='1')
    initializer=start_process('initializer',[BIN/'cratectld','init','--directory',INSTALL,'--tenant','first-team'],initial_env)
    for _ in range(150):
        if (INSTALL/'prepare.json').exists()and (INSTALL/'admin.token').exists():break
        if initializer.poll()is not None:raise AssertionError('initializer exited before durable preparation')
        time.sleep(.02)
    check('initializer prepared private credentials before ready configuration', (INSTALL/'prepare.json').exists()and not (INSTALL/'runtime.json').exists())
    before=(INSTALL/'prepare.json').read_bytes();initializer.kill();initializer.wait(timeout=5);stop('initializer')
    psql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='"+blocker_name+"' AND datname='"+database+"'");stop('blocker')
    receipt=json.loads(command([BIN/'cratectld','init','--directory',INSTALL,'--tenant','first-team'],initial_env))
    check('real killed initializer resumes original credentials and trust',(INSTALL/'prepare.json').read_bytes()==before)
    check('only one tenant and two purpose-separated credentials exist',psql('SELECT (SELECT count(*) FROM cratectl.tenants)::text || \'/\' || (SELECT count(*) FROM cratectl_private.tokens)::text')=='1/2')
    check('first database has no precreated repositories',psql('SELECT count(*) FROM cratectl.repositories')=='0')
    fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert((INSTALL/'ca.crt').read_text())).hexdigest()
    check('receipt names independently computed CA fingerprint',receipt['ca_sha256']==fingerprint)
    check('installation directory is private',INSTALL.stat().st_mode&0o077==0)
    check('all generated credential and configuration files are private',all(p.stat().st_mode&0o077==0 for p in INSTALL.iterdir()if p.is_file()))
    owner_bytes=initial_env['CRATECTL_OWNER_DSN'].encode();owner_password=urllib.parse.unquote(owner.password).encode()
    check('owner database authority is absent from retained installation files',all(owner_bytes not in p.read_bytes()and owner_password not in p.read_bytes()for p in INSTALL.iterdir()if p.is_file()))
    repeated=json.loads(command([BIN/'cratectld','init','--directory',INSTALL],initial_env))
    check('completed initialization replays original receipt',receipt==repeated)
    start_server()
    check('config-only CLI starts with an empty repository inventory',json.loads(cli('/api/v1/repositories'))['items']==[])
    cli('/api/v1/repositories',extra=['--url','https://127.0.0.1:38443'],ok=False)
    check('wrong TLS hostname fails even with the installation CA',True)
    cli('/api/v1/repositories',extra=['--token-file',INSTALL/'worker.token'],ok=False)
    check('explicit CLI token override is honored and worker purpose is denied',True)
    body={'name':'packages','format':'npm','require_review':True};key='first-repository-'+RUN
    created=cli('/api/v1/repositories','POST',body,key);replayed=cli('/api/v1/repositories','POST',body,key)
    check('first repository mutation replays identical output',created==replayed)
    package=PRIVATE/'package';package.mkdir();name='cratectl-first-'+RUN
    (package/'package.json').write_text(json.dumps({'name':name,'version':'1.0.0','description':'Owned blank-install proof','license':'MIT','main':'index.js'}));(package/'index.js').write_text('module.exports=42;\n')
    npmrc=PRIVATE/'npmrc'
    generated=json.loads(command([BIN/'cratectl','npm-config','--config',INSTALL/'client.json','--repository','packages','--output',npmrc]))
    check('CLI writes a private native npm configuration with TLS verification',generated['tls_verification']is True and npmrc.stat().st_mode&0o077==0)
    original=npmrc.read_bytes();command([BIN/'cratectl','npm-config','--config',INSTALL/'client.json','--repository','packages','--output',npmrc],ok=False)
    check('native credential configuration cannot overwrite an existing file',npmrc.read_bytes()==original)
    npm_env=dict(public_env,NPM_CONFIG_USERCONFIG=str(npmrc),NPM_CONFIG_CACHE=str(PRIVATE/'npm-cache'),NPM_CONFIG_AUDIT='false',NPM_CONFIG_FUND='false')
    command(['npm','publish','--ignore-scripts','--access','public'],npm_env,package)
    check('stock npm publishes its first package over verified TLS',True)
    consumer=PRIVATE/'consumer';consumer.mkdir()
    command(['npm','install','--ignore-scripts','--no-audit','--no-fund',name+'@1.0.0'],npm_env,consumer,ok=False)
    check('unassessed package is denied by the chosen review policy',True)
    artifacts=json.loads(cli('/api/v1/repositories/packages/artifacts'))['items'];check('administrator sees exact pending package bytes',len(artifacts)==1 and artifacts[0]['decision']=='unassessed')
    artifact=artifacts[0]
    cli('/api/v1/repositories/packages/decisions','PUT',{'path':artifact['path'],'digest':artifact['digest'],'decision':'allowed'},'approve-first-'+RUN)
    command(['npm','install','--ignore-scripts','--no-audit','--no-fund',name+'@1.0.0'],npm_env,consumer)
    command(['node','-e','if(require('+json.dumps(name)+')!==42)process.exit(1)'],public_env,consumer)
    result['seconds_to_first_publish_and_install']=round(time.monotonic()-start,3)
    check('approved exact package installs and its benign fixture returns expected value',True)
    stop('registry');start_server()
    check('first repository and package survive config-only restart',len(json.loads(cli('/api/v1/repositories/packages/artifacts'))['items'])==1)
    start_process('worker',[BIN/'cratectld','worker','--config',INSTALL/'runtime.json','--poll','50ms'])
    for _ in range(200):
        jobs=json.loads(cli('/api/v1/jobs?limit=100'))['items']
        if jobs and all(j['state']=='succeeded'for j in jobs):break
        if processes['worker'].poll()is not None:raise AssertionError('config-only worker stopped')
        time.sleep(.05)
    check('config-only dedicated worker completes publication and policy intents',bool(jobs)and all(j['state']=='succeeded'for j in jobs))
    check('publication completes both event projection and byte-integrity handlers',{j.get('handler')for j in jobs}=={'event.project','storage.integrity'})
    stop('worker')
    cli('/api/v1/repositories/packages/decisions','PUT',{'path':artifact['path'],'digest':artifact['digest'],'decision':'denied'},'deny-first-'+RUN)
    other=PRIVATE/'after-denial';other.mkdir();denial_env=dict(npm_env,NPM_CONFIG_CACHE=str(PRIVATE/'fresh-denial-cache'))
    command(['npm','install','--ignore-scripts','--no-audit','--no-fund',name+'@1.0.0'],denial_env,other,ok=False)
    check('current policy denial still blocks a fresh stock-client install after restart',True)
    # A different directory cannot take over this initialized database.
    command([BIN/'cratectld','init','--directory',PRIVATE/'other-installation','--tenant','other-team'],initial_env,ok=False)
    check('a second initializer cannot replace existing tenant state',psql('SELECT count(*) FROM cratectl.tenants')=='1')
    cli('/api/v1/repositories',extra=['--ca-file',PRIVATE/'other-installation/ca.crt'],ok=False)
    check('unrelated root cannot authenticate the server',True)
    events=json.loads(cli('/api/v1/audit'))['items']
    check('bootstrap and native mutations retain tenant audit evidence',len(events)>=6 and all(json.loads(e['payload'])['tenant']=='first-team'for e in events))
    result['database']=database;result['operator_inputs']=['empty database owner and restricted runtime connections','private installation directory','tenant name (administrator/listener/lifetimes use documented defaults)','first repository name, npm format and require-review policy','native npm CA/token configuration','explicit digest approval and later denial'];result['ca_sha256']=fingerprint
    result['status']='passed'
except BaseException as e:
    result['status']='failed';result['failure']=type(e).__name__+': '+str(e)
finally:
    if 'blocker_name'in locals():
        try:psql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='"+blocker_name+"' AND datname='"+database+"'")
        except Exception:result['blocker_cleanup']='failed; inspect the exact owned backend before rerun'
    for name in list(processes):stop(name)
    result['seconds_total']=round(time.monotonic()-start,3)
    path=evidence/('installation-'+RUN+'.json');path.write_text(json.dumps(result,indent=2)+'\n')
    print(result['status'].upper()+': '+str(len(checks))+' assertions; blank native install with trusted TLS')
    print('Evidence: '+str(path))
if result['status']!='passed':raise SystemExit(result.get('failure','installation failed'))
