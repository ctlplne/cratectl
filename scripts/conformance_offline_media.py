#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Rehearse signed offline media imports with stock clients on a native Docker engine."""
import argparse
import fcntl
import platform
import re
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

from bounded_client import run_owned_client
from compose_evaluation import ROOT, private_directory
from linux_offline_media import assemble, require, saved_image_configuration
from ci.offline_media_evidence import CHECKS, NODE, SOURCE_PATHS, validate

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
args = parser.parse_args()
require(__debug__, 'keep the fixture assertions enabled')
os.umask(0o077)
os.chdir(ROOT)
ARCH = args.architecture
PLATFORM = 'linux/' + ARCH
MACHINE, RUNNER = {'amd64': ('x86_64', 'X64'), 'arm64': ('aarch64', 'ARM64')}[ARCH]
require(platform.machine() in (MACHINE, ARCH) and platform.system() in ('Linux', 'Darwin'), 'native host required')
require(os.geteuid() != 0, 'run the offline media fixture as an unprivileged user')
PROJECT = 'cratectl-imported-' + secrets.token_hex(5)
private_directory(ROOT / '.private')
PRIVATE = ROOT / '.private' / PROJECT
PRIVATE.mkdir(mode=0o700)
MEDIA = PRIVATE / 'media'
PG, REGISTRY, WORKER, INIT = (PROJECT + '-' + name for name in ('pg', 'registry', 'worker', 'init'))
owned = []
mount_root = '/var/lib/cratectl'
uid = f'{os.geteuid()}:{os.getegid()}'
ARCHIVE = 'cratectl-linux-' + ARCH + '.tar.gz'


def sha(file):
    with file.open('rb') as data:
        return hashlib.file_digest(data,'sha256').hexdigest()


def run(label, *args, want=0, timeout=90):
    log = PRIVATE / (label + '.log')
    with log.open('wb') as output:
        code, text = run_owned_client(args, ROOT, os.environ, timeout=timeout,
                                      output_limit=4 << 20, capture_limit=64 << 10, output_sink=output)
    require(code == want, f'{label} status {code}. See {log}')
    return text.strip()


def bind(source,target,readonly=False):
    return '--mount=type=bind,source='+str(source)+',destination='+target+(',readonly' if readonly else '')


def sql(label,query):
    return run(label,'docker','exec',PG,'psql','-X','-v','ON_ERROR_STOP=1','-At','-U','postgres','-p','35432','-d','cratectl','-c',query)


def verify_args(path, fingerprint):
    return [sys.executable,'scripts/linux_offline_media.py','verify',path,'--architecture', ARCH,
            '--trusted-key',PRIVATE/'operator-public.pem','--trusted-key-sha256',fingerprint]


def inspect(tag):
    result = run('inspected-'+tag.split(':')[0],'docker','image','inspect',
                 '--format','{{.Id}} {{.Os}}/{{.Architecture}}',tag)
    match = re.fullmatch(r'(sha256:[a-f0-9]{64}) ' + re.escape(PLATFORM), result)
    require(match is not None, 'loaded Docker platform differs')
    return match[1]


CANDIDATE = run('source', 'git', 'rev-parse', 'HEAD')
require(re.fullmatch('[a-f0-9]{40}', CANDIDATE) and not run('source-clean', 'git', 'status', '--porcelain'),
        'clean exact source is required')
if os.environ.get('GITHUB_RUN_ID'):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_SHA') == CANDIDATE
            and os.environ.get('RUNNER_OS') == 'Linux' and os.environ.get('RUNNER_ARCH') == RUNNER,
            'exact native GitHub run binding required')
endpoint = run('docker-context', 'docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}')
require(endpoint.startswith('unix://') and os.environ.get('DOCKER_HOST', 'unix://').startswith('unix://'),
        'a local Docker Unix socket is required')
engine = run('docker-engine', 'docker', 'info', '--format', '{{.OSType}}/{{.Architecture}}')
require(engine in ('linux/' + MACHINE, PLATFORM), 'native Docker platform required')
run('package-archive-and-sboms', 'make', 'package-linux-sbom', timeout=590)
lock_dir = ROOT / '.cache/cratectl-offline-media'
lock_dir.mkdir(parents=True, exist_ok=True)
flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
lock = os.open(lock_dir / (CANDIDATE + '-' + ARCH + '.lock'), flags, 0o600)
secret_env_files = []
try:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assemble(ARCH, CANDIDATE, MEDIA)
    manifest_path=MEDIA/'release-manifest.json'
    assert not (MEDIA/'release-manifest.sig').exists()
    with tempfile.TemporaryDirectory(prefix='cratectl-disposable-signing-',dir=PRIVATE) as folder:
        key=Path(folder)/'private.pem'
        run('sign-key','openssl','genpkey','-algorithm','ED25519','-out',key)
        run('sign-public','openssl','pkey','-in',key,'-pubout','-out',PRIVATE/'operator-public.pem')
        run('sign-manifest','openssl','pkeyutl','-sign','-rawin','-inkey',key,'-in',manifest_path,
            '-out',MEDIA/'release-manifest.sig')
    fingerprint=sha(PRIVATE/'operator-public.pem')
    manifest=json.loads(run('verify-complete-media',*verify_args(MEDIA,fingerprint)))
    assert manifest['candidate']==CANDIDATE and manifest['platform']==PLATFORM
    for name in ('release-manifest.json','release-manifest.sig'):
        shutil.copyfile(MEDIA/name,PRIVATE/name)
    run('refuse-wrong-trust',*verify_args(MEDIA,'0'*64),want=1)
    assert 'approved public key digest differs' in (PRIVATE/'refuse-wrong-trust.log').read_text()
    with tempfile.TemporaryDirectory(prefix=PROJECT+'-tamper-',dir=ROOT/'.cache') as folder:
        altered=Path(folder)
        for item in MEDIA.iterdir():
            if item.name=='registry-image.tar':
                shutil.copyfile(item,altered/item.name)
            else:
                os.link(item,altered/item.name)
        with (altered/'registry-image.tar').open('r+b') as handle:
            offset=(altered/'registry-image.tar').stat().st_size//2
            handle.seek(offset)
            value=handle.read(1)
            handle.seek(offset)
            handle.write(bytes([value[0]^1]))
        run('refuse-changed-registry-image',*verify_args(altered,fingerprint),want=1)
        assert 'signed media bytes differ: registry-image.tar' in (PRIVATE/'refuse-changed-registry-image.log').read_text()
    images=manifest['images']
    loaded_ids={}
    for role in ('postgres','registry'):
        ref=images[role]['tag']
        run('remove-only-assembly-tag-'+role,'docker','image','rm',ref)
        run('confirm-absent-tag-'+role,'docker','image','inspect',ref,want=1)
        run('load-'+role,'docker','image','load','--platform='+PLATFORM,'--input',MEDIA/(role+'-image.tar'),timeout=120)
        loaded_ids[role]=inspect(ref)
        with tempfile.TemporaryDirectory(prefix=PROJECT+'-readback-',dir=PRIVATE) as folder:
            readback=Path(folder)/'image.tar'
            run('export-loaded-'+role,'docker','image','save','--platform='+PLATFORM,
                '--output',readback,ref,timeout=120)
            assert saved_image_configuration(readback,ref,PLATFORM)==images[role]['id']
    install=PRIVATE/'installation'
    install.mkdir(mode=0o700)
    pagination=PRIVATE/'pagination'
    pagination.mkdir(mode=0o700)
    owner,runtime,dbadmin=(secrets.token_hex(24) for _ in range(3))
    pgenv=PRIVATE/'postgres.env'
    env=PRIVATE/'initializer.env'
    secret_env_files[:]=[pgenv,env]
    pgenv.write_text('POSTGRES_PASSWORD='+dbadmin+'\nCRATECTL_DB_OWNER_PASSWORD='+owner+'\nCRATECTL_DB_RUNTIME_PASSWORD='+runtime+'\n'
                    'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256\nPGPORT=35432\n')
    env.write_text('CRATECTL_OWNER_DSN=postgres://cratectl_owner:'+owner+'@127.0.0.1:35432/cratectl?sslmode=disable\n'
                  'CRATECTL_DSN=postgres://cratectl_app:'+runtime+'@127.0.0.1:35432/cratectl?sslmode=disable\n')
    owned.append(PG)
    run('start-imported-postgres','docker','run','-d','--pull=never','--name',PG,'--platform='+PLATFORM,'--network=none',
        '--label','ctlplne.project=cratectl','--env-file',pgenv,'--tmpfs=/var/lib/postgresql/data:rw,nosuid,nodev,size=384m,mode=0700',
        bind(MEDIA/'init-database.sql','/docker-entrypoint-initdb.d/01-cratectl.sql',True),
        images['postgres']['tag'],'postgres','-h','127.0.0.1','-p','35432')
    for _ in range(80):
        readiness=subprocess.run(['docker','exec',PG,'pg_isready','-h','127.0.0.1','-p','35432','-d','cratectl'],
                                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
        if readiness.returncode==0:
            break
        time.sleep(.13)
    else:
        raise RuntimeError('Imported database never ready')
    assert sql('pre-bootstrap-schema',"SELECT count(*) FROM pg_namespace WHERE nspname='cratectl'")=='0'
    service_args=['--platform='+PLATFORM,'--network=container:'+PG,'--user='+uid,'--read-only','--cap-drop=ALL',
                  '--security-opt=no-new-privileges','--label','ctlplne.project=cratectl']
    app_image=images['registry']['tag']
    owned.append(INIT)
    run('verify-imported-bootstrap','docker','run','--rm','--pull=never','--name',INIT,*service_args,'--env-file',env,
        bind(install,mount_root),app_image,'init','--directory',mount_root,'--tenant','transport-evaluation',
        '--public-url','https://127.0.0.1:38443')
    assert all(owner.encode() not in f.read_bytes() for f in install.iterdir() if f.is_file())
    common=[bind(install/'runtime.json',mount_root+'/runtime.json',True),bind(install/'objects',mount_root+'/objects')]
    registry_mount=common+[bind(install/name,mount_root+'/'+name,True) for name in ('server.crt','server.key')]
    registry_mount.append(bind(pagination,mount_root+'/pagination'))
    worker_mount=common+[bind(install/name,mount_root+'/'+name,True) for name in ('workers.json','worker.token')]
    owned.extend((REGISTRY,WORKER))
    run('start-imported-registry','docker','run','-d','--pull=never','--name',REGISTRY,*service_args,*registry_mount,
        app_image,'serve','--config',mount_root+'/runtime.json','--listen','127.0.0.1:38443',
        '--pagination-key-file',mount_root+'/pagination/pagination.key')
    run('start-imported-worker','docker','run','-d','--pull=never','--name',WORKER,*service_args,*worker_mount,
        app_image,'worker','--config',mount_root+'/runtime.json','--poll','50ms')
    streams=[]
    for phase in ('fresh','restarted'):
        client=PROJECT+'-client-'+phase
        owned.append(client)
        if phase=='restarted':
            run('restart-imported-processes','docker','restart',REGISTRY,WORKER)
        extras=[bind(ROOT/'scripts/fixtures/offline-media/client.py','/fixture/target.py',True)]
        extras.extend(bind(MEDIA/name,'/fixture/'+name,True) for name in
                      ('install_linux_candidate.py','verify_linux_candidate.py','package_linux.py', ARCHIVE))
        extras.extend(bind(install/name,mount_root+'/'+name,True) for name in ('client.json','admin.token','ca.crt'))
        result=run('stock-client-'+phase,'docker','run','--rm','--pull=never','--name',client,*service_args,
                   '--pids-limit=100','--tmpfs=/tmp:rw,nosuid,nodev,exec,size=384m,mode=1777',*extras,
                   NODE,'python3','-B','/fixture/target.py',CANDIDATE, ARCH, manifest['members'][ARCHIVE]['sha256'],phase,timeout=130)
        streams.append(json.loads(result))
    assert len(streams[0]['checks'])==10 and len(streams[1]['checks'])==7
    assert streams[0]['artifact_digest']==streams[1]['artifact_digest']
    rls=sql('verified-imported-rls',"""SELECT count(*)||'/'||count(*) FILTER (WHERE c.relrowsecurity AND c.relforcerowsecurity)
         ||'/'||count(*) FILTER (WHERE pg_get_userbyid(c.relowner)='cratectl_app') FROM pg_class c
         JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='cratectl' AND c.relkind IN ('r','p')
         AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant' AND NOT a.attisdropped)""")
    assert rls=='57/57/0'
    assert sql('verified-imported-schema','SELECT max(version) FROM cratectl_private.schema_migrations')=='18'
    for container in (PG,REGISTRY,WORKER):
        mode=run('container-scope-'+container,'docker','inspect',container,'--format',
                 '{{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}} {{.Image}}')
        assert (' none ' in ' '+mode if container==PG else mode.startswith('container:'))
        assert ' {} ' in mode
        image=loaded_ids['postgres' if container==PG else 'registry']
        assert mode.endswith(' '+image)
    result = {'schema': 1, 'profile': 'cratectl-native-offline-media-v1',
              'candidate': CANDIDATE, 'runner_os': 'Linux', 'runner_arch': RUNNER,
              'run_id': os.environ.get('GITHUB_RUN_ID'), 'source_dirty': False, 'status': 'passed',
              'runtime_phases': streams, 'checks': list(CHECKS),
              'image_configuration_sha256': {role: image['id'] for role, image in images.items()},
              'manifest_sha256': sha(manifest_path), 'archive_sha256': manifest['members'][ARCHIVE]['sha256'],
              'source_sha256': {name: sha(ROOT / name) for name in SOURCE_PATHS},
              'forced_tenant_tables': 57, 'database_schema': 18,
              'goal_complete': False, 'broad_readiness': False}
    validate(result, local=result['run_id'] is None)
    encoded = json.dumps(result, indent=2) + '\n'
    (PRIVATE / 'safe-report.json').write_text(encoded)
    (ROOT / '.cache/ci-offline-media.json').write_text(encoded)
    print('PASS: 17 scoped imported-image runtime checks and 10 media controls')

finally:
    for name in reversed(owned):
        subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
    for file in secret_env_files:
        file.unlink(missing_ok=True)
    os.close(lock)
