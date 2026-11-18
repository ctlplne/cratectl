#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Check actual imported cratectl image services with stock npm and a native archive CLI."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

if not __debug__:
    raise SystemExit('keep the stock-client assertions enabled')
os.umask(0o077)
candidate, architecture, archive_hash, phase = sys.argv[1:]
expected_machine = {"amd64": "x86_64", "arm64": "aarch64"}[architecture]
media = Path('/fixture')
installation = Path('/var/lib/cratectl')
url = 'https://127.0.0.1:38443'
payload = b'Stock npm proof from the annotated cratectl offline media.\n'
checks = []


def ok(label, condition):
    if not condition:
        raise AssertionError(label)
    checks.append(label)


def runner(args, env, cwd, *, want=0):
    process = subprocess.run([str(arg) for arg in args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, check=False, timeout=35, env=env, cwd=cwd)
    if not (process.returncode == want if want is not None else process.returncode != 0):
        raise AssertionError(str(args[0]) + ' result ' + str(process.returncode) + ': '
                             + process.stdout[-4000:].decode(errors='replace'))
    return process.stdout


with tempfile.TemporaryDirectory(prefix='cratectl-imported-media-') as folder:
    local = Path(folder)
    env = {key: value for key, value in os.environ.items()
           if not key.lower().endswith('_proxy') and not key.lower().startswith('npm_config_')}
    env.update(HOME=folder, NO_PROXY='*')
    flags = {name: int((Path('/sys/class/net')/name/'flags').read_text(), 16) for _, name in socket.if_nameindex()}
    v4 = Path('/proc/net/route').read_text().splitlines()[1:]
    v6 = Path('/proc/net/ipv6_route').read_text().splitlines()
    ok('only-loopback-in-imported-image-namespace', {k for k,v in flags.items() if v&1}=={'lo'}
       and all(r.split()[0]=='lo' for r in v4) and all(r.split()[-1]=='lo' for r in v6))
    ok('native-linux-arch-nonroot-client',os.uname().machine == expected_machine and os.geteuid()!=0)
    target=local/'bin'
    target.mkdir(mode=0o700)
    installed=runner(['python3','-B',media/'install_linux_candidate.py',media / ('cratectl-linux-' + architecture + '.tar.gz'),
                      '--directory',target,'--sha256',archive_hash],env,local).decode().strip()
    binary=target/('cratectl-' + candidate + '-' + architecture)/'cratectl'
    ok('verified-native-cli-archive',Path(installed)==binary.parent and binary.is_file())
    config=installation/'client.json'
    certificate=installation/'ca.crt'
    curl=['curl','-q','--noproxy','*','--silent','--show-error','--fail']
    for _ in range(50):
        result=subprocess.run([*curl,'--cacert',certificate,'--max-time','1',url+'/health/ready'],
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        if result.returncode==0:
            break
        time.sleep(.1)
    else:
        raise AssertionError('imported registry readiness')
    runner([*curl,'--max-time','2',url+'/health/ready'],env,local,want=60)
    ok('imported-registry-trusted-tls',True)

    def api(label,path,method='GET',value=None):
        args=[binary,'--config',config,'--path','/api/v1/'+path,'--method',method]
        if value is not None:
            request=local/(label+'.json')
            request.write_text(json.dumps(value))
            args.extend(['--body-file',request,'--idempotency-key','imported-media-'+label])
        return json.loads(runner(args,env,local))

    if phase=='fresh':
        ok('registry-empty-after-imported-bootstrap', api('blank','repositories')['items']==[])
        api('create','repositories','POST',{'name':'packages','format':'npm','require_review':True})
    npmrc=local/'npmrc'
    value=json.loads(runner([binary,'npm-config','--config',config,'--repository','packages','--output',npmrc],env,local))
    ok('private-stock-npm-input',value['tls_verification'] is True and npmrc.stat().st_mode&0o777==0o600)
    npm=dict(env,NPM_CONFIG_USERCONFIG=str(npmrc),NPM_CONFIG_GLOBALCONFIG='/dev/null',NPM_CONFIG_AUDIT='false',
             NPM_CONFIG_FUND='false',NPM_CONFIG_UPDATE_NOTIFIER='false',NPM_CONFIG_FETCH_RETRIES='0',
             NPM_CONFIG_REGISTRY=url+'/npm/packages/')
    name='cratectl-imported-media-proof'

    def fetch(label, expected):
        cwd=local/label
        cwd.mkdir(mode=0o700)
        runner(['npm','install','--ignore-scripts','--no-audit','--no-fund','--package-lock=false',name+'@1.0.0'],
               dict(npm,NPM_CONFIG_CACHE=str(cwd/'cache')),cwd,want=expected)
        installed=cwd/'node_modules'/name/'proof.txt'
        return installed.read_bytes() if installed.is_file() else None

    if phase=='fresh':
        pkg=local/'package'
        pkg.mkdir(mode=0o700)
        (pkg/'package.json').write_text(json.dumps({'name':name,'version':'1.0.0','license':'MIT'}))
        (pkg/'proof.txt').write_bytes(payload)
        runner(['npm','publish','--ignore-scripts','--access','public'],
               dict(npm,NPM_CONFIG_CACHE=str(local/'publish-cache')),pkg)
        artifact,=api('after','repositories/packages/artifacts')['items']
        ok('stock-npm-published-to-imported-image',artifact['decision']=='unassessed'
           and re.fullmatch('[a-f0-9]{64}',artifact['digest']))
        ok('unassessed-package-refused',fetch('unassessed',None) is None)
        api('approve','repositories/packages/decisions','PUT',
            {'path':artifact['path'],'digest':artifact['digest'],'decision':'allowed'})
        ok('exact-approved-package-downloaded',fetch('approved',0)==payload)
        for _ in range(90):
            jobs=api('jobs','jobs?limit=100')['items']
            if jobs and all(j['state']=='succeeded' for j in jobs):
                break
            time.sleep(.13)
        ok('imported-worker-completed-durable-intents', {j['handler'] for j in jobs}=={'storage.integrity','event.project'}
           and all(j['state']=='succeeded' for j in jobs))
    else:
        artifact,=api('retained','repositories/packages/artifacts')['items']
        ok('registry-restart-retains-approved-reference',artifact['decision']=='allowed')
        ok('fresh-cache-installs-identical-bytes-after-restart', fetch('after-restart',0)==payload)
    print(json.dumps({'phase':phase,'checks':checks,'artifact_digest':artifact['digest'],
                      'npm':runner(['npm','--version'],env,local).decode().strip()}))
