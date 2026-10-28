# SPDX-License-Identifier: BUSL-1.1
"""Owned native PostgreSQL fallback. Never operates another data directory."""
import json,os,secrets,subprocess,sys
from pathlib import Path
from urllib.parse import urlparse

root=Path(__file__).resolve().parents[1];os.chdir(root)
private=root/'.private';private.mkdir(exist_ok=True,mode=0o700);private.chmod(0o700)
binary=root/'.cache/postgresql-16.15-install/bin'
data=private/'cratectl-native-postgres';config=private/'native-db.json'
command=sys.argv[1:]

def write_private(path,text):
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,'w') as f:f.write(text)

if command==['init'] and not config.exists():
 owner=secrets.token_urlsafe(32);runtime=secrets.token_urlsafe(32)
 write_private(config,json.dumps({'owner':'postgres://cratectl_owner:'+owner+'@127.0.0.1:35432/cratectl?sslmode=disable','runtime':'postgres://cratectl_app:'+runtime+'@127.0.0.1:35432/cratectl?sslmode=disable'}))
cfg=json.loads(config.read_text())
env=dict(os.environ,CRATECTL_OWNER_DSN=cfg['owner'],CRATECTL_DSN=cfg['runtime'])
owner_password=urlparse(cfg['owner']).password;runtime_password=urlparse(cfg['runtime']).password

def run(args,**kwargs):
 result=subprocess.run([str(x) for x in args],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,**kwargs)
 output=result.stdout.replace(owner_password,'[REDACTED]').replace(runtime_password,'[REDACTED]')
 if result.returncode:raise SystemExit(output)
 return output

if command==['stop']:
 status=subprocess.run([str(binary/'pg_ctl'),'-D',str(data),'status'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 if status.returncode==0:run([binary/'pg_ctl','-D',data,'stop','-m','fast'])
 print('Owned native PostgreSQL stopped; private data retained.');raise SystemExit(0)
if command==['init']:
 if not (data/'PG_VERSION').exists():
  pwfile=private/'native-owner-password'
  if not pwfile.exists():write_private(pwfile,owner_password+'\n')
  run([binary/'initdb','-D',data,'--username=cratectl_owner','--pwfile='+str(pwfile),'--auth-host=scram-sha-256','--auth-local=scram-sha-256','--locale=C','--encoding=UTF8'])
 status=subprocess.run([str(binary/'pg_ctl'),'-D',str(data),'status'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 if status.returncode:
  run([binary/'pg_ctl','-D',data,'-l',private/'native-postgres.log','-o',"-h 127.0.0.1 -p 35432 -c unix_socket_directories='' -c shared_buffers=64MB -c max_connections=30",'start','-w'])
  # Only the freshly initialized owned cluster has no cratectl database.
  pgenv=dict(env,PGPASSWORD=owner_password)
  result=subprocess.run([str(binary/'createdb'),'-h','127.0.0.1','-p','35432','-U','cratectl_owner','cratectl'],env=pgenv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  if result.returncode and 'already exists' not in result.stdout:raise SystemExit(result.stdout.replace(owner_password,'[REDACTED]'))
 command=['setup']
if command==['setup']:
 run([root/'bin/cratectld','migrate'])
 pgenv=dict(env,PGPASSWORD=owner_password)
 result=subprocess.run([str(binary/'psql'),'-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p','35432','-U','cratectl_owner','-d','cratectl'],input="ALTER ROLE cratectl_app LOGIN PASSWORD '"+runtime_password+"';\n",env=pgenv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 if result.returncode:raise SystemExit(result.stdout.replace(runtime_password,'[REDACTED]').replace(owner_password,'[REDACTED]'))
 for tenant in ['test-a','test-b']:
  token=private/('native-'+tenant+'.token')
  if not token.exists():run([root/'bin/cratectld','provision','--tenant',tenant,'--actor','operator','--role','admin','--token-file',token])
 print('Owned native PostgreSQL 16.15 ready on loopback 35432; container data untouched.')
else:raise SystemExit(subprocess.run(command,env=env).returncode)
