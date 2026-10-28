# SPDX-License-Identifier: BUSL-1.1
"""Owned local development resources. Never cleans up by prefix or wildcard."""
import json,os,secrets,subprocess,sys,time
from pathlib import Path
root=Path(__file__).resolve().parents[1];os.chdir(root)
private=root/'.private';private.mkdir(exist_ok=True,mode=0o700);private.chmod(0o700)
command=sys.argv[1:]
if os.environ.get('CRATECTL_DEV_DATABASE')=='native':
 raise SystemExit(subprocess.run([sys.executable,str(root/'scripts/native_db.py'),*command]).returncode)
if command==['init']:
 cfgfile=private/'db.json'
 if not cfgfile.exists():
  pw=secrets.token_urlsafe(32);app=secrets.token_urlsafe(32)
  files={'postgres.env':'POSTGRES_USER=cratectl_owner\nPOSTGRES_PASSWORD='+pw+'\nPOSTGRES_DB=cratectl\n',
   'db.json':json.dumps({'owner':'postgres://cratectl_owner:'+pw+'@127.0.0.1:35432/cratectl?sslmode=disable','runtime':'postgres://cratectl_app:'+app+'@127.0.0.1:35432/cratectl?sslmode=disable'}),
   'runtime-role.sql':"ALTER ROLE cratectl_app LOGIN PASSWORD '"+app+"';\n"}
  for name,content in files.items():
   fd=os.open(private/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
   with os.fdopen(fd,'w') as f:f.write(content)
 inspected=subprocess.run(['docker','inspect','cratectl-dev-postgres'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
 if inspected.returncode==0:
  info=json.loads(inspected.stdout)[0]
  if info['Config']['Labels'].get('ctlplne.project')!='cratectl':raise SystemExit('Refusing to operate an unowned container with the reserved name.')
  if not info['State']['Running']:subprocess.run(['docker','start','cratectl-dev-postgres'],check=True,stdout=subprocess.DEVNULL)
 else:
  subprocess.run(['docker','run','-d','--name','cratectl-dev-postgres','--label','ctlplne.project=cratectl','--env-file',str(private/'postgres.env'),'-p','127.0.0.1:35432:5432','-v','cratectl-dev-postgres-data:/var/lib/postgresql/data','--memory','512m','--cpus','2','--pids-limit','128','postgres:16.15-alpine'],check=True,stdout=subprocess.DEVNULL)
 for _ in range(60):
  if subprocess.run(['docker','exec','cratectl-dev-postgres','pg_isready','-U','cratectl_owner','-d','cratectl'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
  time.sleep(.25)
 else:raise SystemExit('Owned PostgreSQL readiness timeout.')
 command=['setup']
cfg=json.loads((private/'db.json').read_text());env=dict(os.environ,CRATECTL_OWNER_DSN=cfg['owner'],CRATECTL_DSN=cfg['runtime'])
if command==['setup']:
 subprocess.run(['bin/cratectld','migrate'],env=env,check=True)
 subprocess.run(['docker','exec','-i','cratectl-dev-postgres','psql','-v','ON_ERROR_STOP=1','-U','cratectl_owner','-d','cratectl'],input=(private/'runtime-role.sql').read_bytes(),check=True,stdout=subprocess.DEVNULL)
 for tenant in ['test-a','test-b']:
  token=private/f'{tenant}.token'
  if not token.exists():subprocess.run(['bin/cratectld','provision','--tenant',tenant,'--actor','operator','--role','admin','--token-file',str(token)],env=env,check=True)
 print('Owned database ready on 127.0.0.1:35432. Private credentials retained in .private/.')
else:raise SystemExit(subprocess.run(command,env=env).returncode)
