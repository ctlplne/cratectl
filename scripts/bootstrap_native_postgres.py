# SPDX-License-Identifier: BUSL-1.1
"""Build an official, checksum-verified PostgreSQL inside this project only."""
from pathlib import Path
import hashlib,json,subprocess,tarfile,urllib.request

root=Path(__file__).resolve().parents[1];cache=root/'.cache';cache.mkdir(exist_ok=True)
name='postgresql-16.15';base='https://ftp.postgresql.org/pub/source/v16.15/'
archive=cache/(name+'.tar.bz2');digestfile=cache/(name+'.tar.bz2.sha256')
for target in [archive,digestfile]:
 if not target.exists():
  temporary=target.with_suffix(target.suffix+'.partial')
  with urllib.request.urlopen(base+target.name,timeout=60) as response,temporary.open('wb') as out:
   while chunk:=response.read(1<<20):out.write(chunk)
  temporary.replace(target)
expected=digestfile.read_text().split()[0];actual=hashlib.sha256(archive.read_bytes()).hexdigest()
if actual!=expected:raise SystemExit('PostgreSQL source checksum mismatch; build stopped.')
source=cache/name
if not source.exists():
 with tarfile.open(archive,'r:bz2') as bundle:bundle.extractall(cache,filter='data')
prefix=cache/(name+'-install');options=['--without-readline','--without-icu','--without-zlib']
with (cache/'postgresql-native-build.log').open('w') as log:
 for command in [['./configure','--prefix='+str(prefix),*options],['make','-j4'],['make','install']]:
  subprocess.run(command,cwd=source,stdout=log,stderr=subprocess.STDOUT,check=True)
version=subprocess.check_output([str(prefix/'bin/postgres'),'--version'],text=True).strip()
(cache/'postgresql-native-build.json').write_text(json.dumps({'version':version,'source':base+archive.name,'sha256':actual,'prefix':str(prefix),'configure':options,'purpose':'Owned loopback integration fallback; no production packaging or Docker qualification.'},indent=2)+'\n')
print(version+' installed in the project cache; no global service started.')
