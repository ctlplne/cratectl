#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Build/reproduce embedded assets. Dependency installation is an explicit separate step."""
import argparse,hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1];os.chdir(root)
parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
target=root/'internal/consoleui/dist';temporary=None
if args.check:
    (root/'.cache').mkdir(exist_ok=True);temporary=Path(tempfile.mkdtemp(prefix='console-build-',dir=root/'.cache'));target=temporary
env=dict(os.environ)
for key in ['CRATECTL_OWNER_DSN','CRATECTL_DSN']:env.pop(key,None)
try:
    subprocess.run(['npm','--prefix','web','run','build',*(['--','--outDir',str(target)]if args.check else[])],env=env,check=True)
    notices=['cratectl operator console\nOriginal application: BUSL-1.1; see the repository licensing records.\nBundled runtime components retain their licenses below.\n']
    for name in ['react','react-dom','scheduler']:
        package=root/'web/node_modules'/name;metadata=json.loads((package/'package.json').read_text())
        notices.append('\n--- '+name+' '+metadata['version']+' ---\n'+(package/'LICENSE').read_text())
    (target/'third-party-notices.txt').write_text('\n'.join(notices))
    sources=[Path(p)for p in ['web/package.json','web/package-lock.json','web/tsconfig.json','web/vite.config.ts','web/index.html','scripts/build_console.py']]+sorted(Path('web/src').rglob('*'))
    sources=[{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in sources if p.is_file()]
    assets={str(p.relative_to(target)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(target.rglob('*'))if p.is_file()}
    manifest={'sources':sources,'asset_sha256':assets,'build':'TypeScript check, Vite production build and bundled React/ReactDOM/scheduler license notices. No source maps or external assets.'}
    path=root/'web/build-manifest.json'
    if args.check:
        if manifest!=json.loads(path.read_text()):raise SystemExit('Embedded console differs from its source. Run python3 scripts/build_console.py and inspect the generated diff.')
        print('PASS: embedded console reproduces byte-for-byte from pinned source')
    else:path.write_text(json.dumps(manifest,indent=2)+'\n');print('Embedded console and source/asset digest manifest written')
finally:
    if temporary:shutil.rmtree(temporary)
