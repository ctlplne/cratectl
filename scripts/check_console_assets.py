#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Offline source/asset consistency gate; native builds do not need Node."""
from pathlib import Path
import hashlib,json
root=Path(__file__).resolve().parents[1]
manifest=json.loads((root/'web/build-manifest.json').read_text())
for prefix,entries in [(root,manifest['sources']),(root/'internal/consoleui/dist',[{'path':name,'sha256':digest}for name,digest in manifest['asset_sha256'].items()])]:
    for entry in entries:
        p=prefix/entry['path']
        if not p.is_file()or hashlib.sha256(p.read_bytes()).hexdigest()!=entry['sha256']:raise SystemExit('Console source/assets changed: run python3 scripts/build_console.py and review the generated diff.')
actual={str(p.relative_to(root/'internal/consoleui/dist'))for p in (root/'internal/consoleui/dist').rglob('*')if p.is_file()}
if actual!=set(manifest['asset_sha256']):raise SystemExit('Unexpected embedded console assets; rebuild and review')
source_paths={str(p.relative_to(root))for p in (root/'web/src').rglob('*')if p.is_file()}
if source_paths!={p['path']for p in manifest['sources']if p['path'].startswith('web/src/')}:raise SystemExit('Console source set changed; rebuild and review')
print('PASS: embedded console matches the recorded source and asset digests')
