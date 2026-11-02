#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Run every checked-in Go fuzz target for a bounded native-runner smoke budget."""

import os
from pathlib import Path
import platform
import re
import subprocess

root = Path(__file__).resolve().parents[2]
go = root / '.cache/go/bin/go'
executable = str(go) if go.exists() else 'go'
targets = []
for path in sorted((root / 'internal').rglob('*_test.go')):
    for match in re.finditer(r'^func\s+(Fuzz[A-Za-z0-9_]+)\s*\(', path.read_text(), re.MULTILINE):
        targets.append((f'./{path.parent.relative_to(root)}', match.group(1)))
if not targets or len(targets) > 100:
    raise SystemExit('Go fuzz target inventory is empty or exceeds its CI bound')

environment = dict(os.environ, GOTOOLCHAIN='local', GOCACHE=str(root / '.cache/go-build'), GOMODCACHE=str(root / '.cache/go-mod'))
print(f'Native {platform.system()} {platform.machine()}: {len(targets)} Go fuzz targets, 5 seconds each', flush=True)
for package, name in targets:
    command = [executable, 'test', '-run=^$', f'-fuzz=^{name}$', '-fuzztime=5s', '-parallel=2', '-timeout=90s', package]
    print(f'FUZZ {package} {name}', flush=True)
    result = subprocess.run(command, cwd=root, env=environment, capture_output=True, text=True, timeout=120)
    output = result.stdout + result.stderr
    if result.returncode:
        print(output[-12000:], flush=True)
        raise SystemExit(f'Go fuzz target failed: {package} {name}')
    print(output[-800:].strip(), flush=True)
print(f'PASS: {len(targets)} bounded native Go fuzz targets', flush=True)
