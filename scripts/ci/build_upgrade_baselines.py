#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Rebuild pinned historical servers only on a disposable GitHub Linux runner."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from qualification_contract import validate_historical_build


def baselines():
    rows = json.loads((ROOT / 'docs/qualification/upgrade-baselines.json').read_text())['baselines']
    if len(rows) != 12 or {row['schema'] for row in rows} != {None, *range(2, 13)}:
        raise ValueError('Historical schema inventory is incomplete')
    sources, outputs = set(), set()
    for row in rows:
        path = ROOT / row['binary']
        if not re.fullmatch('[0-9a-f]{40}', row['source']) or row['source'] in sources:
            raise ValueError('Historical source must be a distinct full commit')
        if not path.resolve().is_relative_to(ROOT / '.cache') or path.name != 'cratectld' or path in outputs:
            raise ValueError('Historical output must be a distinct owned cache binary')
        sources.add(row['source'])
        outputs.add(path)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Check pins and reachable sources without building or creating worktrees')
    args = parser.parse_args()
    rows = baselines()
    candidate = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    for row in rows:
        subprocess.run(['git', 'merge-base', '--is-ancestor', row['source'], candidate], cwd=ROOT, check=True)
    if args.check:
        print(f'PASS: {len(rows)} pinned historical sources are reachable; no build or worktree created')
        return
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux' or Path(os.environ.get('GITHUB_WORKSPACE', '/')).resolve() != ROOT:
        raise SystemExit('Historical rebuilds require this disposable GitHub Linux workspace; use --check for read-only local preflight')
    go = subprocess.check_output(['which', 'go'], text=True).strip()
    architecture = subprocess.check_output([go, 'env', 'GOARCH'], text=True).strip()
    native_architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if architecture != native_architecture:
        raise SystemExit('Historical build target must match the actual native runner architecture')
    environment = dict(os.environ, GOTOOLCHAIN='local', GOCACHE=str(ROOT / '.cache/go-build'), GOMODCACHE=str(ROOT / '.cache/go-mod'))
    result = {'candidate': candidate, 'status': 'running', 'checks': [], 'baselines': [], 'limits': [
        'Native rebuilt historical servers for disposable controlled-upgrade fixtures only.',
        'No retained primary, production migration, rolling compatibility, backup/restore or release readiness claim.',
    ]}
    evidence = ROOT / 'evidence' / datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    evidence.mkdir(parents=True, exist_ok=True)
    record = evidence / ('historical-build-' + uuid.uuid4().hex[:10] + '.json')
    try:
        for row in rows:
            worktree = ROOT / '.cache/ci-historical-sources' / row['source']
            output = ROOT / row['binary']
            if worktree.exists() or output.exists():
                raise ValueError('Historical rebuild requires absent worktree and output; refusing cache reuse')
            worktree.parent.mkdir(parents=True, exist_ok=True)
            output.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(['git', 'worktree', 'add', '--detach', str(worktree), row['source']], cwd=ROOT, check=True)
            subprocess.run([go, 'build', '-trimpath', '-o', str(output), './cmd/cratectld'], cwd=worktree, env=environment, check=True, timeout=180)
            if subprocess.check_output(['git', 'status', '--porcelain'], cwd=worktree).strip():
                raise ValueError('Historical source changed during the build')
            metadata = subprocess.check_output([go, 'version', '-m', str(output)], text=True)
            validate_historical_build(metadata, row['source'], 'linux', architecture)
            result['baselines'].append({**row, 'binary_sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'goos': 'linux', 'goarch': architecture})
            result['checks'].append(f'clean native historical source {row["source"]}')
            record.write_text(json.dumps(result, indent=2) + '\n')
            print(f'PASS: rebuilt schema {row["schema"]} from {row["source"]} on linux/{architecture}', flush=True)
        result['status'] = 'passed'
    except BaseException:
        result['status'] = 'failed'
        raise
    finally:
        record.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
