#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Export only reviewed CI evidence fields; never publish raw runner reports."""

import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
os.chdir(root)
paths = subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard', '-z', '--', 'evidence']).split(b'\0')
if len(paths) > 201:
    raise SystemExit('Too many generated evidence files for a bounded CI summary')

candidate = os.environ.get('GITHUB_SHA', '')
summary = {
    'candidate': candidate,
    'run_id': os.environ.get('GITHUB_RUN_ID', ''),
    'runner_os': os.environ.get('RUNNER_OS', ''),
    'runner_arch': os.environ.get('RUNNER_ARCH', ''),
    'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'records': [],
    'limits': [
        'Only allowlisted counts, boolean build checks and raw-report digests are exported.',
        'Raw evidence, browser reports, private command logs and generated credentials remain on the disposable runner.',
        'This summary establishes only the named CI job stages, not release or product readiness.',
    ],
}
for raw_path in paths:
    if not raw_path:
        continue
    path = Path(raw_path.decode())
    if path.suffix != '.json' or not path.is_file() or not path.resolve().is_relative_to(root / 'evidence'):
        continue
    data = path.read_bytes()
    if len(data) > 16 << 20:
        raise SystemExit('Generated evidence exceeds the CI summary byte budget')
    report = json.loads(data)
    if not isinstance(report, dict):
        continue
    record_candidate = report.get('candidate') or report.get('source_parent')
    if record_candidate and candidate and record_candidate != candidate:
        raise SystemExit('Generated evidence candidate does not match this CI run')
    status = report.get('status')
    if status not in ('passed', 'failed', 'running', 'manual-review-stopped'):
        status = 'passed' if report.get('passed') is True else 'failed' if report.get('passed') is False else 'unknown'
    entry = {
        'report': path.name,
        'raw_report_sha256': hashlib.sha256(data).hexdigest(),
        'status': status,
        'checks': len(report.get('checks', [])) if isinstance(report.get('checks'), list) else None,
        'cases': len(report.get('results', [])) if isinstance(report.get('results'), list) else None,
        'source_dirty': report.get('source_dirty') if isinstance(report.get('source_dirty'), bool) else None,
        'build_source_matches_candidate': report.get('build_source_matches_candidate') if isinstance(report.get('build_source_matches_candidate'), bool) else None,
    }
    if isinstance(report.get('browser_stats'), dict):
        entry['browser'] = {key: int(report['browser_stats'].get(key, 0)) for key in ('expected', 'unexpected', 'skipped', 'flaky')}
    summary['records'].append(entry)

summary['records'].sort(key=lambda entry: entry['report'])
out = root / '.cache/ci-evidence-summary.json'
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
print(f'Safe CI evidence summary: {len(summary["records"])} generated reports; {out.relative_to(root)}')
