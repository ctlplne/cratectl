#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Export only reviewed CI evidence fields; never publish raw runner reports."""

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def summarize(root, environment):
    paths = subprocess.check_output(['git', 'ls-files', '--others', '--modified', '--exclude-standard', '-z', '--', 'evidence'], cwd=root).split(b'\0')
    if len(paths) > 201:
        raise SystemExit('Too many generated evidence files for a bounded CI summary')

    candidate = environment.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', candidate):
        raise SystemExit('CI evidence requires an exact candidate commit')
    native_os = {'Linux': 'linux', 'macOS': 'darwin', 'Windows': 'windows'}.get(environment.get('RUNNER_OS'))
    native_arch = {'X64': 'amd64', 'ARM64': 'arm64'}.get(environment.get('RUNNER_ARCH'))
    if native_os is None or native_arch is None:
        raise SystemExit('CI evidence requires a reviewed native runner platform')
    artifact_sources = {'.cache/ci-build/cratectld': candidate, '.cache/ci-build/cratectl': candidate, '.cache/bin/oras': None}
    manifest = root / 'docs/qualification/upgrade-baselines.json'
    if manifest.is_file():
        for baseline in json.loads(manifest.read_text())['baselines']:
            artifact_sources[baseline['binary']] = baseline['source']
    summary = {
        'candidate': candidate,
        'run_id': environment.get('GITHUB_RUN_ID', ''),
        'runner_os': environment.get('RUNNER_OS', ''),
        'runner_arch': environment.get('RUNNER_ARCH', ''),
        'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'records': [],
        'limits': [
            'Only counts, report hashes, reviewed binary digests and clean embedded source/platform identities are exported.',
            'Raw evidence, browser reports, private command logs and generated credentials remain on the disposable runner.',
            'This summary establishes only the named CI job stages, not release or product readiness.',
        ],
    }
    for raw_path in paths:
        if not raw_path:
            continue
        relative = Path(raw_path.decode())
        path = root / relative
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
        if 'artifact_digests' in report:
            if not isinstance(report['artifact_digests'], dict) or len(report['artifact_digests']) > 16:
                raise SystemExit('Artifact identity evidence exceeds its inventory bound')
            entry['artifacts'] = []
            for name, digest in sorted(report['artifact_digests'].items()):
                if name not in artifact_sources or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
                    raise SystemExit('Artifact identity is outside the reviewed path/digest allowlist')
                artifact = {'path': name, 'sha256': digest}
                expected_source = artifact_sources[name]
                if expected_source:
                    identity = report.get('build_identity', {}).get(name, {})
                    settings = identity.get('settings', identity)
                    if settings.get('vcs.revision') != expected_source or settings.get('vcs.modified') != 'false' or settings.get('GOOS') not in ('linux', 'darwin', 'windows') or settings.get('GOARCH') not in ('amd64', 'arm64'):
                        raise SystemExit('Artifact embedded source identity is not the expected clean native build')
                    if settings['GOOS'] != native_os or settings['GOARCH'] != native_arch:
                        raise SystemExit('Artifact platform identity does not match the native runner')
                    artifact['build'] = {key: settings[key] for key in ('vcs.revision', 'vcs.modified', 'GOOS', 'GOARCH')}
                entry['artifacts'].append(artifact)
        if isinstance(report.get('browser_stats'), dict):
            entry['browser'] = {key: int(report['browser_stats'].get(key, 0)) for key in ('expected', 'unexpected', 'skipped', 'flaky')}
        if report.get('workflow') in ('all', 'repair'):
            entry['workflow'] = report['workflow']
        for key in ('baseline_version', 'expected_schema'):
            if key in report:
                if type(report[key]) is not int or not 1 <= report[key] <= 1000:
                    raise SystemExit('Schema evidence must be a bounded positive integer')
                entry[key] = report[key]
        if 'baselines' in report:
            if not isinstance(report['baselines'], list) or len(report['baselines']) > 10:
                raise SystemExit('Historical build evidence exceeds its inventory bound')
            entry['baselines'] = []
            for baseline in report['baselines']:
                if baseline.get('schema') not in (None, *range(2, 11)) or not re.fullmatch('[0-9a-f]{40}', baseline.get('source', '')) or not re.fullmatch('[0-9a-f]{64}', baseline.get('binary_sha256', '')):
                    raise SystemExit('Historical build evidence has an invalid source or binary digest')
                entry['baselines'].append({key: baseline[key] for key in ('schema', 'source', 'binary_sha256')})
        summary['records'].append(entry)

    summary['records'].sort(key=lambda entry: entry['report'])
    return summary


def main():
    root = Path(__file__).resolve().parents[2]
    summary = summarize(root, os.environ)
    out = root / '.cache/ci-evidence-summary.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(f'Safe CI evidence summary: {len(summary["records"])} generated reports; {out.relative_to(root)}')
    if not summary['records']:
        raise SystemExit('No generated evidence records; refusing a successful empty summary')


if __name__ == '__main__':
    main()
