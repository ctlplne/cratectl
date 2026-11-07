#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Print bounded, credential-free Playwright failure locations from private reports."""

import json
from pathlib import Path
import re

def safe_focus_target(message):
    for label, value in [('Verified repair source file', 'verified_source'), ('Repair reason', 'repair_reason')]:
        if label in message:
            return value
    return 'unknown'


def safe_error_kind(message):
    # Source frames embedded later in the message can mention unrelated
    # matchers. Classify only the actual error header.
    lines = re.sub(r'\x1b\[[0-9;]*m', '', message).splitlines()
    header = next((line for line in lines if line.strip()), '')
    if 'response.json' in header or 'Network.getResponseBody' in header:
        return 'response_body'
    if 'locator.click' in header and 'strict mode violation' in header:
        return 'locator_ambiguous'
    for marker, kind in [('toBeFocused', 'assert_focus'), ('toBeVisible', 'assert_visible'), ('toEqual', 'assert_equal'), ('toBe(', 'assert_value'), ('page.waitForResponse', 'response_wait'), ('locator.click', 'click')]:
        if marker in header:
            return kind
    if 'timeout' in header.lower():
        return 'timeout'
    return 'unclassified'


def safe_axe_findings(proof, states=None):
    if states is None:
        states = {'exact byte repair form', 'byte repair impact preview', 'repair awaiting source', 'repair rejects incorrect source digest', 'repair verified with immutable observation'}
    lines = []
    observations = proof.get('accessibility', []) if isinstance(proof, dict) else []
    if not isinstance(observations, list):
        return lines
    for observation in observations[:10]:
        if not isinstance(observation, dict):
            continue
        if not isinstance(observation.get('state'), str) or observation['state'] not in states:
            continue
        findings = observation.get('findings', [])
        if not isinstance(findings, list):
            continue
        for finding in findings[:20]:
            if not isinstance(finding, dict):
                continue
            rule, impact, nodes = finding.get('id', ''), finding.get('impact'), finding.get('nodes')
            if not isinstance(rule, str) or not re.fullmatch('[a-z][a-z0-9-]{0,79}', rule) or impact not in ('minor', 'moderate', 'serious', 'critical', None) or type(nodes) is not int or not 0 <= nodes <= 10000:
                continue
            lines.append(f'{observation["state"]}: rule={rule} impact={impact} nodes={nodes}')
    return lines


def safe_go_export_progress(proof):
    if not isinstance(proof, dict):
        return []
    phases = {'connect', 'commands', 'import-command', 'create', 'unsafe', 'loading', 'denied', 'expiry', 'reader', 'complete'}
    states = {'export historical source list', 'export collection command scroll region',
              'export explicit destination import instructions', 'export unsigned preview and current recheck',
              'export unsafe generation', 'export unreconciled expiry', 'export reader denied'}
    lines = []
    if isinstance(proof.get('phase'), str) and proof['phase'] in phases:
        lines.append('Hosted export workflow phase: ' + proof['phase'])
    if isinstance(proof.get('checks'), list) and len(proof['checks']) <= 32:
        lines.append(f'Hosted export workflow progress: {len(proof["checks"])} completed checks')
    lines.extend('Hosted export accessibility finding: ' + line for line in safe_axe_findings(proof, states))
    return lines


def safe_nuget_progress(proof):
    phases = {'connect', 'create_repository', 'client_configuration', 'publication_and_grants', 'exact_review', 'policy_denial', 'retained_lifecycle', 'grant_revocation', 'complete'}
    lines = []
    if proof.get('phase') in phases:
        lines.append('NuGet workflow phase: ' + proof['phase'])
    if isinstance(proof.get('checks'), list) and len(proof['checks']) <= 32:
        lines.append(f'NuGet workflow progress: {len(proof["checks"])} completed checks')
    return lines


def main():
    root = Path(__file__).resolve().parents[2]
    reports = list((root / '.private/console-conformance').glob('*/browser-results.json'))
    if not reports:
        print('No private Playwright JSON report was produced; inspect the preceding CI step.')
        raise SystemExit(0)

    report_path = max(reports, key=lambda path: path.stat().st_mtime)
    report = json.loads(report_path.read_text())
    proof_path = report_path.parent / 'repair-browser-proof.json'
    if proof_path.is_file() and proof_path.stat().st_size <= 1 << 20:
        proof = json.loads(proof_path.read_text())
        if proof.get('phase') in ('fixture', 'connect', 'open_repair', 'create_operation', 'source_focus', 'source_accessibility', 'navigate_jobs', 'resume_source', 'wrong_source', 'exact_source', 'credential_checks', 'complete'):
            print('Repair workflow phase: ' + proof['phase'])
        if isinstance(proof.get('checks'), list):
            print(f'Repair workflow progress: {len(proof["checks"])} completed checks')
        for finding in safe_axe_findings(proof):
            print('Repair accessibility finding: ' + finding)
    nuget_path = report_path.parent / 'nuget-browser-proof.json'
    if nuget_path.is_file() and nuget_path.stat().st_size <= 1 << 20:
        for line in safe_nuget_progress(json.loads(nuget_path.read_text())):
            print(line)
    export_path = report_path.parent / 'go-export-browser-proof.json'
    if export_path.is_file() and export_path.stat().st_size <= 1 << 20:
        for line in safe_go_export_progress(json.loads(export_path.read_text())):
            print(line)
    stats = report.get('stats', {})
    print('Playwright counts: ' + ', '.join(f'{key}={int(stats.get(key, 0))}' for key in ('expected', 'unexpected', 'skipped', 'flaky')))


    def specs(suite):
        yield from suite.get('specs', [])
        for child in suite.get('suites', []):
            yield from specs(child)


    shown = 0
    for suite in report.get('suites', []):
        for spec in specs(suite):
            for test in spec.get('tests', []):
                if test.get('status') == 'expected':
                    continue
                shown += 1
                if shown > 20:
                    continue
                source = Path(str(spec.get('file', 'unknown'))).name
                line = int(spec.get('line', 0))
                print(f'Nonpassing test: {source}:{line}; status={test.get("status", "unknown")}')
                for result in test.get('results', [])[-2:]:
                    print(f'  attempt={result.get("retry", 0)} status={result.get("status", "unknown")}')
                    message = ''
                    for error in result.get('errors', [])[:3]:
                        location = error.get('location') or {}
                        if location:
                            print(f'  error location: {Path(str(location.get("file", "unknown"))).name}:{int(location.get("line", 0))}:{int(location.get("column", 0))}')
                        message = str(error.get('message', ''))
                    kind = safe_error_kind(message)
                    print('  error kind: ' + kind)
                    if kind == 'assert_focus':
                            print('  focus target: ' + safe_focus_target(message))
    if shown > 20:
        print(f'{shown - 20} more nonpassing tests omitted.')


if __name__ == '__main__':
    main()
