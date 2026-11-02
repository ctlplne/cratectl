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


def safe_axe_findings(proof):
    states = {'exact byte repair form', 'byte repair impact preview', 'repair awaiting source', 'repair rejects incorrect source digest', 'repair verified with immutable observation'}
    lines = []
    for observation in proof.get('accessibility', [])[:10]:
        if observation.get('state') not in states:
            continue
        for finding in observation.get('findings', [])[:20]:
            rule, impact, nodes = finding.get('id', ''), finding.get('impact'), finding.get('nodes')
            if not re.fullmatch('[a-z][a-z0-9-]{0,79}', rule) or impact not in ('minor', 'moderate', 'serious', 'critical', None) or type(nodes) is not int or not 0 <= nodes <= 10000:
                continue
            lines.append(f'{observation["state"]}: rule={rule} impact={impact} nodes={nodes}')
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
        if isinstance(proof.get('checks'), list):
            print(f'Repair workflow progress: {len(proof["checks"])} completed checks')
        for finding in safe_axe_findings(proof):
            print('Repair accessibility finding: ' + finding)
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
                    for error in result.get('errors', [])[:3]:
                        location = error.get('location') or {}
                        if location:
                            print(f'  error location: {Path(str(location.get("file", "unknown"))).name}:{int(location.get("line", 0))}:{int(location.get("column", 0))}')
                        message = str(error.get('message', ''))
                        kinds = ('toBeFocused', 'toBeVisible', 'toEqual', 'toBe', 'page.waitForResponse', 'locator.click', 'TimeoutError')
                        print('  error kind: ' + next((kind for kind in kinds if kind in message), 'unclassified'))
                        if 'toBeFocused' in message:
                            print('  focus target: ' + safe_focus_target(message))
    if shown > 20:
        print(f'{shown - 20} more nonpassing tests omitted.')


if __name__ == '__main__':
    main()
