#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Print bounded, credential-free Playwright failure locations from private reports."""

import json
from pathlib import Path

root = Path(__file__).resolve().parents[2]
reports = list((root / '.private/console-conformance').glob('*/browser-results.json'))
if not reports:
    print('No private Playwright JSON report was produced; inspect the preceding CI step.')
    raise SystemExit(0)

report = json.loads(max(reports, key=lambda path: path.stat().st_mtime).read_text())
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
                        print(f'  error location: {Path(str(location.get("file", "unknown"))).name}:{int(location.get("line", 0))}')
if shown > 20:
    print(f'{shown - 20} more nonpassing tests omitted.')
