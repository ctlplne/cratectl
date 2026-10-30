#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Guard comma-containing YAML flow descriptions; full API validation is separate."""
from pathlib import Path
import re

source = Path(__file__).resolve().parents[1] / 'api/openapi.yaml'
pattern = re.compile(r'description: ([^\'"{}\n][^{}\n]*)(?=\})')
bad = [number for number, line in enumerate(source.read_text().splitlines(), 1)
       if (match := pattern.search(line)) and ',' in match[1]]
if bad:
    raise SystemExit('Quote comma-containing flow-map descriptions in api/openapi.yaml: '
                     + ', '.join(map(str, bad)))
print('PASS: comma-containing OpenAPI flow descriptions are quoted')
