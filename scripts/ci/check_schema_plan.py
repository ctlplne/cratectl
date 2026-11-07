#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Validate the source-pinned current migration plan without echoing its input."""
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qualification_contract import CURRENT_SCHEMA

MAX_PLAN_BYTES = 64 << 10
FIELDS = {'binary_version', 'database_state', 'applied', 'pending', 'requires_legacy_adoption', 'safety_valid'}


def validate_current_plan(value):
    if (not isinstance(value, dict) or set(value) != FIELDS
            or type(value['binary_version']) is not int or value['binary_version'] != CURRENT_SCHEMA
            or value['database_state'] != 'current' or value['safety_valid'] is not True
            or value['requires_legacy_adoption'] is not False or value['pending'] != []
            or not isinstance(value['applied'], list) or len(value['applied']) != CURRENT_SCHEMA):
        raise ValueError('CI migration plan does not match the complete safe source target')
    for version, row in enumerate(value['applied'], start=1):
        if (not isinstance(row, dict) or set(row) != {'version', 'checksum'}
                or type(row['version']) is not int or row['version'] != version
                or not isinstance(row['checksum'], str) or not re.fullmatch('[a-f0-9]{64}', row['checksum'])):
            raise ValueError('CI migration receipt inventory is incomplete or malformed')


def read_plan(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PLAN_BYTES:
        raise ValueError('CI migration plan exceeds its input bound')

    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError('Duplicate CI migration plan field')
            out[key] = value
        return out

    def reject_constant(_):
        raise ValueError('Nonfinite JSON is not a migration plan')

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid bounded CI migration plan JSON') from None
    validate_current_plan(value)
    return value


def main():
    try:
        read_plan(sys.stdin.buffer.read(MAX_PLAN_BYTES + 1))
    except ValueError as error:
        raise SystemExit(str(error)) from None
    print(f'PASS: complete safe schema {CURRENT_SCHEMA} plan matches the committed source target')


if __name__ == '__main__':
    main()
