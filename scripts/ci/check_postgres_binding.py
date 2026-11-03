#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Check the actual owned GitHub service's Docker port map, without credentials."""
import json
import sys


def valid_binding(value):
    return (isinstance(value, dict)
            and set(value) == {'5432/tcp'}
            and value['5432/tcp'] == [{'HostIp': '127.0.0.1', 'HostPort': '35432'}])


def main():
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384 or not valid_binding(json.loads(raw)):
            raise ValueError('service binding')
    except (ValueError, UnicodeError):
        raise SystemExit('FAIL: CI PostgreSQL must expose exactly 127.0.0.1:35432 to port 5432/tcp')
    print('PASS: actual CI PostgreSQL service exposes only 127.0.0.1:35432')


if __name__ == '__main__':
    main()
