#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Bounded transport decoding for an owned fixture; this does not authenticate packages."""
import base64
import os
from pathlib import Path
import re
import stat

from ci.campaign_transport import strict_json
from ci.go_common_export_portability_evidence import FILES

CAPSULE_LIMIT = 2 << 20
MEMBER_LIMIT = 512 << 10
TOTAL_LIMIT = 1 << 20
MODULE_PREFIX = 'go.cratectl.invalid/Owned/' + 'a' * 100 + '/' + 'b' * 100 + '/' + 'c' * 100
FIELDS = {'profile', 'candidate', 'source_run_id', 'source_job', 'source_runner_sha256',
          'source_os', 'source_arch', 'tenant', 'set_id', 'created_sequence', 'through',
          'root_module', 'root_count', 'files'}


def decode_common_fixture(raw, candidate, run_id):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= CAPSULE_LIMIT:
        raise ValueError('Common capsule exceeds its byte bound')
    value = strict_json(raw)
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError('Common capsule contains unreviewed fields')
    if (value['profile'] != 'cratectl.go.common-export.portable.fixture.v1'
            or not isinstance(candidate, str) or not re.fullmatch('[a-f0-9]{40}', candidate)
            or value['candidate'] != candidate or not isinstance(run_id, str)
            or not re.fullmatch('[1-9][0-9]{0,19}', run_id) or value['source_run_id'] != run_id
            or value['source_job'] != 'produce' or value['source_os'] != 'linux'
            or value['source_arch'] != 'amd64' or value['tenant'] != 'schema-team'
            or value['root_module'] != MODULE_PREFIX + '/node0'
            or type(value['root_count']) is not int or value['root_count'] != 8):
        raise ValueError('Common capsule is outside its owned candidate/run/coordinate')
    for key in ('source_runner_sha256', 'set_id'):
        if not isinstance(value[key], str) or not re.fullmatch('[a-f0-9]{64}', value[key]):
            raise ValueError('Common capsule identity is not canonical')
    head, sequence = value['through'], value['created_sequence']
    if (not isinstance(head, dict) or set(head) != {'tenant', 'sequence', 'hash'}
            or head['tenant'] != 'schema-team' or type(head['sequence']) is not int
            or not 1 <= head['sequence'] <= (1 << 63) - 1
            or not isinstance(head['hash'], str) or not re.fullmatch('[a-f0-9]{64}', head['hash'])
            or type(sequence) is not int or not 1 <= sequence <= head['sequence']):
        raise ValueError('Common capsule terminal checkpoint is incomplete or inconsistent')
    if not isinstance(value['files'], dict) or set(value['files']) != FILES:
        raise ValueError('Common capsule must contain exactly the reviewed 31 original members')
    decoded, total = {}, 0
    for name, encoded in value['files'].items():
        if not isinstance(encoded, str) or not 0 < len(encoded) <= 4 * ((MEMBER_LIMIT + 2) // 3):
            raise ValueError('Common capsule member encoding exceeds its bound')
        try:
            body = base64.b64decode(encoded, validate=True)
        except (ValueError, UnicodeError):
            raise ValueError('Common capsule member is not strict base64') from None
        if (not 0 < len(body) <= MEMBER_LIMIT or len(body) > TOTAL_LIMIT - total
                or base64.b64encode(body).decode() != encoded or b'PRIVATE KEY' in body):
            raise ValueError('Common capsule member is oversized, ambiguous or contains forbidden key material')
        total += len(body)
        decoded[name] = body
    if (len(decoded['checkpoint.sig']) != 64
            or not decoded['signer-public.pem'].startswith(b'-----BEGIN PUBLIC KEY-----\n')):
        raise ValueError('Common capsule must retain the public checkpoint proof')
    return value, decoded


def read_common_capsule(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > CAPSULE_LIMIT or before.st_nlink != 1:
        raise ValueError('Common capsule must be one bounded unshared regular file')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as source:
        actual = os.fstat(source.fileno())
        if not os.path.samestat(before, actual):
            raise ValueError('Common capsule changed before reading')
        raw = source.read(CAPSULE_LIMIT + 1)
        after = os.fstat(source.fileno())
    mapped = path.lstat()
    if (len(raw) > CAPSULE_LIMIT or len(raw) != actual.st_size or actual.st_size != after.st_size
            or actual.st_mtime_ns != after.st_mtime_ns or not os.path.samestat(after, mapped)
            or after.st_nlink != 1):
        raise ValueError('Common capsule changed while reading')
    return raw
