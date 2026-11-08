#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Decode one bounded owned requirement fixture; this grants no authenticity."""
import base64
import re

from ci.campaign_transport import strict_json
from ci.go_requirement_export_portability_evidence import FILES
from go_common_export_fixture import read_common_capsule as read_requirement_capsule

CAPSULE_LIMIT = 2 << 20
MEMBER_LIMIT = 512 << 10
TOTAL_LIMIT = 1 << 20
MODULE = 'go.cratectl.invalid/Owned/competing'
SELECTOR = 'go.cratectl.invalid/Owned/selector'
FIELDS = {'profile', 'candidate', 'source_run_id', 'source_job', 'source_runner_sha256',
          'source_os', 'source_arch', 'tenant', 'set_id', 'created_sequence', 'through',
          'module', 'selector', 'lower_input', 'examined_sources', 'selected_roots', 'files'}


def decode_requirement_fixture(raw, candidate, run_id):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= CAPSULE_LIMIT:
        raise ValueError('Requirement capsule exceeds its byte bound')
    value = strict_json(raw)
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError('Requirement capsule contains unreviewed fields')
    if (value['profile'] != 'cratectl.go.requirement-export.portable.fixture.v1'
            or not isinstance(candidate, str) or not re.fullmatch('[a-f0-9]{40}', candidate)
            or value['candidate'] != candidate or not isinstance(run_id, str)
            or not re.fullmatch('[1-9][0-9]{0,19}', run_id) or value['source_run_id'] != run_id
            or value['source_job'] != 'produce' or value['source_os'] != 'linux'
            or value['source_arch'] != 'amd64' or value['tenant'] != 'schema-http'
            or value['module'] != MODULE or value['selector'] != SELECTOR or value['lower_input'] != 'input.0000.mod'
            or type(value['examined_sources']) is not int or value['examined_sources'] != 3
            or type(value['selected_roots']) is not int or value['selected_roots'] != 2):
        raise ValueError('Requirement capsule is outside its exact owned source/graph')
    for key in ('source_runner_sha256', 'set_id'):
        if not isinstance(value[key], str) or not re.fullmatch('[a-f0-9]{64}', value[key]):
            raise ValueError('Requirement capsule identity is not canonical')
    head, sequence = value['through'], value['created_sequence']
    if (not isinstance(head, dict) or set(head) != {'tenant', 'sequence', 'hash'}
            or head['tenant'] != 'schema-http' or type(head['sequence']) is not int
            or not 1 <= head['sequence'] <= (1 << 63) - 1
            or not isinstance(head['hash'], str) or not re.fullmatch('[a-f0-9]{64}', head['hash'])
            or type(sequence) is not int or not 1 <= sequence <= head['sequence']):
        raise ValueError('Requirement capsule checkpoint is incomplete or inconsistent')
    if not isinstance(value['files'], dict) or set(value['files']) != FILES:
        raise ValueError('Requirement capsule needs exactly22 reviewed original members')
    decoded, total = {}, 0
    for name, encoded in value['files'].items():
        if not isinstance(encoded, str) or not 0 < len(encoded) <= 4 * ((MEMBER_LIMIT + 2) // 3):
            raise ValueError('Requirement member encoding exceeds its bound')
        try:
            body = base64.b64decode(encoded, validate=True)
        except (ValueError, UnicodeError):
            raise ValueError('Requirement member is not strict base64') from None
        if (not 0 < len(body) <= MEMBER_LIMIT or len(body) > TOTAL_LIMIT - total
                or base64.b64encode(body).decode() != encoded or b'PRIVATE KEY' in body):
            raise ValueError('Requirement member is oversized, ambiguous or contains private keys')
        total += len(body)
        decoded[name] = body
    if (len(decoded['checkpoint.sig']) != 64
            or not decoded['signer-public.pem'].startswith(b'-----BEGIN PUBLIC KEY-----\n')):
        raise ValueError('Requirement capsule needs the original public checkpoint proof')
    return value, decoded
