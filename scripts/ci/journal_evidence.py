# SPDX-License-Identifier: BUSL-1.1
"""Reviewed scalar evidence for the actual external-tool checkpoint profile."""
import re

STAGES = ['prepare_exact_unsigned', 'openssl_sign_exact_bytes', 'openssl_verify_exact_bytes',
          'offline_signature_verify', 'collector_signature_verify', 'changed_statement_rejected',
          'wrong_key_rejected', 'changed_signature_rejected', 'changed_head_rejected',
          'partial_signature_flags_rejected', 'private_key_rejected']
HASHES = {'openssl_binary_sha256', 'statement_sha256', 'signature_sha256', 'public_key_pem_sha256', 'public_key_der_sha256', 'journal_export_sha256'}

def safe_journal_checkpoint_contract(value, status):
    expected = {'profile', 'openssl_version', 'completed', *HASHES}
    if not isinstance(value, dict) or set(value) != expected or value.get('profile') != 'journal-checkpoint-openssl-v1':
        raise ValueError('Unexpected journal checkpoint evidence fields or profile')
    if not isinstance(value['openssl_version'], str) or not re.fullmatch(r'(?:3|4)\.[0-9]{1,3}\.[0-9]{1,3}[a-z]?', value['openssl_version']):
        raise ValueError('Invalid bounded OpenSSL version')
    for name in HASHES:
        if not isinstance(value[name], str) or not re.fullmatch('[a-f0-9]{64}', value[name]):
            raise ValueError('Missing exact public checkpoint/tool byte binding')
    stages = value['completed']
    if not isinstance(stages, list) or stages != STAGES[:len(stages)] or len(stages) > len(STAGES) or status not in {'passed', 'failed'}:
        raise ValueError('Invalid checkpoint control outcomes')
    if status == 'passed' and stages != STAGES:
        raise ValueError('Incomplete external checkpoint signature profile')
    return value
