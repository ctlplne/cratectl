# SPDX-License-Identifier: BUSL-1.1
"""Public, bounded observations for the owned two-runner export fixture."""
import re

FILES = {'original.zip', 'original.mod', 'original.info', 'manifest.json',
         'journal.jsonl', 'checkpoint.json', 'signer-public.pem', 'checkpoint.sig'}
STAGES = {
    'producer': ['native_identity', 'native_postgresql_fixture', 'transport_bound'],
    'consumer': ['native_identity', 'transport_bound', 'network_isolation_observed', 'signed_export_verified',
                 'stock_go_exact_bytes', 'existing_output_rejected',
                 'changed_manifest_rejected', 'changed_zip_rejected',
                 'truncated_journal_rejected', 'changed_statement_rejected',
                 'changed_signature_rejected', 'wrong_key_rejected',
                 'wrong_export_rejected'],
}
HASHES = {'fixture_sha256', 'public_key_sha256', 'source_runner_sha256',
          'destination_runner_sha256', 'go_binary_sha256', 'fixture_source_sha256',
          'script_sha256', 'network_probe_sha256'}


def safe_go_export_portability_contract(value, status):
    fields = {'profile', 'role', 'completed', 'go_version', 'source_run_id',
              'source_arch', 'destination_arch', 'files_sha256', 'network_isolated', 'network_tools_sha256', *HASHES}
    if (not isinstance(value, dict) or set(value) != fields
            or value['profile'] != 'hosted-export-cross-runner-v1'
            or not isinstance(value['role'], str) or value['role'] not in STAGES or status not in ('passed', 'failed')):
        raise ValueError('Unexpected export portability evidence fields or profile')
    role = value['role']
    if type(value['network_isolated']) is not bool:
        raise ValueError('Portability isolation must be an explicit observed boolean')
    tools = value['network_tools_sha256']
    if (not isinstance(tools, dict) or not set(tools) <= {'sudo', 'unshare', 'setpriv'}
            or any(not isinstance(h, str) or not re.fullmatch('[a-f0-9]{64}', h) for h in tools.values())):
        raise ValueError('Portability namespace utilities require reviewed exact identities')
    stages, completed = STAGES[role], value['completed']
    if (not isinstance(completed, list) or len(completed) > len(stages)
            or completed != stages[:len(completed)]):
        raise ValueError('Portability stages must be the ordered mandatory prefix')
    if value['source_arch'] != 'amd64' or value['destination_arch'] != ('arm64' if role == 'consumer' else None):
        raise ValueError('Portability requires the declared native source and destination architectures')
    if not isinstance(value['source_run_id'], str) or not re.fullmatch(r'[1-9][0-9]{0,19}', value['source_run_id']):
        raise ValueError('Portability requires a bounded original workflow identity')
    if value['go_version'] not in (None, '1.27.3'):
        raise ValueError('Portability uses the exact pinned native Go runtime')
    for key in HASHES:
        if value[key] is not None and (not isinstance(value[key], str) or not re.fullmatch('[a-f0-9]{64}', value[key])):
            raise ValueError('Portability identities must be exact SHA256 digests')
    hashes = value['files_sha256']
    if (not isinstance(hashes, dict) or not set(hashes) <= FILES
            or any(not isinstance(h, str) or not re.fullmatch('[a-f0-9]{64}', h) for h in hashes.values())):
        raise ValueError('Portability file inventory exceeds the reviewed synthetic fixture')
    if status == 'passed':
        required = HASHES - ({'destination_runner_sha256', 'network_probe_sha256'} if role == 'producer' else set())
        if (completed != stages or value['go_version'] != '1.27.3'
                or any(value[k] is None for k in required) or set(hashes) != FILES
                or hashes['signer-public.pem'] != value['public_key_sha256']):
            raise ValueError('Passed portability requires every control and exact public input identity')
        if role == 'consumer' and value['source_runner_sha256'] == value['destination_runner_sha256']:
            raise ValueError('Portability cannot substitute the producer runner for the consumer')
        if role == 'producer' and value['destination_runner_sha256'] is not None:
            raise ValueError('A producer cannot claim a destination observation')
        if role == 'consumer' and (not value['network_isolated'] or set(tools) != {'sudo', 'unshare', 'setpriv'}):
            raise ValueError('Passed consumption requires actual kernel network isolation and its utilities')
        if role == 'producer' and (value['network_isolated'] or tools or value['network_probe_sha256'] is not None):
            raise ValueError('A producer cannot claim an isolated consumer')
    return {**value, 'files_sha256': dict(sorted(hashes.items()))}
