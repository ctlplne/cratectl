# SPDX-License-Identifier: BUSL-1.1
"""Closed safe evidence for the owned requirement graph's two-host journey."""
import re

FILES = {'manifest.json', 'journal.jsonl', 'checkpoint.json', 'checkpoint.sig',
         'signer-public.pem', 'bindings.json', 'receipt.json', 'main.mod',
         'requirements.json', 'selection.json'} | {
             'input.%04d.%s' % (n, kind) for n in range(3) for kind in ('manifest.json', 'mod')} | {
             'root.%03d.%s' % (n, kind) for n in range(2) for kind in ('zip', 'mod', 'info')}
STAGES = {
    'producer': ['native_identity', 'native_postgresql_requirement_fixture', 'original_requirement_files_bound', 'transport_bound'],
    'consumer': ['native_identity', 'transport_bound', 'network_isolation_observed',
                 'complete_requirement_proxy_and_sdk', 'acknowledgement_loss_exact_replay', 'original_inputs_and_proof_retained',
                 'changed_parent_refused', 'changed_lower_mod_refused', 'truncated_journal_refused',
                 'changed_signature_refused', 'wrong_independent_key_refused', 'wrong_set_refused',
                 'copied_unsupported_receipt_refused', 'unknown_member_refused'],
}
HASHES = {'fixture_sha256', 'public_key_sha256', 'source_runner_sha256', 'destination_runner_sha256',
          'go_binary_sha256', 'fixture_source_sha256', 'capsule_source_sha256', 'script_sha256',
          'native_helper_sha256', 'probe_helper_sha256', 'process_helper_sha256', 'decoder_sha256', 'graph_fixture_source_sha256',
          'reader_source_sha256', 'network_probe_sha256', 'native_journey_sha256'}


def safe_go_requirement_export_portability_contract(value, status):
    fields = {'profile', 'role', 'completed', 'go_version', 'source_run_id', 'source_arch',
              'destination_arch', 'files_sha256', 'network_isolated', 'network_tools_sha256',
              'namespace_commands', 'examined_sources', 'selected_roots', 'automatic_closure',
              'checksum_authority', 'destination_admission', *HASHES}
    if (not isinstance(value, dict) or set(value) != fields
            or value['profile'] != 'hosted-requirement-export-cross-runner-v1'
            or not isinstance(value['role'], str) or value['role'] not in STAGES
            or status not in ('passed', 'failed')):
        raise ValueError('Unexpected requirement portability fields or profile')
    role = value['role']
    if (value['source_arch'] != 'amd64' or value['destination_arch'] != ('arm64' if role == 'consumer' else None)
            or not isinstance(value['source_run_id'], str) or not re.fullmatch('[1-9][0-9]{0,19}', value['source_run_id'])
            or type(value['examined_sources']) is not int or value['examined_sources'] != 3
            or type(value['selected_roots']) is not int or value['selected_roots'] != 2
            or value['automatic_closure'] is not False or value['checksum_authority'] is not False
            or value['destination_admission'] is not False):
        raise ValueError('Requirement portability context or trust scope changed')
    stages, completed = STAGES[role], value['completed']
    if (not isinstance(completed, list) or len(completed) > len(stages)
            or completed != stages[:len(completed)]):
        raise ValueError('Requirement portability requires every ordered mandatory stage')
    for name in HASHES:
        h = value[name]
        if h is not None and (not isinstance(h, str) or not re.fullmatch('[a-f0-9]{64}', h)):
            raise ValueError('Requirement portability identity must be exact SHA256')
    if value['go_version'] not in (None, '1.27.3'):
        raise ValueError('Requirement portability needs pinned stock Go1.27.3')
    hashes, tools = value['files_sha256'], value['network_tools_sha256']
    if (not isinstance(hashes, dict) or not set(hashes) <= FILES
            or any(not isinstance(h, str) or not re.fullmatch('[a-f0-9]{64}', h) for h in hashes.values())
            or not isinstance(tools, dict) or not set(tools) <= {'sudo', 'unshare', 'setpriv'}
            or any(not isinstance(h, str) or not re.fullmatch('[a-f0-9]{64}', h) for h in tools.values())
            or type(value['network_isolated']) is not bool
            or type(value['namespace_commands']) is not int or not 0 <= value['namespace_commands'] <= 25):
        raise ValueError('Requirement original-byte inventory or isolation exceeds bounds')
    if status == 'passed':
        optional = {'destination_runner_sha256', 'network_probe_sha256', 'native_journey_sha256'} if role == 'producer' else set()
        if (completed != stages or value['go_version'] != '1.27.3' or set(hashes) != FILES
                or any(value[h] is None for h in HASHES - optional)
                or hashes['signer-public.pem'] != value['public_key_sha256']):
            raise ValueError('Passed requirement portability needs every original and control')
        if role == 'producer':
            if (any(value[h] is not None for h in optional) or value['network_isolated']
                    or tools or value['namespace_commands'] != 0):
                raise ValueError('Requirement producer cannot claim destination observations')
        elif (value['source_runner_sha256'] == value['destination_runner_sha256']
              or not value['network_isolated'] or value['namespace_commands'] != 25
              or set(tools) != {'sudo', 'unshare', 'setpriv'}):
            raise ValueError('Requirement consumer needs a distinct runner and all25 empty command networks')
    return {**value, 'files_sha256': dict(sorted(hashes.items())), 'network_tools_sha256': dict(sorted(tools.items()))}
