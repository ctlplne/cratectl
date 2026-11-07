# SPDX-License-Identifier: BUSL-1.1
import unittest

from go_common_export_portability_evidence import (FILES, HASHES, STAGES,
                                                  safe_go_common_export_portability_contract)


def complete(role='consumer'):
    value = {key: 'a' * 64 for key in HASHES}
    value.update(profile='hosted-common-export-cross-runner-v1', role=role, completed=list(STAGES[role]),
                 go_version='1.27.3', source_run_id='123', source_arch='amd64',
                 destination_arch='arm64' if role == 'consumer' else None,
                 destination_runner_sha256='b' * 64 if role == 'consumer' else None,
                 network_isolated=role == 'consumer', namespace_commands=14 if role == 'consumer' else 0,
                 network_probe_sha256='c' * 64 if role == 'consumer' else None,
                 native_journey_sha256='d' * 64 if role == 'consumer' else None,
                 network_tools_sha256={key: 'a' * 64 for key in ['sudo', 'unshare', 'setpriv']} if role == 'consumer' else {},
                 explicit_roots=8, automatic_closure=False, destination_admission=False,
                 files_sha256={key: 'a' * 64 for key in FILES})
    return value


class EvidenceTests(unittest.TestCase):
    def test_complete_metadata_accepts_only_closed_fixed_fields(self):
        for role in STAGES:
            value = complete(role)
            self.assertEqual(safe_go_common_export_portability_contract(value, 'passed'), value)

    def test_failed_prefix_does_not_supply_a_pass(self):
        for role in STAGES:
            value = complete(role)
            value['completed'] = value['completed'][:1]
            value['fixture_sha256'] = None
            value['files_sha256'] = {}
            self.assertEqual(safe_go_common_export_portability_contract(value, 'failed'), value)
            with self.assertRaises(ValueError):
                safe_go_common_export_portability_contract(value, 'passed')

    def test_partial_wrong_version_scope_counts_and_reused_host_refuse(self):
        changes = [{'go_version': '1.27.4'}, {'role': []}, {'source_run_id': '01'}, {'namespace_commands': 13},
                   {'namespace_commands': True}, {'explicit_roots': True}, {'explicit_roots': 7},
                   {'automatic_closure': True}, {'destination_admission': True}, {'network_isolated': False},
                   {'network_tools_sha256': {}}, {'source_runner_sha256': 'b' * 64}, {'public_key_sha256': 'b' * 64},
                   {'completed': STAGES['consumer'][:-1]}, {'completed': STAGES['consumer'][::-1]},
                   {'credential': 'private-synthetic-value'}]
        changes += [{name: None} for name in HASHES]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                safe_go_common_export_portability_contract({**complete(), **change}, 'passed')

    def test_private_unknown_and_missing_originals_never_escape_safe_evidence(self):
        for name in ['admin.token', 'external-private.pem', '../root.000.zip', 'root.008.zip']:
            value = complete()
            value['files_sha256'][name] = 'a' * 64
            with self.subTest(name=name), self.assertRaises(ValueError):
                safe_go_common_export_portability_contract(value, 'passed')
        for name in FILES:
            value = complete()
            del value['files_sha256'][name]
            with self.subTest(name=name), self.assertRaises(ValueError):
                safe_go_common_export_portability_contract(value, 'passed')

    def test_producer_cannot_claim_destination_or_consumer_networks(self):
        changes = [{'destination_runner_sha256': 'b' * 64}, {'network_probe_sha256': 'b' * 64},
                   {'native_journey_sha256': 'b' * 64}, {'namespace_commands': 14}, {'network_isolated': True},
                   {'network_tools_sha256': {'sudo': 'a' * 64}}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                safe_go_common_export_portability_contract({**complete('producer'), **change}, 'passed')


if __name__ == '__main__':
    unittest.main()
