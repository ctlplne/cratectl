# SPDX-License-Identifier: BUSL-1.1
import unittest

from go_export_portability_evidence import FILES, HASHES, STAGES, safe_go_export_portability_contract


def complete(role='consumer'):
    out = {key: 'a' * 64 for key in HASHES}
    out.update(profile='hosted-export-cross-runner-v1', role=role, completed=list(STAGES[role]),
               go_version='1.27.3', source_run_id='123', source_arch='amd64',
               destination_arch='arm64' if role == 'consumer' else None,
               destination_runner_sha256='b' * 64 if role == 'consumer' else None,
               network_isolated=role == 'consumer', network_probe_sha256='c' * 64 if role == 'consumer' else None,
               network_tools_sha256={name: 'a' * 64 for name in ['sudo', 'unshare', 'setpriv']} if role == 'consumer' else {},
               files_sha256={name: 'a' * 64 for name in FILES})
    return out


class EvidenceTests(unittest.TestCase):
    def test_both_complete_profiles_accept_only_fixed_public_fields(self):
        for role in STAGES:
            value = complete(role)
            self.assertEqual(safe_go_export_portability_contract(value, 'passed'), value)

    def test_failure_can_retain_an_ordered_prefix_without_a_success(self):
        for role in STAGES:
            value = complete(role)
            value['completed'] = value['completed'][:1]
            value['fixture_sha256'] = None
            value['files_sha256'] = {}
            self.assertEqual(safe_go_export_portability_contract(value, 'failed'), value)
            with self.assertRaises(ValueError):
                safe_go_export_portability_contract(value, 'passed')

    def test_unknown_fields_wrong_versions_partial_controls_and_reused_runner_reject(self):
        mutations = [{'credential': 'private-synthetic-value'}, {'go_version': '1.27.4'},
                     {'role': 'unknown'}, {'role': []}, {'source_arch': 'arm64'}, {'destination_arch': 'amd64'},
                     {'source_run_id': 'unbounded'}, {'source_runner_sha256': 'b' * 64},
                     {'completed': STAGES['consumer'][:-1]}, {'completed': STAGES['consumer'][::-1]},
                     {'public_key_sha256': 'c' * 64}, {'fixture_sha256': None}]
        mutations.extend([{'network_isolated': False}, {'network_tools_sha256': {}}, {'network_probe_sha256': None}])
        for change in mutations:
            with self.subTest(change=change), self.assertRaises(ValueError):
                safe_go_export_portability_contract({**complete(), **change}, 'passed')
        for name in ['signer-private.pem', 'api-token', '../original.zip']:
            value = complete()
            value['files_sha256'][name] = 'c' * 64
            with self.subTest(name=name), self.assertRaises(ValueError):
                safe_go_export_portability_contract(value, 'passed')


if __name__ == '__main__':
    unittest.main()
