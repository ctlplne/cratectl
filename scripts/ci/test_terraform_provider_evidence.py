# SPDX-License-Identifier: BUSL-1.1
"""Reject cross-run, source and stock-client substitutions in provider summaries."""
import copy
import hashlib
import unittest

from campaign_contract import jobs
from campaign_reports import validate_custom
from campaign_transport import EvidenceError
from terraform_provider_evidence import ARCHIVE_PINS, BASE_CHECKS, CLIENTS, CLIENT_CHECKS, SOURCE_PATHS, validate


def complete():
    return {
        'schema': 1, 'profile': 'cratectl-native-terraform-provider-v1', 'candidate': 'b' * 40,
        'run_id': '31', 'runner_os': 'Linux', 'runner_arch': 'ARM64', 'source_dirty': False, 'status': 'passed',
        'goal_complete': False, 'broad_readiness': False, 'postgres': 'postgres (PostgreSQL) 16.15 (Ubuntu 16.15)',
        'npm': '10.9.9', 'checks': list(BASE_CHECKS), 'client_archives': dict(ARCHIVE_PINS['arm64']),
        'source_sha256': dict.fromkeys(SOURCE_PATHS, hashlib.sha256(b'owned-source').hexdigest()),
        'binary_sha256': {'cratectl': 'c' * 64, 'cratectld': 'd' * 64},
        'provider_sha256': 'e' * 64, 'archive_sha256': 'a' * 64,
        'clients': [{'client': name, 'version': version, 'client_sha256': 'a' * 64, 'checks': list(CLIENT_CHECKS)}
                    for name, version in CLIENTS.items()],
    }


class TerraformProviderEvidence(unittest.TestCase):
    def test_complete_exact_report_uses_both_clients_and_all_checks(self):
        report = complete()
        self.assertEqual(validate(report), report)
        spec = jobs('terraform-provider')['Terraform and OpenTofu with real PostgreSQL (arm64)']
        self.assertEqual(validate_custom(report, report['candidate'], 31, spec, lambda _: b'owned-source'),
                         {'records': 1, 'checks': 38})
        with self.assertRaisesRegex(EvidenceError, 'terraform_provider_source_identity'):
            validate_custom(report, report['candidate'], 31, spec, lambda _: b'different-source')
        with self.assertRaises(EvidenceError):
            validate_custom(report, report['candidate'], 32, spec, lambda _: b'owned-source')

    def test_wrong_architecture_versions_and_incomplete_journeys_refuse(self):
        for alter in (
            lambda report: report.update(runner_arch='X64'),
            lambda report: report.update(goal_complete=True),
            lambda report: report.update(postgres='postgres (PostgreSQL) 16.16'),
            lambda report: report['clients'].pop(),
            lambda report: report['clients'].reverse(),
            lambda report: report['clients'][0].update(version='1.17.1'),
            lambda report: report['clients'][0]['checks'].pop(),
            lambda report: report['checks'].pop(),
            lambda report: report['source_sha256'].pop(SOURCE_PATHS[0]),
        ):
            report = copy.deepcopy(complete())
            alter(report)
            with self.assertRaises(ValueError):
                validate(report)


if __name__ == '__main__':
    unittest.main()
