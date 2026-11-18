#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned report mutations; these tests make no Windows runtime claim."""
import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

from campaign_contract import COMPATIBLE_FILES, jobs
from campaign_reports import validate_custom
from campaign_transport import EvidenceError
from windows_cli_evidence import SOURCES, TESTS, safe_windows_cli_contract

ROOT = Path(__file__).resolve().parents[2]


def complete(candidate='a' * 40, run_id='12', arch='X64', source=lambda _: b'owned-fixture'):
    identity = {'GOOS': 'windows', 'GOARCH': {'X64': 'amd64', 'ARM64': 'arm64'}[arch],
                'vcs.revision': candidate, 'vcs.modified': 'false'}
    return {'schema': 1, 'profile': 'cratectl.windows.private-configuration.v1', 'candidate': candidate,
            'run_id': run_id, 'runner_os': 'Windows', 'runner_arch': arch, 'status': 'passed', 'go_version': '1.27.3',
            'binary_sha256': dict(zip(('cli', 'driver', 'go'), (c * 64 for c in 'bcd'))),
            'build_identity': {'cli': dict(identity), 'driver': dict(identity)},
            'source_sha256': {p: hashlib.sha256(source(p)).hexdigest() for p in SOURCES},
            'tests': copy.deepcopy(TESTS), 'events_sha256': {'driver': 'e' * 64, 'configuration': 'f' * 64},
            'managed_commands': 5, 'all_owned_jobs_empty': True, 'management_response_standin': True,
            'windows_server_qualified': False, 'offline_collection_qualified': False,
            'goal_complete': False, 'broad_readiness': False}


class WindowsEvidence(unittest.TestCase):
    def test_workflow_uploads_only_named_safe_and_encrypted_files_from_hidden_cache(self):
        workflow = (ROOT / '.github/workflows/windows-cli.yml').read_text()
        uploads = re.findall(r'^      - uses: actions/upload-artifact@[^\n]+\n(.*?)(?=^      - |\Z)', workflow, re.M | re.S)
        self.assertEqual(len(uploads), 2)
        for upload, expected in zip(uploads, [
            ['.cache/ci-windows-cli-summary.json'],
            ['.cache/ci-windows-diagnostics.cms', '.cache/ci-windows-diagnostics.json'],
        ]):
            self.assertRegex(upload, r'(?m)^          include-hidden-files: true$')
            path = re.search(r'^          path: (.*(?:\n +\.cache/[^\n]+)*)', upload, re.M).group(1)
            paths = [line.strip() for line in path.splitlines() if line.strip() != '|']
            self.assertEqual(paths, expected)

    def test_both_native_platforms_bind_every_candidate_source_without_executing_artifacts(self):
        for spec in jobs('windows').values():
            source = lambda p: ('owned source: ' + p).encode()
            report = complete(arch=spec['platform'][2], source=source)
            self.assertEqual(safe_windows_cli_contract(report), report)
            self.assertEqual(validate_custom(report, report['candidate'], 12, spec, source), {'checks': 14, 'records': 1})
            for path in SOURCES:
                changed = copy.deepcopy(report)
                changed['source_sha256'][path] = '0' * 64
                with self.subTest(path=path), self.assertRaisesRegex(EvidenceError, 'windows_source_identity'):
                    validate_custom(changed, report['candidate'], 12, spec, source)

    def test_private_unknown_partial_reordered_or_overclaimed_fields_are_refused(self):
        mutations = [
            lambda r: r.update(private_path='owned-private-synthetic'),
            lambda r: r.update(schema=True), lambda r: r.update(status='skipped'),
            lambda r: r.update(run_id='012'), lambda r: r.update(managed_commands=True),
            lambda r: r.update(managed_commands=4), lambda r: r.update(all_owned_jobs_empty=False),
            lambda r: r.update(management_response_standin=False),
            lambda r: r['tests']['configuration'].pop(), lambda r: r['tests']['driver'].reverse(),
            lambda r: r['tests']['driver'].append('TestOwnedProcessFixture'),
            lambda r: r['source_sha256'].pop('scripts/ci/windowscli/process_windows.go'),
            lambda r: r['source_sha256'].update(unreviewed='e' * 64),
            lambda r: r['binary_sha256'].pop('go'), lambda r: r['events_sha256'].update(configuration='bad'),
            lambda r: r['build_identity']['driver'].update(GOARCH='arm64'),
            lambda r: r['build_identity']['cli'].update(**{'vcs.modified': 'true'}),
            lambda r: r['build_identity']['cli'].update(**{'vcs.revision': '0' * 40}),
        ]
        for key in ['windows_server_qualified', 'offline_collection_qualified', 'goal_complete', 'broad_readiness']:
            mutations.append(lambda r, key=key: r.update({key: True}))
        for index, mutate in enumerate(mutations):
            changed = complete()
            mutate(changed)
            with self.subTest(index=index), self.assertRaises(ValueError):
                safe_windows_cli_contract(changed)

    def test_campaign_rejects_cross_platform_source_and_run_substitution(self):
        report = complete()
        spec = jobs('windows')['Native Windows private configuration (amd64)']
        for changed in [{'runner_arch': 'ARM64'}, {'runner_os': 'Linux'}, {'candidate': '0' * 40}, {'run_id': '13'}]:
            with self.subTest(changed=changed), self.assertRaises(EvidenceError):
                validate_custom({**report, **changed}, report['candidate'], 12, spec, lambda _: b'owned-fixture')

    def test_closed_inventory_matches_native_driver_and_real_functions(self):
        main = (ROOT / 'scripts/ci/windowscli/main.go').read_text()
        section = re.search(r'var sourcePaths = \[\]string\{(.*?)\n\}', main, re.S).group(1)
        self.assertEqual(set(re.findall(r'"([^"]+)"', section)), SOURCES)
        events = (ROOT / 'scripts/ci/windowscli/events.go').read_text()
        for group, variable in [('configuration', 'configurationTests'), ('driver', 'driverTests')]:
            section = re.search(r'var ' + variable + r' = \[\]string\{(.*?)\n\}', events, re.S).group(1)
            self.assertEqual(sorted(re.findall(r'"([^"]+)"', section)), TESTS[group])
        bodies = '\n'.join((ROOT / p).read_text() for p in SOURCES if p.endswith('_test.go'))
        functions = re.findall(r'^func (Test\w+)\(', bodies, re.M)
        for name in sum(TESTS.values(), []):
            self.assertEqual(functions.count(name), 1, name)
        self.assertEqual(len(COMPATIBLE_FILES), 22)
        self.assertIn('scripts/ci/windows_cli_evidence.py', COMPATIBLE_FILES)
        self.assertIn('.github/workflows/windows-cli.yml', COMPATIBLE_FILES)
        self.assertEqual(len(sum(TESTS.values(), [])), 14)
        self.assertNotIn('owned-private-synthetic', json.dumps(safe_windows_cli_contract(complete())))


if __name__ == '__main__':
    unittest.main()
