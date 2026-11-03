#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Exercise report collection with a real disposable Git index and private fields."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from evidence_summary import summarize

ROOT = Path(__file__).resolve().parents[2]


class EvidenceSummary(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cratectl-ci-evidence-', dir=ROOT / '.cache')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        subprocess.run(['git', 'init', '-q', '-b', 'main', str(self.root)], check=True)
        (self.root / 'evidence').mkdir()
        self.environment = {'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': 'fixture', 'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64'}

    def write(self, name, data):
        path = self.root / 'evidence' / name
        path.write_text(json.dumps(data))
        return path

    def test_same_date_tracked_overwrite_and_new_report_are_both_exported(self):
        path = self.write('rules.json', {'candidate': 'b' * 40})
        subprocess.run(['git', 'add', 'evidence/rules.json'], cwd=self.root, check=True)
        self.write('rules.json', {'source_parent': 'a' * 40, 'passed': True, 'results': [{}, {}], 'credential': 'private-synthetic-value'})
        self.write('native.json', {'candidate': 'a' * 40, 'status': 'failed', 'workflow': 'repair', 'checks': ['one'], 'failure': 'private-synthetic-value'})
        report = summarize(self.root, self.environment)
        self.assertEqual([(r['report'], r['status']) for r in report['records']], [('native.json', 'failed'), ('rules.json', 'passed')])
        self.assertEqual(report['records'][1]['cases'], 2)
        self.assertEqual(report['records'][0]['workflow'], 'repair')
        self.assertNotIn('private-synthetic-value', json.dumps(report))
        self.assertTrue(all('credential' not in record for record in report['records']))
        self.write('native.json', {'candidate': 'a' * 40, 'status': 'failed', 'workflow': 'retention', 'browser_stats': {'expected': 0, 'unexpected': 1, 'skipped': 0, 'flaky': 0}, 'failure': 'private-synthetic-value'})
        failed = summarize(self.root, self.environment)['records'][0]
        self.assertEqual(failed['workflow'], 'retention')
        self.assertEqual(failed['browser'], {'expected': 0, 'unexpected': 1, 'skipped': 0, 'flaky': 0})
        self.assertNotIn('private-synthetic-value', json.dumps(failed))

    def test_stale_candidate_and_external_symlink_do_not_become_evidence(self):
        path = self.write('stale.json', {'candidate': 'b' * 40})
        with self.assertRaises(SystemExit):
            summarize(self.root, self.environment)
        path.unlink()
        outside = self.root / 'private.json'
        outside.write_text(json.dumps({'candidate': 'a' * 40, 'credential': 'private-synthetic-value'}))
        (self.root / 'evidence/escaped.json').symlink_to(outside)
        self.assertEqual(summarize(self.root, self.environment)['records'], [])

    def test_nuget_sdk_and_fixture_evidence_is_bounded_and_complete(self):
        fixtures = {key: 'b' * 64 for key in ('dependency', 'application_1', 'application_2', 'other_application_1')}
        data = {'candidate': 'a' * 40, 'status': 'passed', 'nuget_sdk_version': '10.0.403', 'nuget_dotnet_sha256': 'c' * 64, 'nuget_fixture_sha256': fixtures, 'private_output': 'private-synthetic-value'}
        self.write('nuget.json', data)
        record = summarize(self.root, self.environment)['records'][0]
        self.assertEqual(record['nuget_sdk_version'], '10.0.403')
        self.assertEqual(record['nuget_fixture_sha256'], fixtures)
        self.assertNotIn('private-synthetic-value', json.dumps(record))
        for change in [{'nuget_sdk_version': 'private-synthetic-value'}, {'nuget_dotnet_sha256': 'private-synthetic-value'}, {'nuget_fixture_sha256': {'dependency': 'b' * 64}}, {'nuget_fixture_sha256': {**fixtures, 'credential': 'b' * 64}}]:
            self.write('nuget.json', {**data, **change})
            with self.assertRaises(SystemExit):
                summarize(self.root, self.environment)

    def test_native_failure_diagnostics_never_accept_arbitrary_output(self):
        report = {'candidate': 'a' * 40, 'status': 'failed', 'phase': 'authentication', 'client_versions': {}, 'command_diagnostics': ['registry_ping', 'permission_denied'], 'failure': 'private-synthetic-value'}
        self.write('clients.json', report)
        record = summarize(self.root, self.environment)['records'][0]
        self.assertEqual(record['command_diagnostics'], ['permission_denied', 'registry_ping'])
        self.assertNotIn('private-synthetic-value', json.dumps(record))
        for codes in [['private-synthetic-value'], ['registry_ping', 'registry_ping'], 'private-synthetic-value', [{'secret': 'private-synthetic-value'}]]:
            self.write('clients.json', {**report, 'command_diagnostics': codes})
            with self.subTest(codes=codes), self.assertRaises(SystemExit):
                summarize(self.root, self.environment)

    def test_historical_identity_is_retained_without_arbitrary_fields(self):
        self.write('baseline.json', {'candidate': 'a' * 40, 'status': 'passed', 'baseline_version': 2, 'expected_schema': 11, 'baselines': [{'schema': 2, 'source': 'b' * 40, 'binary_sha256': 'c' * 64, 'private_log': 'private-synthetic-value'}]})
        record = summarize(self.root, self.environment)['records'][0]
        self.assertEqual(record['baselines'][0]['source'], 'b' * 40)
        self.assertEqual((record['baseline_version'], record['expected_schema']), (2, 11))
        self.assertNotIn('private-synthetic-value', json.dumps(record))

    def test_current_binary_hash_and_embedded_identity_are_retained_without_extra_fields(self):
        name = '.cache/ci-build/cratectld'
        identity = {'vcs.revision': 'a' * 40, 'vcs.modified': 'false', 'GOOS': 'linux', 'GOARCH': 'amd64', 'private': 'private-synthetic-value'}
        path = self.write('native.json', {'candidate': 'a' * 40, 'status': 'passed', 'artifact_digests': {name: 'c' * 64}, 'build_identity': {name: identity}})
        artifact = summarize(self.root, self.environment)['records'][0]['artifacts'][0]
        self.assertEqual((artifact['path'], artifact['sha256']), (name, 'c' * 64))
        self.assertEqual(artifact['build']['vcs.revision'], 'a' * 40)
        self.assertNotIn('private-synthetic-value', json.dumps(artifact))
        for changed in [{'vcs.modified': 'true'}, {'GOARCH': 'arm64'}, {'vcs.revision': 'b' * 40}]:
            self.write('native.json', {'candidate': 'a' * 40, 'artifact_digests': {name: 'c' * 64}, 'build_identity': {name: {**identity, **changed}}})
            with self.subTest(changed=changed), self.assertRaises(SystemExit):
                summarize(self.root, self.environment)
        path.unlink()
        self.write('unknown.json', {'candidate': 'a' * 40, 'artifact_digests': {'.private/credential': 'c' * 64}})
        with self.assertRaises(SystemExit):
            summarize(self.root, self.environment)

    def test_client_versions_and_hashes_are_complete_and_do_not_export_arbitrary_text(self):
        versions = {'docker': '29.0.0+azure-1', 'docker_engine': '29.0.0', 'buildx': '0.29.1', 'podman': '4.9.3', 'helm': '4.3.1+gc0d08d0'}
        digests = {name: 'd' * 64 for name in ['docker', 'podman', 'helm']}
        fixtures = {key: 'e' * 64 for key in ['application_v1', 'application_v2', 'dependency', 'fallback', 'other_tenant', 'foreign_platform', 'chart_dependency_1_0_0', 'chart_dependency_1_1_0', 'chart_application_1_0_0', 'chart_other_tenant_1_0_0']}
        subject = {'repository': 'hosted', 'image': 'payload', 'reference': 'multi', 'digest': 'sha256:' + 'f' * 64, 'native_manifest_digest': 'sha256:' + 'a' * 64, 'members': [{'digest': 'sha256:' + 'b' * 64, 'size': 12}, {'digest': 'sha256:' + 'c' * 64, 'size': 20}], 'private': 'private-synthetic-value'}
        evidence = {'candidate': 'a' * 40, 'status': 'passed', 'phase': 'complete', 'client_versions': versions, 'client_binary_sha256': digests, 'client_packages': {'podman': {'version': '4.9.3+ds1-1ubuntu0.3', 'architecture': 'amd64', 'private': 'private-synthetic-value'}}, 'fixture_sha256': fixtures, 'subjects': [subject], 'private_log': 'private-synthetic-value'}
        self.write('clients.json', evidence)
        record = summarize(self.root, self.environment)['records'][0]
        self.assertEqual(record['client_versions'], versions)
        self.assertEqual(record['client_binary_sha256'], digests)
        self.assertEqual(record['subjects'][0]['digest'], subject['digest'])
        self.assertEqual(record['fixture_sha256'], fixtures)
        self.assertNotIn('private-synthetic-value', json.dumps(record))
        for changed in [{**versions, 'helm': '4.3.1+private-synthetic-value'}, {'credential': 'private-synthetic-value'}, {name: version for name, version in versions.items() if name != 'podman'}]:
            self.write('clients.json', {**evidence, 'client_versions': changed})
            with self.subTest(changed=changed), self.assertRaises(SystemExit):
                summarize(self.root, self.environment)
        for changed in [{'fixture_sha256': {}}, {'subjects': [{**subject, 'image': 'private-synthetic-value'}]}, {'phase': 'private-synthetic-value'}, {'client_packages': {'podman': {'version': '4.9.3+private-synthetic-value', 'architecture': 'amd64'}}}]:
            self.write('clients.json', {**evidence, **changed})
            with self.subTest(changed=changed), self.assertRaises(SystemExit):
                summarize(self.root, self.environment)


if __name__ == '__main__':
    unittest.main()
