#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Exercise report collection with a real disposable Git index and private fields."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from evidence_summary import summarize
from test_gradle_evidence import complete_contract
from test_ivy_evidence import complete_contract as complete_ivy_contract, metadata_contract, snapshot_contract, cache_contract
from test_sbt_evidence import complete_contract as complete_sbt_contract, snapshot_contract as sbt_snapshot_contract
from test_maven_evidence import complete_contract as complete_maven_cache_contract

ROOT = Path(__file__).resolve().parents[2]


class EvidenceSummary(unittest.TestCase):
    def test_maven_warm_cache_requires_exact_safe_before_after_bytes(self):
        contract=complete_maven_cache_contract()
        report={'candidate':'a'*40,'status':'passed','maven_cache_contract':contract,
                'commands':[{'output':'private-synthetic-value'}],'failure':'private-synthetic-value'}
        self.write('maven-cache.json',report)
        exported=summarize(self.root,self.environment)['records'][0]
        self.assertEqual(exported['maven_cache_contract'],contract)
        self.assertNotIn('private-synthetic-value',json.dumps(exported))
        self.write('maven-cache.json',{**report,'maven_cache_contract':{**contract,'cache_reused':False}})
        with self.assertRaises(SystemExit):summarize(self.root,self.environment)

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
        self.write('native.json', {'candidate': 'a' * 40, 'status': 'passed', 'workflow': 'nuget', 'browser_stats': {'expected': 1, 'unexpected': 0, 'skipped': 0, 'flaky': 0}, 'private_output': 'private-synthetic-value'})
        nuget = summarize(self.root, self.environment)['records'][0]
        self.assertEqual(nuget['workflow'], 'nuget')
        self.assertEqual(nuget['browser'], {'expected': 1, 'unexpected': 0, 'skipped': 0, 'flaky': 0})
        self.assertNotIn('private-synthetic-value', json.dumps(nuget))

    def test_stale_candidate_and_external_symlink_do_not_become_evidence(self):
        path = self.write('stale.json', {'candidate': 'b' * 40})
        with self.assertRaises(SystemExit):
            summarize(self.root, self.environment)
        path.unlink()
        outside = self.root / 'private.json'
        outside.write_text(json.dumps({'candidate': 'a' * 40, 'credential': 'private-synthetic-value'}))
        (self.root / 'evidence/escaped.json').symlink_to(outside)
        self.assertEqual(summarize(self.root, self.environment)['records'], [])

    def test_gradle_export_keeps_exact_safe_fields_and_rejects_partial_pass(self):
        report={'candidate':'a'*40,'status':'passed','gradle_contract':complete_contract(),'commands':[{'output':'private-synthetic-value'}],'failure':'private-synthetic-value'}
        self.write('gradle.json',report)
        record=summarize(self.root,self.environment)['records'][0]
        self.assertEqual(record['gradle_contract'],complete_contract())
        self.assertNotIn('private-synthetic-value',json.dumps(record))
        self.write('gradle.json',{**report,'gradle_contract':{**complete_contract(),'phase':'snapshots'}})
        with self.assertRaises(SystemExit):summarize(self.root,self.environment)

    def test_ivy_export_binds_all_owned_bytes_and_rejects_partial_pass(self):
        report={'candidate':'a'*40,'status':'passed','ivy_contract':complete_ivy_contract(),'commands':[{'output':'private-synthetic-value'}]}
        self.write('ivy.json',report)
        record=summarize(self.root,self.environment)['records'][0]
        self.assertEqual(record['ivy_contract'],complete_ivy_contract())
        self.assertNotIn('private-synthetic-value',json.dumps(record))
        self.write('ivy.json',{**report,'ivy_contract':{**complete_ivy_contract(),'wire_sha256':{}}})
        with self.assertRaises(SystemExit):summarize(self.root,self.environment)

    def test_ivy_snapshot_export_requires_all_original_and_new_bytes_without_private_output(self):
        contract=snapshot_contract()
        report={'candidate':'a'*40,'status':'passed','ivy_contract':contract,'commands':[{'output':'private-synthetic-value'}]}
        self.write('ivy-snapshot.json',report)
        record=summarize(self.root,self.environment)['records'][0]
        self.assertEqual(record['ivy_contract'],contract)
        self.assertEqual(len(record['ivy_contract']['wire_sha256']),34)
        self.assertNotIn('private-synthetic-value',json.dumps(record))
        self.write('ivy-snapshot.json',{**report,'ivy_contract':{**contract,'snapshot_cases_completed':contract['snapshot_cases_completed'][:-1]}})
        with self.assertRaises(SystemExit):summarize(self.root,self.environment)

    def test_ivy_warm_cache_export_requires_every_retained_byte_without_private_output(self):
        contract=cache_contract()
        report={'candidate':'a'*40,'status':'passed','ivy_contract':contract,'commands':[{'output':'private-synthetic-value'}]}
        self.write('ivy-cache.json',report)
        record=summarize(self.root,self.environment)['records'][0]
        self.assertEqual(record['ivy_contract'],contract)
        self.assertNotIn('private-synthetic-value',json.dumps(record))
        stale={**contract['cache_sha256'],'snapshot_second_jar':contract['cache_sha256']['snapshot_first_jar']}
        self.write('ivy-cache.json',{**report,'ivy_contract':{**contract,'cache_sha256':stale}})
        with self.assertRaises(SystemExit):summarize(self.root,self.environment)

    def test_ivy_metadata_export_requires_parent_and_classified_wire_bytes(self):
        contract=metadata_contract()
        report={'candidate':'a'*40,'status':'passed','ivy_contract':contract,'commands':[{'output':'private-synthetic-value'}]}
        self.write('ivy-metadata.json',report)
        record=summarize(self.root,self.environment)['records'][0]
        self.assertEqual(record['ivy_contract'],contract)
        self.assertNotIn('private-synthetic-value',json.dumps(record))
        for key in ['parent_pom','metadata_app_tests_jar']:
            wire=dict(contract['wire_sha256']);wire.pop(key)
            self.write('ivy-metadata.json',{**report,'ivy_contract':{**contract,'wire_sha256':wire}})
            with self.subTest(key=key),self.assertRaises(SystemExit):summarize(self.root,self.environment)

    def test_go_module_export_requires_every_native_stage_and_exact_byte_binding(self):
        from test_go_module_evidence import complete_contract
        contract=complete_contract()
        report={'candidate':'a'*40,'status':'passed','go_module_contract':contract,'commands':[{'output':'private-synthetic-value'}]}
        self.write('go-module.json',report)
        record=summarize(self.root,self.environment)['records'][0]
        self.assertEqual(record['go_module_contract'],contract)
        self.assertNotIn('private-synthetic-value',json.dumps(record))
        self.write('go-module.json',{**report,'go_module_contract':{**contract,'completed':contract['completed'][:-1]}})
        with self.assertRaises(SystemExit):summarize(self.root,self.environment)

    def test_go_group_export_preserves_all_original_and_group_identities(self):
        from test_go_module_evidence import complete_group_contract
        contract=complete_group_contract()
        report={'candidate':'a'*40,'status':'passed','go_module_contract':contract,'commands':[{'output':'private-synthetic-value'}]}
        self.write('go-group.json',report)
        record=summarize(self.root,self.environment)['records'][0]
        self.assertEqual(record['go_module_contract'],contract)
        self.assertNotIn('private-synthetic-value',json.dumps(record))
        self.write('go-group.json',{**report,'go_module_contract':{**contract,'completed':contract['completed'][:-1]}})
        with self.assertRaises(SystemExit):summarize(self.root,self.environment)

    def test_sbt_export_keeps_bounded_bootstrap_identity_without_private_observations(self):
        contract=complete_sbt_contract()
        report={'candidate':'a'*40,'status':'passed','sbt_contract':contract,'commands':[{'output':'private-synthetic-value'}]}
        self.write('sbt.json',report)
        record=summarize(self.root,self.environment)['records'][0]
        self.assertEqual(record['sbt_contract'],contract)
        self.assertNotIn('private-synthetic-value',json.dumps(record))
        self.write('sbt.json',{**report,'sbt_contract':{**contract,'bootstrap_boot':None}})
        with self.assertRaises(SystemExit):summarize(self.root,self.environment)

    def test_sbt_snapshot_export_requires_every_case_and_original_representation(self):
        contract=sbt_snapshot_contract()
        report={'candidate':'a'*40,'status':'passed','sbt_contract':contract,'commands':[{'output':'private-synthetic-value'}]}
        self.write('sbt-snapshot.json',report)
        record=summarize(self.root,self.environment)['records'][0]
        self.assertEqual(record['sbt_contract'],contract)
        self.assertEqual(len(record['sbt_contract']['wire_sha256']),18)
        self.assertNotIn('private-synthetic-value',json.dumps(record))
        self.write('sbt-snapshot.json',{**report,'sbt_contract':{**contract,'snapshot_cases_completed':contract['snapshot_cases_completed'][:-1]}})
        with self.assertRaises(SystemExit):summarize(self.root,self.environment)

    def test_nuget_sdk_and_fixture_evidence_is_bounded_and_complete(self):
        fixtures = {key: 'b' * 64 for key in ('dependency', 'application_1', 'application_2', 'other_application_1')}
        data = {'candidate': 'a' * 40, 'status': 'passed', 'nuget_sdk_version': '10.0.403', 'nuget_dotnet_sha256': 'c' * 64, 'nuget_fixture_sha256': fixtures, 'private_output': 'private-synthetic-value', 'nuget_protocol_probe_sha256': 'd' * 64, 'nuget_protocol_library_sha256': 'e' * 64, 'nuget_protocol_library_version': '7.9.0.0'}
        self.write('nuget.json', data)
        record = summarize(self.root, self.environment)['records'][0]
        self.assertEqual(record['nuget_sdk_version'], '10.0.403')
        self.assertEqual(record['nuget_fixture_sha256'], fixtures)
        self.assertEqual(record['nuget_protocol_probe_sha256'], 'd' * 64)
        self.assertEqual(record['nuget_protocol_library_sha256'], 'e' * 64)
        self.assertEqual(record['nuget_protocol_library_version'], '7.9.0.0')
        self.assertNotIn('private-synthetic-value', json.dumps(record))
        for change in [{'nuget_sdk_version': 'private-synthetic-value'}, {'nuget_dotnet_sha256': 'private-synthetic-value'}, {'nuget_fixture_sha256': {'dependency': 'b' * 64}}, {'nuget_fixture_sha256': {**fixtures, 'credential': 'b' * 64}}, {'nuget_protocol_probe_sha256': 'private-synthetic-value'}, {'nuget_protocol_library_sha256': 'private-synthetic-value'}, {'nuget_protocol_library_version': 'private-synthetic-value'}]:
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

    def test_nuget_http_metadata_evidence_never_exports_arbitrary_client_output(self):
        fixtures = {key: 'b' * 64 for key in ('dependency', 'application_1', 'application_2', 'other_application_1')}
        contract = {'cases':44, 'fixture_sha256':'d'*64, 'observations_sha256':'e'*64, 'mismatch_indexes':[], 'phase':'restarted'}
        report = {'candidate':'a'*40, 'status':'passed', 'nuget_sdk_version':'10.0.403', 'nuget_dotnet_sha256':'c'*64, 'nuget_fixture_sha256':fixtures, 'nuget_metadata_contract':contract, 'nuget_metadata_mismatches':['private-synthetic-value']}
        self.write('native.json',report)
        safe=summarize(self.root,self.environment)['records'][0]
        self.assertEqual(safe['nuget_metadata_contract'],contract)
        self.assertNotIn('private-synthetic-value',json.dumps(safe))
        for change in [{'cases':65},{'cases':True},{'phase':'private-synthetic-value'},{'phase':'published'},{'fixture_sha256':'private-synthetic-value'},{'observations_sha256':'private-synthetic-value'},{'mismatch_indexes':[1]},{'mismatch_indexes':[44]},{'mismatch_indexes':[True]},{'output':'private-synthetic-value'}]:
            with self.subTest(change=change),self.assertRaises(SystemExit):
                self.write('native.json',{**report,'nuget_metadata_contract':{**contract,**change}})
                summarize(self.root,self.environment)
        self.write('native.json',{**report,'status':'failed','nuget_metadata_contract':{**contract,'phase':'published','mismatch_indexes':[1]}})
        self.assertEqual(summarize(self.root,self.environment)['records'][0]['nuget_metadata_contract']['mismatch_indexes'],[1])
        failed={**report,'status':'failed','nuget_metadata_contract':{**contract,'phase':'published','mismatch_indexes':[1]},'nuget_metadata_diagnostics':[{'index':1,'failed':False,'paths':['groups[0].framework','groups[0].packages._length','groups[0].packages[1].min_metadata']}]}
        self.write('native.json',failed)
        self.assertEqual(summarize(self.root,self.environment)['records'][0]['nuget_metadata_diagnostics'],failed['nuget_metadata_diagnostics'])
        for diagnostics in [[{'index':2,'failed':True,'paths':[]}],[{'index':True,'failed':True,'paths':[]}],[{'index':1,'failed':False,'paths':['private-synthetic-value']}],[{'index':1,'failed':False,'paths':[],'value':'private-synthetic-value'}]]:
            with self.subTest(diagnostics=diagnostics),self.assertRaises(SystemExit):
                self.write('native.json',{**failed,'nuget_metadata_diagnostics':diagnostics})
                summarize(self.root,self.environment)

    def test_historical_identity_is_retained_without_arbitrary_fields(self):
        self.write('baseline.json', {'candidate': 'a' * 40, 'status': 'passed', 'baseline_version': 2, 'expected_schema': 11, 'baselines': [{'schema': 2, 'source': 'b' * 40, 'binary_sha256': 'c' * 64, 'private_log': 'private-synthetic-value'}]})
        record = summarize(self.root, self.environment)['records'][0]
        self.assertEqual(record['baselines'][0]['source'], 'b' * 40)
        self.assertEqual((record['baseline_version'], record['expected_schema']), (2, 11))
        self.assertNotIn('private-synthetic-value', json.dumps(record))

    def test_historical_inventory_includes_schema_twelve_and_remains_bounded(self):
        baselines = [{'schema': schema, 'source': format(n, '040x'), 'binary_sha256': format(n, '064x')} for n, schema in enumerate([None, *range(2, 13)], start=1)]
        report = {'candidate': 'a' * 40, 'status': 'passed', 'baselines': baselines}
        self.write('historical.json', report)
        self.assertEqual(len(summarize(self.root, self.environment)['records'][0]['baselines']), 12)
        for invalid in [baselines + [baselines[-1]], [{**baselines[-1], 'schema': 13}]]:
            self.write('historical.json', {**report, 'baselines': invalid})
            with self.assertRaises(SystemExit): summarize(self.root, self.environment)

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
