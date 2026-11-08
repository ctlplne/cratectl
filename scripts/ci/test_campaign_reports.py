#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Retained public report fixtures and owned mutations, without native execution."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from campaign_contract import WORKFLOWS, jobs
from campaign_reports import validate_custom, validate_summary
from campaign_transport import EvidenceError
from test_go_common_export_portability_evidence import complete as complete_common_contract
from test_go_requirement_export_portability_evidence import complete as complete_requirement_contract

ROOT = Path(__file__).resolve().parents[2]
SPECS = {spec['artifact']: spec for family in WORKFLOWS.values() for spec in jobs(family).values() if spec['artifact']}


class CampaignReports(unittest.TestCase):
    def requirement_pair(self, role):
        summary, source = self.common_pair(role)
        code_hash = hashlib.sha256(source('owned')).hexdigest()
        requirement = copy.deepcopy(summary['records'][1])
        del requirement['go_common_export_portability_contract']
        contract = complete_requirement_contract(role)
        contract['source_run_id'] = str(summary['run_id'])
        for key in ['script_sha256', 'fixture_source_sha256', 'capsule_source_sha256', 'graph_fixture_source_sha256',
                    'native_helper_sha256', 'probe_helper_sha256', 'process_helper_sha256', 'decoder_sha256', 'reader_source_sha256']:
            contract[key] = code_hash
        requirement.update(report='owned-requirement-portability.json', raw_report_sha256='f' * 64,
                           checks=4 if role == 'producer' else 14, go_requirement_export_portability_contract=contract)
        summary['records'].append(requirement)
        source.paths = set(source.paths) | {'scripts/conformance_go_requirement_export_portable.py'}
        return summary, source

    def test_requirement_profile_keeps_all_three_separate_source_bound_reports(self):
        for role in ['producer', 'consumer']:
            summary, source = self.requirement_pair(role)
            spec = SPECS['ci-summary-export-portability-' + role]
            counts, contracts = validate_summary(summary, summary['candidate'], int(summary['run_id']), spec, self.baselines, source)
            self.assertEqual(counts['records'], 3)
            self.assertEqual(len(contracts), 3)
            self.assertEqual(counts['checks'], 11 if role == 'producer' else 41)
            for index in range(3):
                changed = copy.deepcopy(summary)
                del changed['records'][index]
                with self.subTest(role=role, missing=index), self.assertRaisesRegex(EvidenceError, 'requirement_profile_report_inventory'):
                    validate_summary(changed, changed['candidate'], int(changed['run_id']), spec, self.baselines, source)

    def test_requirement_profile_binds_each_source_dependency_and_rejects_collapsed_record(self):
        summary, source = self.requirement_pair('producer')
        spec = SPECS['ci-summary-export-portability-producer']
        for key in ['probe_helper_sha256', 'reader_source_sha256', 'capsule_source_sha256', 'graph_fixture_source_sha256']:
            changed = copy.deepcopy(summary)
            changed['records'][2]['go_requirement_export_portability_contract'][key] = '0' * 64
            with self.subTest(key=key), self.assertRaisesRegex(EvidenceError, 'requirement_portable_source_identity'):
                validate_summary(changed, changed['candidate'], int(changed['run_id']), spec, self.baselines, source)
        changed = copy.deepcopy(summary)
        changed['records'][1]['go_requirement_export_portability_contract'] = changed['records'][2].pop('go_requirement_export_portability_contract')
        with self.assertRaisesRegex(EvidenceError, 'requirement_profile_report_inventory'):
            validate_summary(changed, changed['candidate'], int(changed['run_id']), spec, self.baselines, source)

    def common_pair(self, role='producer'):
        summary = self.report('ci-summary-export-portability-' + role)
        code = b'owned frozen source data, never executed'
        code_hash = hashlib.sha256(code).hexdigest()
        old = summary['records'][0]
        old['go_export_portability_contract']['script_sha256'] = code_hash
        old['go_export_portability_contract']['fixture_source_sha256'] = code_hash
        common = copy.deepcopy(old)
        del common['go_export_portability_contract']
        contract = complete_common_contract(role)
        contract['source_run_id'] = str(summary['run_id'])
        for key in ['script_sha256', 'fixture_source_sha256', 'capsule_source_sha256', 'graph_fixture_source_sha256',
                    'native_helper_sha256', 'process_helper_sha256', 'decoder_sha256']:
            contract[key] = code_hash
        common.update(report='owned-common-portability.json', raw_report_sha256='e' * 64,
                      checks=4 if role == 'producer' else 14, go_common_export_portability_contract=contract)
        summary['records'].append(common)

        class FrozenSource:
            paths = {'scripts/conformance_go_common_export_portable.py'}

            def __call__(self, _):
                return code

        return summary, FrozenSource()

    def test_current_portability_requires_both_original_and_common_source_bound_records(self):
        for role in ['producer', 'consumer']:
            summary, source = self.common_pair(role)
            name = 'ci-summary-export-portability-' + role
            counts, contracts = validate_summary(summary, summary['candidate'], int(summary['run_id']), SPECS[name], self.baselines, source)
            self.assertEqual(counts['records'], 2)
            self.assertEqual(len(contracts), 2)
            for index in range(2):
                changed = copy.deepcopy(summary)
                del changed['records'][index]
                with self.subTest(role=role, missing=index), self.assertRaisesRegex(EvidenceError, 'common_profile_report_inventory'):
                    validate_summary(changed, changed['candidate'], int(changed['run_id']), SPECS[name], self.baselines, source)

    def test_common_code_identity_and_separate_record_cannot_be_substituted(self):
        summary, source = self.common_pair()
        name = 'ci-summary-export-portability-producer'
        bad = copy.deepcopy(summary)
        bad['records'][1]['go_common_export_portability_contract']['process_helper_sha256'] = '0' * 64
        with self.assertRaisesRegex(EvidenceError, 'common_portable_source_identity'):
            validate_summary(bad, bad['candidate'], int(bad['run_id']), SPECS[name], self.baselines, source)
        bad = copy.deepcopy(summary)
        bad['records'][0]['go_common_export_portability_contract'] = bad['records'][1].pop('go_common_export_portability_contract')
        with self.assertRaisesRegex(EvidenceError, 'common_profile_report_inventory'):
            validate_summary(bad, bad['candidate'], int(bad['run_id']), SPECS[name], self.baselines, source)

    def setUp(self):
        self.baselines = json.loads((ROOT / 'scripts/ci/testdata/schema16-historical-baselines.json').read_text())['baselines']

    def report(self, name):
        return json.loads((ROOT / 'evidence/2026-11-07/github-4956197' / (name + '.json')).read_text())

    def validate(self, name, report):
        return validate_summary(report, report['candidate'], int(report['run_id']), SPECS[name], self.baselines)

    def test_every_retained_original_safe_report_profile_is_understood(self):
        paths = list((ROOT / 'evidence/2026-11-07/github-4956197').glob('*.json'))
        self.assertEqual(len(paths), 19)
        records = 0
        for path in paths:
            with self.subTest(profile=path.stem):
                report = json.loads(path.read_text())
                summary, _ = self.validate(path.stem, report)
                records += summary['records']
                self.assertNotIn('candidate', summary)
        self.assertEqual(records, 72)

    def test_new_schema17_contract_refuses_old15_baseline_campaign(self):
        current = json.loads((ROOT / 'docs/qualification/upgrade-baselines.json').read_text())['baselines'][:-1]
        self.assertEqual({row['schema'] for row in current}, {None, *range(2, 17)})
        original = self.report('ci-summary-upgrades-amd64')
        with self.assertRaisesRegex(EvidenceError, 'historical_baselines'):
            validate_summary(original, original['candidate'], int(original['run_id']), SPECS['ci-summary-upgrades-amd64'], current)

    def test_schema18_requires_actual17_historical_binary_and_upgrade_report(self):
        current = json.loads((ROOT / 'docs/qualification/upgrade-baselines.json').read_text())['baselines']
        self.assertEqual([row['schema'] for row in current], [None, *range(2, 18)])
        original = json.loads((ROOT / 'evidence/2026-11-07/github-bb6f728/ci-summary-upgrades-amd64.json').read_bytes())
        with self.assertRaisesRegex(EvidenceError, 'historical_baselines'):
            validate_summary(original, original['candidate'], int(original['run_id']), SPECS['ci-summary-upgrades-amd64'], current)

    def test_metadata_empty_partial_and_unreviewed_record_never_pass(self):
        original = self.report('ci-summary-go-module-amd64')
        for kind in ['source', 'platform', 'empty', 'unknown', 'no-counts', 'dirty', 'binary', 'partial-contract', 'checks']:
            with self.subTest(kind=kind):
                report = copy.deepcopy(original)
                record = report['records'][0]
                if kind == 'source':
                    report['candidate'] = '0' * 40
                elif kind == 'platform':
                    report['runner_arch'] = 'ARM64'
                elif kind == 'empty':
                    report['records'] = []
                elif kind == 'unknown':
                    record['private_context'] = 'private-synthetic'
                elif kind == 'no-counts':
                    record['checks'] = record['cases'] = None
                elif kind == 'dirty':
                    record['source_dirty'] = True
                elif kind == 'binary':
                    record['artifacts'][0]['build']['vcs.modified'] = 'true'
                elif kind == 'partial-contract':
                    record['go_module_contract']['completed'].pop()
                elif kind == 'checks':
                    record['checks'] -= 1
                with self.assertRaises(EvidenceError):
                    validate_summary(report, original['candidate'], int(original['run_id']), SPECS['ci-summary-go-module-amd64'], self.baselines)

    def test_runtime_reports_require_both_candidate_binaries_and_one_identity_per_job(self):
        for name in ['ci-summary-go-module-amd64', 'ci-summary-amd64', 'ci-summary-export-portability-consumer', 'ci-summary-upgrades-amd64']:
            original = self.report(name)
            index = next(n for n, r in enumerate(original['records']) if r.get('artifacts'))
            for mutation in ['missing', 'empty', 'one']:
                report = copy.deepcopy(original)
                record = report['records'][index]
                if mutation == 'missing':
                    record.pop('artifacts')
                    record['source_dirty'] = record['build_source_matches_candidate'] = None
                elif mutation == 'empty':
                    record['artifacts'] = []
                else:
                    record['artifacts'] = [a for a in record['artifacts'] if a['path'] != '.cache/ci-build/cratectl']
                with self.subTest(profile=name, mutation=mutation), self.assertRaises(EvidenceError):
                    self.validate(name, report)
        report = self.report('ci-summary-amd64')
        report['records'][-1]['artifacts'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(EvidenceError, 'candidate_binary_identity_changed'):
            self.validate('ci-summary-amd64', report)

    def test_historical_browser_and_native_report_inventories_are_complete(self):
        pinned = {row['binary'] for row in self.baselines}
        for name, mutation in [
            ('ci-summary-amd64', lambda r: r['records'].pop()),
            ('ci-summary-amd64', lambda r: next(x for x in r['records'] if 'browser' in x)['browser'].update(skipped=1)),
            ('ci-summary-upgrades-amd64', lambda r: next(x for x in r['records'] if 'baselines' in x)['baselines'].pop()),
            ('ci-summary-upgrades-amd64', lambda r: next(x for x in r['records'] if x.get('baseline_version') == 15).update(checks=95)),
            ('ci-summary-upgrades-amd64', lambda r: next(a for x in r['records'] if x.get('baseline_version') == 15 for a in x['artifacts'] if a['path'] in pinned).update(sha256='0' * 64)),
            ('ci-summary-export-portability-consumer', lambda r: r['records'][0]['go_export_portability_contract'].update(network_isolated=False)),
        ]:
            with self.subTest(name=name):
                report = self.report(name)
                mutation(report)
                with self.assertRaises(EvidenceError):
                    self.validate(name, report)

    def test_source_fixture_identity_is_checked_separately_from_internal_hash_maps(self):
        report = self.report('ci-summary-go-module-amd64')
        name = 'ci-summary-go-module-amd64'
        source = lambda _: (ROOT / 'scripts/conformance_go.py').read_bytes()
        report['records'][0]['go_module_contract']['fixture_source_sha256'] = '0' * 64
        with self.assertRaisesRegex(EvidenceError, 'go_fixture_source_identity'):
            validate_summary(report, report['candidate'], int(report['run_id']), SPECS[name], self.baselines, source)
        report['records'][0]['go_module_contract']['fixture_source_sha256'] = hashlib.sha256(source('')).hexdigest()
        validate_summary(report, report['candidate'], int(report['run_id']), SPECS[name], self.baselines, source)
        contract = report['records'][0]['go_module_contract']
        old = contract['publisher_sha256']['application_1_mod']
        for key in ['publisher_sha256', 'reference_sha256', 'wire_sha256', 'cached_sha256']:
            contract[key] = {k: ('f' * 64 if value == old else value) for k, value in contract[key].items()}
        with self.assertRaisesRegex(EvidenceError, 'go_publisher_fixture_identity'):
            validate_summary(report, report['candidate'], int(report['run_id']), SPECS[name], self.baselines, source)

    def test_custom_library_and_strict_controls_require_complete_clean_results(self):
        path = ROOT / 'evidence/2026-11-07/github-fbe3bf9-final/ci-summary-nuget-version-arm64.json'
        library = json.loads(path.read_text())
        spec = SPECS['ci-summary-nuget-version-arm64']
        self.assertEqual(validate_custom(library, library['candidate'], int(library['run_id']), spec, lambda _: b''), {'checks': 37, 'records': 1})
        library['mismatch_indexes'] = [1]
        with self.assertRaises(EvidenceError):
            validate_custom(library, library['candidate'], int(library['run_id']), spec, lambda _: b'')
        controls = ['verified-cold', 'verified-warm', 'fresh-consumer', 'zip-mismatch', 'mod-mismatch', 'invalid-signature', 'authority-unavailable']
        source = lambda _: b'owned-public-fixture'
        strict = {'schema': 1, 'candidate': 'a' * 40, 'run_id': '1', 'runner_os': 'Linux', 'runner_arch': 'x86_64',
                  'status': 'passed', 'source_dirty': False, 'required_controls': controls,
                  'controls': dict.fromkeys(controls, 'passed'), 'go_version': '1.27.3', 'go_binary_sha256': 'b' * 64,
                  'script_sha256': hashlib.sha256(source('')).hexdigest(), 'fixture_sha256': hashlib.sha256(source('')).hexdigest(),
                  'zip_rejected_first': True, 'untrusted_zip_sum_retained': False,
                  'retry_succeeded': False, 'altered_inert_file_extracted': False}
        spec = SPECS['ci-summary-checksum-client-linux-amd64']
        self.assertEqual(validate_custom(strict, 'a' * 40, 1, spec, source), {'checks': 7, 'records': 1})
        for mutation in [lambda r: r['controls'].pop('zip-mismatch'), lambda r: r.update(status='failed'),
                         lambda r: r.update(retry_succeeded=True), lambda r: r.update(altered_inert_file_extracted=True)]:
            report = copy.deepcopy(strict)
            mutation(report)
            with self.assertRaises(EvidenceError):
                validate_custom(report, 'a' * 40, 1, spec, source)


if __name__ == '__main__':
    unittest.main()
