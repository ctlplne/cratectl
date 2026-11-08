#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Owned API/run stand-ins; retained reports never execute artifact code."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import accept_campaign as acceptance
from test_go_export_portability_evidence import complete as complete_legacy_contract
from test_go_common_export_portability_evidence import complete as complete_common_contract
from test_go_requirement_export_portability_evidence import complete as complete_requirement_contract
from campaign_contract import WORKFLOWS, jobs
from campaign_transport import EvidenceError, REPOSITORY

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = 'a' * 40


class Source:
    candidate = CANDIDATE
    verifier = 'b' * 40
    paths = set()
    compatibility = []
    inventory = {'integration_functions': 274, 'named_go_functions': 96, 'fuzz_targets': 57}
    baselines = json.loads((ROOT / 'scripts/ci/testdata/schema16-historical-baselines.json').read_text())['baselines']

    def __call__(self, _):
        return b'owned-fixture'


class HistoricalBaselineAdmission(unittest.TestCase):
    def test_only_exact_frozen_summary_baseline_bound_change_is_compatible(self):
        name = 'scripts/ci/evidence_summary.py'
        old = (ROOT / 'scripts/ci/testdata/schema17-evidence-summary.py.txt').read_bytes()
        current = (ROOT / 'scripts/ci/testdata/schema18-before-requirement-evidence-summary.py.txt').read_bytes()
        self.assertEqual(hashlib.sha256(old).hexdigest(), acceptance.SCHEMA17_SUMMARY_SHA256)
        entry = acceptance.compatible_contract(name, old, current, 17)
        self.assertEqual(entry['sha256'], hashlib.sha256(old).hexdigest())
        self.assertEqual(entry['verifier_sha256'], hashlib.sha256(current).hexdigest())
        for original, verifier, schema in [(old, current, 18), (old + b'\n', current, 17),
                (old, current + b'\n', 17), (old, current.replace(b'*range(2, 18)', b'*range(2, 19)'), 17),
                (old, current.replace(b"len(report['baselines']) > 17", b"len(report['baselines']) > 18"), 17),
                (old, current.replace(b"'binary_sha256'", b"'unreviewed_field'"), 17)]:
            with self.subTest(schema=schema), self.assertRaises(EvidenceError):
                acceptance.compatible_contract(name, original, verifier, schema)
        # New requirement-report extraction is a different contract. The exact
        # old exception cannot be widened to accept it for historical sources.
        with self.assertRaises(EvidenceError):
            acceptance.compatible_contract(name, old, (ROOT / name).read_bytes(), 17)

    def test_only_exact_frozen_upgrade_workflow_has_cross_generation_compatibility(self):
        name = '.github/workflows/upgrade-qualification.yml'
        old = (ROOT / 'scripts/ci/testdata/schema17-upgrade-workflow.yml').read_bytes()
        current = (ROOT / name).read_bytes()
        self.assertEqual(hashlib.sha256(old).hexdigest(), acceptance.SCHEMA17_UPGRADE_WORKFLOW_SHA256)
        entry = acceptance.compatible_contract(name, old, current, 17)
        self.assertEqual(entry['sha256'], hashlib.sha256(old).hexdigest())
        self.assertEqual(entry['verifier_sha256'], hashlib.sha256(current).hexdigest())
        self.assertNotIn('compatibility', acceptance.compatible_contract(name, current, current, 18))
        self.assertIn('every schema 2–16 upgrade', jobs('upgrades', 17)['Real PostgreSQL controlled upgrades (amd64)']['required'][2])
        self.assertIn('every schema 2–17 upgrade', jobs('upgrades', 18)['Real PostgreSQL controlled upgrades (amd64)']['required'][2])
        for original, verifier, path, schema in [
                (old, current, name, 18), (old, current, '.github/workflows/ci.yml', 17),
                (old + b'\n', current, name, 17), (old, current + b'\n', name, 17),
                (old, current.replace(b'14 15 16 17; do', b'14 15 17; do'), name, 17),
                (old, current.replace(b'ubuntu-24.04', b'ubuntu-latest'), name, 17)]:
            with self.subTest(path=path, schema=schema), self.assertRaises(EvidenceError):
                acceptance.compatible_contract(path, original, verifier, schema)

    def test_schema18_requires_qualified17_and_every_previous_binary(self):
        current = json.loads((ROOT / 'docs/qualification/upgrade-baselines.json').read_bytes())['baselines']
        acceptance.validate_baselines(current, 18)
        acceptance.validate_baselines(current[:-1], 17)
        for change in ('missing17', 'wrong17source', 'wrong17path', 'missingold', 'duplicate', 'reordered', 'unreviewedtarget'):
            rows = copy.deepcopy(current)
            schema = 18
            if change == 'missing17': rows.pop()
            elif change == 'wrong17source': rows[-1]['source'] = 'f' * 40
            elif change == 'wrong17path': rows[-1]['binary'] = '.cache/unqualified/cratectld'
            elif change == 'missingold': rows.pop(3)
            elif change == 'duplicate': rows[2] = copy.deepcopy(rows[1])
            elif change == 'reordered': rows[2], rows[3] = rows[3], rows[2]
            elif change == 'unreviewedtarget': schema = 19
            with self.subTest(change=change), self.assertRaises(EvidenceError):
                acceptance.validate_baselines(rows, schema)


def run(identifier=11, path='ci.yml'):
    return {'id': identifier, 'head_sha': CANDIDATE, 'head_branch': 'main', 'event': 'push',
            'path': '.github/workflows/' + path, 'run_attempt': 1, 'status': 'completed', 'conclusion': 'success',
            'repository': {'full_name': REPOSITORY}, 'head_repository': {'full_name': REPOSITORY}}


class API:
    def __init__(self):
        self.runs = [run()]
        self.snapshots = 0
        self.change_snapshot = False
        self.jobs = []
        self.artifacts = []
        self.bodies = {}
        self.transfers = []
        for n, (name, spec) in enumerate((n, s) for n, s in jobs('main').items() if s['kind'] in ('selection', 'security')):
            self.jobs.append({'id': 101 + n, 'name': name, 'run_id': 11, 'head_sha': CANDIDATE, 'head_branch': 'main',
                              'status': 'completed', 'conclusion': 'success', 'labels': ['ubuntu-24.04'],
                              'steps': [{'name': s, 'status': 'completed', 'conclusion': 'success'} for s in spec['required']]})
            self.bodies['jobs/' + str(101 + n) + '/logs'] = b'owned-private-synthetic-log-context\n'
        for n, name in enumerate(['source', 'fuzz', 'native']):
            self.jobs.append({'id': 201 + n, 'name': name, 'run_id': 11, 'head_sha': CANDIDATE, 'head_branch': 'main',
                              'status': 'completed', 'conclusion': 'skipped', 'steps': []})
        self.add_artifact(301, 'ci-selection', 'ci-selection.json', {'schema': 1, 'candidate': CANDIDATE, 'runtime': False})
        self.security = {'candidate': CANDIDATE, 'run_id': '11', 'runner_os': 'Linux', 'runner_arch': 'X64',
                         'generated_at': 'owned-private-synthetic', 'limits': ['owned-private-synthetic'],
                         'records': [{'report': 'gitleaks-rule-fixtures.json', 'raw_report_sha256': 'c' * 64,
                                      'status': 'passed', 'checks': None, 'cases': 324, 'source_dirty': None,
                                      'build_source_matches_candidate': None}]}
        self.add_artifact(302, 'ci-summary-security', 'ci-evidence-summary.json', self.security)

    def add_artifact(self, identifier, name, member, report):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(member, json.dumps(report).encode())
        raw = buffer.getvalue()
        self.artifacts = [a for a in self.artifacts if a['id'] != identifier]
        self.artifacts.append({'id': identifier, 'name': name, 'size_in_bytes': len(raw), 'expired': False,
                               'workflow_run': {'id': 11, 'head_sha': CANDIDATE}, 'digest': 'sha256:' + hashlib.sha256(raw).hexdigest()})
        self.bodies['artifacts/' + str(identifier) + '/zip'] = raw

    def listing(self, route, key):
        if route.startswith('runs?'):
            self.snapshots += 1
            values = self.runs + ([run(12, 'go-modules.yml')] if self.change_snapshot and self.snapshots > 1 else [])
        elif key == 'jobs':
            values = self.jobs
        else:
            values = self.artifacts
        return copy.deepcopy(values)

    def get(self, route, **_):
        self.transfers.append(route)
        return self.bodies[route]


class CampaignAcceptance(unittest.TestCase):
    def pairs(self):
        pairs, runners = {}, {}
        for factory in [complete_legacy_contract, complete_common_contract, complete_requirement_contract]:
            producer, consumer = factory('producer'), factory('consumer')
            key = (producer['profile'], 123)
            pairs[key] = {'producer': producer, 'consumer': consumer}
            runners[key] = {'producer': 100, 'consumer': 200}
        return pairs, runners

    def test_original_and_common_pair_each_bind_distinct_actual_runner_identities(self):
        pairs, runners = self.pairs()
        acceptance.validate_portable_pairs(pairs, runners)
        # Each CPU has its own native SDK bytes; equality across architectures
        # would misrepresent the actual independent native builds.
        for pair in pairs.values():
            pair['consumer']['go_binary_sha256'] = 'e' * 64
        acceptance.validate_portable_pairs(pairs, runners)

    def test_common_pair_missing_peer_changed_inputs_or_code_cannot_pass(self):
        for mode in ['missing', 'files', 'helper', 'run', 'scope']:
            pairs, runners = self.pairs()
            key = ('hosted-common-export-cross-runner-v1', 123)
            value = pairs[key]
            if mode == 'missing':
                del value['consumer']
            if mode == 'files':
                value['consumer']['files_sha256']['root.007.zip'] = 'f' * 64
            if mode == 'helper':
                value['consumer']['process_helper_sha256'] = 'f' * 64
            if mode == 'run':
                value['consumer']['source_run_id'] = '124'
            if mode == 'scope':
                value['consumer']['automatic_closure'] = True
            with self.subTest(mode=mode), self.assertRaises(EvidenceError):
                acceptance.validate_portable_pairs(pairs, runners)

    def test_requirement_pair_binds_all_inputs_helpers_scope_and_actual_runner_id(self):
        for field in ['fixture_sha256', 'public_key_sha256', 'reader_source_sha256', 'probe_helper_sha256',
                      'capsule_source_sha256', 'graph_fixture_source_sha256', 'native_helper_sha256',
                      'process_helper_sha256', 'decoder_sha256', 'script_sha256', 'examined_sources',
                      'selected_roots', 'automatic_closure', 'checksum_authority', 'destination_admission', 'runner']:
            pairs, runners = self.pairs()
            key = ('hosted-requirement-export-cross-runner-v1', 123)
            consumer = pairs[key]['consumer']
            if field == 'runner':
                runners[key]['consumer'] = runners[key]['producer']
            elif type(consumer[field]) is bool:
                consumer[field] = not consumer[field]
            elif type(consumer[field]) is int:
                consumer[field] += 1
            else:
                consumer[field] = 'e' * 64
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                acceptance.validate_portable_pairs(pairs, runners)

    def test_requirement_source_presence_adds_mandatory_workflow_steps_only_to_schema18(self):
        old = jobs('portable', 18)
        current = jobs('portable', 18, requirement_portability=True)
        for name in current:
            self.assertEqual(len(current[name]['required']), len(old[name]['required']) + 2)
            for step in current[name]['required'][-2:]:
                self.assertIn(step, (ROOT / '.github/workflows/go-export-portability.yml').read_text())
        for schema, flag in [(17, True), (18, 'true')]:
            with self.subTest(schema=schema, flag=flag), self.assertRaises(ValueError):
                jobs('portable', schema, requirement_portability=flag)

    def test_false_success_requirement_producer_refuses_missing_transfer_or_skipped_execution_before_logs(self):
        source = Source()
        source.schema = 18
        source.paths = {'scripts/conformance_go_common_export_portable.py', 'scripts/conformance_go_requirement_export_portable.py'}

        class RequirementAPI(API):
            def __init__(self, mode):
                super().__init__()
                self.runs.append(run(12, 'go-export-portability.yml'))
                self.portable_jobs = []
                for n, (name, spec) in enumerate(jobs('portable', 18, requirement_portability=True).items()):
                    steps = [{'name': step, 'status': 'completed', 'conclusion': 'success'} for step in spec['required']]
                    if n == 0 and mode.startswith('missing-step'):
                        del steps[-1 if mode.endswith('1') else -2]
                    if n == 0 and mode == 'skipped-step':
                        steps[-2]['conclusion'] = 'skipped'
                    self.portable_jobs.append({'id': 400+n, 'name': name, 'run_id': 12, 'head_sha': CANDIDATE,
                                               'head_branch': 'main', 'status': 'completed', 'conclusion': 'success',
                                               'labels': [spec['platform'][0]], 'steps': steps})
                self.portable_artifacts = [
                    {'id': 500+n, 'name': name, 'size_in_bytes': 100, 'expired': False,
                     'workflow_run': {'id': 12, 'head_sha': CANDIDATE}, 'digest': 'sha256:'+'c'*64}
                    for n, name in enumerate(['cratectl-owned-go-export-fixture', 'cratectl-owned-go-common-export-fixture',
                                              'cratectl-owned-go-requirement-export-fixture'])]
                if mode == 'missing-transfer':
                    self.portable_artifacts.pop()

            def listing(self, route, key):
                if route.startswith('runs/12/'):
                    return copy.deepcopy(self.portable_jobs if key == 'jobs' else self.portable_artifacts)
                return super().listing(route, key)

        for mode in ['missing-transfer', 'missing-step0', 'missing-step1', 'skipped-step']:
            api = RequirementAPI(mode)
            category = 'artifact_identity' if mode == 'missing-transfer' else 'required_step_not_passed'
            with self.subTest(mode=mode), self.assertRaisesRegex(EvidenceError, category):
                acceptance.accept(api, source, [11, 12])
            self.assertNotIn('jobs/400/logs', api.transfers)

    def test_runner_name_fingerprint_alone_cannot_replace_distinct_api_runner_ids(self):
        for mode in ['same-id', 'same-fingerprint']:
            pairs, runners = self.pairs()
            key = ('hosted-common-export-cross-runner-v1', 123)
            if mode == 'same-id':
                runners[key]['consumer'] = runners[key]['producer']
            else:
                pairs[key]['consumer']['destination_runner_sha256'] = pairs[key]['consumer']['source_runner_sha256']
            with self.subTest(mode=mode), self.assertRaisesRegex(EvidenceError, 'portable_pair_isolation'):
                acceptance.validate_portable_pairs(pairs, runners)

    def test_catalog_covers_every_existing_native_job_template(self):
        expected = {'main': 10, 'go': 2, 'jvm': 8, 'oci': 2, 'upgrades': 2, 'portable': 2, 'library': 2, 'browser': 3, 'strict': 3}
        self.assertEqual(sum(expected.values()), 34)
        for filename, family in WORKFLOWS.items():
            specs = jobs(family)
            self.assertEqual(len(specs), expected[family])
            patterns = re.findall(r'^    name: (.+)$', (ROOT / '.github/workflows' / filename).read_text(), re.M)
            expanded = [re.escape(re.sub(r'\$\{\{[^}]+\}\}', 'OWNED_MATRIX', value)).replace('OWNED_MATRIX', '.+') for value in patterns]
            for name in specs:
                self.assertTrue(any(re.fullmatch(p, name) for p in expanded), (filename, name))

    def test_documentation_scope_keeps_runtime_skips_unselected_and_raw_context_private(self):
        api = API()
        result = acceptance.accept(api, Source(), [11])
        self.assertEqual(result['status'], 'passed')
        self.assertFalse(result['goal_complete'])
        self.assertFalse(result['broad_readiness'])
        self.assertEqual(len(result['jobs']), 2)
        self.assertEqual(result['unselected_runtime'], [{'run_id': 11, 'scope': 'runtime', 'jobs': 3}])
        self.assertEqual(len(result['unselected_workflows']), 8)
        self.assertNotIn('owned-private-synthetic', json.dumps(result))
        self.assertEqual(api.snapshots, 2)

    def test_missing_duplicate_new_or_failed_runs_never_return_partial_acceptance(self):
        for kind in ['missing', 'duplicate', 'new', 'failed', 'pending', 'rerun', 'fork']:
            with self.subTest(kind=kind):
                api = API()
                identifiers = [11]
                if kind == 'missing':
                    identifiers = [12]
                elif kind == 'duplicate':
                    identifiers = [11, 11]
                elif kind == 'new':
                    api.change_snapshot = True
                elif kind == 'failed':
                    api.runs[0]['conclusion'] = 'failure'
                elif kind == 'pending':
                    api.runs[0]['status'] = 'in_progress'
                elif kind == 'rerun':
                    api.runs[0]['run_attempt'] = 2
                elif kind == 'fork':
                    api.runs[0]['head_repository']['full_name'] = 'owned-invalid/fork'
                with self.assertRaises(EvidenceError):
                    acceptance.accept(api, Source(), identifiers)

    def test_false_success_steps_foreign_jobs_missing_artifacts_and_empty_reports_refuse(self):
        for kind in ['step', 'skipped-required', 'foreign-job', 'missing-artifact', 'empty-records', 'unknown-field', 'wrong-native']:
            with self.subTest(kind=kind):
                api = API()
                if kind == 'step':
                    api.jobs[0]['steps'][0]['conclusion'] = 'skipped'
                elif kind == 'skipped-required':
                    api.jobs[1]['conclusion'] = 'skipped'
                elif kind == 'foreign-job':
                    api.jobs[-1]['head_sha'] = 'd' * 40
                elif kind == 'missing-artifact':
                    api.artifacts.pop()
                elif kind == 'empty-records':
                    api.security['records'] = []
                elif kind == 'unknown-field':
                    api.security['records'][0]['credential'] = 'owned-private-synthetic'
                elif kind == 'wrong-native':
                    api.jobs[1]['labels'] = ['self-hosted']
                if kind in ('empty-records', 'unknown-field'):
                    api.add_artifact(302, 'ci-summary-security', 'ci-evidence-summary.json', api.security)
                with self.assertRaises(EvidenceError):
                    acceptance.accept(api, Source(), [11])

    def test_new_kernel_control_and_native_inventory_markers_are_required(self):
        source = Source()
        source.paths = {'scripts/ci/prepare_owned_ports.py'}
        spec = next(iter(jobs('go').values()))
        package_lines = ('ok ctlplne.dev/cratectl/internal/server 1s\nok ctlplne.dev/cratectl/internal/store 1s\n' * 2)
        proof = {'profile': 'cratectl-owned-ci-ports-v1', 'source_sha256': hashlib.sha256(source('')).hexdigest(),
                 'machine': 'x86_64', 'owned_ports': [35432, 38443],
                 'kernel_controls': [{'mode': 'unreserved', 'automatic_uses_owned_port': True, 'explicit_bind_succeeds': False},
                                     {'mode': 'reserved', 'automatic_uses_owned_port': False, 'explicit_bind_succeeds': True}]}
        acceptance.check_log((package_lines + json.dumps(proof)).encode(), spec, source)
        for raw in [package_lines, package_lines + json.dumps({**proof, 'kernel_controls': []}),
                    package_lines + json.dumps(proof) * 2, package_lines + '--- SKIP: owned',
                    'ok ctlplne.dev/cratectl/internal/server 1s\n' + json.dumps(proof)]:
            with self.assertRaises(EvidenceError):
                acceptance.check_log(raw.encode(), spec, source)

    def test_portable_transfer_requires_bounded_exact_source_metadata(self):
        artifact = {'id': 301, 'size_in_bytes': 5000, 'expired': False,
                    'workflow_run': {'id': 11, 'head_sha': CANDIDATE}, 'digest': 'sha256:' + 'c' * 64}
        result = acceptance.artifact_metadata(artifact, CANDIDATE, 11, 26 << 20)
        self.assertEqual(result, {'artifact_id': 301, 'archive_bytes': 5000, 'reported_archive_sha256': 'c' * 64})
        for change in [{'size_in_bytes': 27 << 20}, {'expired': True}, {'digest': None},
                       {'workflow_run': {'id': 12, 'head_sha': CANDIDATE}},
                       {'workflow_run': {'id': 11, 'head_sha': 'b' * 40}}]:
            with self.subTest(change=change), self.assertRaises(EvidenceError):
                acceptance.artifact_metadata({**artifact, **change}, CANDIDATE, 11, 26 << 20)
        with self.assertRaises(EvidenceError):
            acceptance.artifact_metadata(None, CANDIDATE, 11, 26 << 20)

    def test_late_verifier_error_discards_passed_body_and_dispatch_guard_never_fetches(self):
        environment = {'CRATECTL_CAMPAIGN_CANDIDATE': CANDIDATE, 'CRATECTL_CAMPAIGN_RUN_IDS': '[11]',
                       'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
                       'GITHUB_REPOSITORY': REPOSITORY, 'RUNNER_ENVIRONMENT': 'github-hosted', 'GITHUB_ACTIONS': 'true',
                       'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64', 'GITHUB_RUN_ATTEMPT': '1',
                       'GITHUB_SHA': Source.verifier, 'GITHUB_RUN_ID': 'owned-private-synthetic'}
        for event in ['workflow_dispatch', 'pull_request']:
            with self.subTest(event=event), tempfile.TemporaryDirectory(prefix='cratectl-verdict-') as directory:
                with patch.object(acceptance, 'ROOT', Path(directory)), patch.dict(os.environ, {**environment, 'GITHUB_EVENT_NAME': event}, clear=True), patch.object(acceptance, 'Source', return_value=Source()) as constructor, patch.object(acceptance, 'GitHubEvidenceClient', return_value=API()):
                    self.assertEqual(acceptance.main(), 1)
                    result = json.loads((Path(directory) / '.cache/ci-campaign-verdict.json').read_text())
                    self.assertEqual(result['status'], 'not_accepted')
                    self.assertNotIn('jobs', result)
                    self.assertNotIn('owned-private-synthetic', json.dumps(result))
                    if event == 'pull_request':
                        constructor.assert_not_called()


if __name__ == '__main__':
    unittest.main()
