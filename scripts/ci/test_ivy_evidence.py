#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import copy
import unittest

from ivy_evidence import CHECKSUM_CLIENTS, FIXTURES, IDENTITIES, STAGES, METADATA_CASES, METADATA_STAGES, METADATA_REPRESENTATIONS, SNAPSHOT_FIXTURES, SNAPSHOT_CASES, SNAPSHOT_STAGES, safe_ivy_contract


def complete_contract():
    fixtures = {name+'_'+ext:'f'*64 for name in FIXTURES for ext in ['jar','pom']}
    return {'profile':'maven-release-v1','version':'2.6.0','ant_version':'1.10.18','ant_runtime_version':'1.10.18','ant_legacy_runtime_version':None,'java_version':'21.0.13+9-LTS',
            'ivy_distribution_sha512':'a'*128,'ant_distribution_sha512':'b'*128,
            **{field:'c'*64 for field in IDENTITIES},'fixture_sha256':fixtures,
            'reference_sha256':dict(fixtures),'wire_sha256':dict(fixtures),
            'completed':list(STAGES),'checksum_clients_completed':list(CHECKSUM_CLIENTS),'phase':'complete','diagnostics':[]}


def metadata_contract():
    value=complete_contract()
    fixtures={**value['fixture_sha256'],**{name+'_'+ext:'f'*64 for name,extensions in METADATA_REPRESENTATIONS.items() for ext in extensions}}
    return {**value,'profile':'maven-metadata-v2','completed':list(METADATA_STAGES),
            'metadata_cases_completed':list(METADATA_CASES),'fixture_sha256':fixtures,
            'reference_sha256':dict(fixtures),'wire_sha256':dict(fixtures)}


def snapshot_contract():
    value=metadata_contract();fixtures={**value['fixture_sha256'],**{name+'_'+ext:('d' if name=='snapshot_first' else 'e')*64 for name in SNAPSHOT_FIXTURES for ext in ['jar','pom']}}
    return {**value,'profile':'maven-snapshots-v3','completed':list(SNAPSHOT_STAGES),
            'snapshot_cases_completed':list(SNAPSHOT_CASES),'fixture_sha256':fixtures,
            'reference_sha256':dict(fixtures),'wire_sha256':dict(fixtures)}


class IvyEvidence(unittest.TestCase):
    def test_snapshot_profile_retains_original_graph_and_requires_changed_native_bytes(self):
        value=snapshot_contract();self.assertEqual(safe_ivy_contract(value,'passed'),value)
        self.assertEqual(len(value['wire_sha256']),34)
        self.assertEqual([s for s in value['completed'] if s!='snapshots'],METADATA_STAGES)
        for change in [{'completed':METADATA_STAGES},{'snapshot_cases_completed':SNAPSHOT_CASES[:-1]},
                       {'snapshot_cases_completed':SNAPSHOT_CASES[::-1]},{'profile':'maven-metadata-v2'},
                       {'snapshot_cases_completed':['private-synthetic-value']}]:
            with self.subTest(change=change),self.assertRaises(ValueError):safe_ivy_contract({**value,**change},'passed')
        for name in ['default_snapshot_jar','snapshot_first_pom','snapshot_second_jar','metadata_app_tests_jar','dependency_jar']:
            for field in ['fixture_sha256','reference_sha256','wire_sha256']:
                bad=copy.deepcopy(value);bad[field].pop(name)
                with self.subTest(name=name,field=field),self.assertRaises(ValueError):safe_ivy_contract(bad,'passed')
        bad=copy.deepcopy(value)
        for field in ['fixture_sha256','reference_sha256','wire_sha256']:bad[field]['snapshot_second_jar']=bad[field]['snapshot_first_jar']
        with self.assertRaises(ValueError):safe_ivy_contract(bad,'passed')

    def test_partial_snapshot_cases_cannot_skip_metadata_or_claim_early_completion(self):
        value={**snapshot_contract(),'completed':SNAPSHOT_STAGES[:7],'snapshot_cases_completed':SNAPSHOT_CASES[:2],'phase':'snapshots'}
        self.assertEqual(safe_ivy_contract(value,'failed'),value)
        for change in [{'completed':SNAPSHOT_STAGES[:6]},{'completed':SNAPSHOT_STAGES[:8]},
                       {'snapshot_cases_completed':SNAPSHOT_CASES[:2]*2}]:
            with self.subTest(change=change),self.assertRaises(ValueError):safe_ivy_contract({**value,**change},'failed')

    def test_metadata_profile_preserves_all_release_cases_and_requires_exact_graph_bytes(self):
        value=metadata_contract()
        self.assertEqual(safe_ivy_contract(value,'passed'),value)
        self.assertEqual(len(value['wire_sha256']),28)
        self.assertEqual([s for s in value['completed'] if s!='metadata'],STAGES)
        for key in ['parent_pom','metadata_app_tests_jar','choice_1_pom','bridge_2_jar','dependency_jar']:
            for field in ['fixture_sha256','reference_sha256','wire_sha256']:
                bad=copy.deepcopy(value);bad[field].pop(key)
                with self.subTest(key=key,field=field),self.assertRaises(ValueError):safe_ivy_contract(bad,'passed')
        for cases in [[],METADATA_CASES[:-1],METADATA_CASES[::-1],['private-synthetic-value']]:
            with self.subTest(cases=cases),self.assertRaises(ValueError):safe_ivy_contract({**value,'metadata_cases_completed':cases},'passed')
        for change in [{'completed':STAGES},{'phase':'metadata'},{'profile':'maven-release-v1'}]:
            with self.subTest(change=change),self.assertRaises(ValueError):safe_ivy_contract({**value,**change},'passed')

    def test_partial_metadata_failure_cannot_fabricate_case_or_stage_completion(self):
        value={**metadata_contract(),'phase':'metadata','completed':METADATA_STAGES[:6],
               'metadata_cases_completed':METADATA_CASES[:2],'diagnostics':['resolution']}
        self.assertEqual(safe_ivy_contract(value,'failed'),value)
        for change in [{'completed':METADATA_STAGES[:5]},{'completed':METADATA_STAGES[:7]},
                       {'metadata_cases_completed':METADATA_CASES[:1]*2}]:
            with self.subTest(change=change),self.assertRaises(ValueError):safe_ivy_contract({**value,**change},'failed')

    def test_complete_requires_every_native_stage_and_independent_representation(self):
        value = complete_contract()
        self.assertEqual(safe_ivy_contract(value,'passed'),value)
        for field in ['fixture_sha256','reference_sha256','wire_sha256']:
            changed = copy.deepcopy(value);del changed[field]['local_application_3_pom']
            with self.subTest(field=field),self.assertRaises(ValueError):safe_ivy_contract(changed,'passed')
        for change in [{'completed':STAGES[:-1]},{'completed':STAGES[::-1]},{'phase':'policy'},{'diagnostics':['publication']},{'checksum_clients_completed':CHECKSUM_CLIENTS[:-1]}]:
            with self.subTest(change=change),self.assertRaises(ValueError):safe_ivy_contract({**value,**change},'passed')

    def test_partial_failure_keeps_progress_without_fabricating_readback(self):
        value = {**complete_contract(),'phase':'publication','completed':STAGES[:1],
                 'fixture_sha256':{'dependency_jar':'f'*64},'reference_sha256':{},'wire_sha256':{},'checksum_clients_completed':[],'diagnostics':['http_403']}
        self.assertEqual(safe_ivy_contract(value,'failed'),value)
        with self.assertRaises(ValueError):safe_ivy_contract(value,'passed')

    def test_observed_ant_runtime_is_required_and_must_match_pin(self):
        for observed in [None,'1.10.14']:
            value={**complete_contract(),'ant_runtime_version':observed}
            self.assertEqual(safe_ivy_contract(value,'failed')['ant_runtime_version'],observed)
            with self.subTest(observed=observed),self.assertRaises(ValueError):safe_ivy_contract(value,'passed')

    def test_private_fields_wrong_hashes_and_unknown_cases_are_rejected(self):
        value = complete_contract()
        changes = [{'profile':'private-synthetic-value'},{'private_output':'private-synthetic-value'},{'phase':'private-synthetic-value'},
                   {'completed':['private-synthetic-value']},{'diagnostics':['private-synthetic-value']},{'diagnostics':['http_401']*2},
                   {'checksum_clients_completed':['private-synthetic-value']},{'checksum_clients_completed':CHECKSUM_CLIENTS[::-1]},
                   {'completed':STAGES[:1]},
                   {'wire_sha256':{'dependency_pom':'0'*64}},{'reference_sha256':{'unexpected':'f'*64}}]
        changes += [{field:'private-synthetic-value'} for field in ['version','ant_version','ant_runtime_version','ant_legacy_runtime_version','java_version','ivy_distribution_sha512','ant_distribution_sha512',*IDENTITIES]]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ValueError):safe_ivy_contract({**value,**change},'failed')


if __name__ == '__main__':unittest.main()
