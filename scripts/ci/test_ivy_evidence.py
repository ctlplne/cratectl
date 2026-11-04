#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import copy
import unittest

from ivy_evidence import FIXTURES, IDENTITIES, STAGES, safe_ivy_contract


def complete_contract():
    fixtures = {name+'_'+ext:'f'*64 for name in FIXTURES for ext in ['jar','pom']}
    return {'profile':'maven-release-v1','version':'2.6.0','ant_version':'1.10.18','java_version':'21.0.13+9-LTS',
            'ivy_distribution_sha512':'a'*128,'ant_distribution_sha512':'b'*128,
            **{field:'c'*64 for field in IDENTITIES},'fixture_sha256':fixtures,
            'reference_sha256':dict(fixtures),'wire_sha256':dict(fixtures),
            'completed':list(STAGES),'phase':'complete','diagnostics':[]}


class IvyEvidence(unittest.TestCase):
    def test_complete_requires_every_native_stage_and_independent_representation(self):
        value = complete_contract()
        self.assertEqual(safe_ivy_contract(value,'passed'),value)
        for field in ['fixture_sha256','reference_sha256','wire_sha256']:
            changed = copy.deepcopy(value);del changed[field]['local_application_3_pom']
            with self.subTest(field=field),self.assertRaises(ValueError):safe_ivy_contract(changed,'passed')
        for change in [{'completed':STAGES[:-1]},{'completed':STAGES[::-1]},{'phase':'policy'},{'diagnostics':['publication']}]:
            with self.subTest(change=change),self.assertRaises(ValueError):safe_ivy_contract({**value,**change},'passed')

    def test_partial_failure_keeps_progress_without_fabricating_readback(self):
        value = {**complete_contract(),'phase':'publication','completed':STAGES[:1],
                 'fixture_sha256':{'dependency_jar':'f'*64},'reference_sha256':{},'wire_sha256':{},'diagnostics':['http_403']}
        self.assertEqual(safe_ivy_contract(value,'failed'),value)
        with self.assertRaises(ValueError):safe_ivy_contract(value,'passed')

    def test_private_fields_wrong_hashes_and_unknown_cases_are_rejected(self):
        value = complete_contract()
        changes = [{'profile':'private-synthetic-value'},{'private_output':'private-synthetic-value'},{'phase':'private-synthetic-value'},
                   {'completed':['private-synthetic-value']},{'diagnostics':['private-synthetic-value']},{'diagnostics':['http_401']*2},
                   {'wire_sha256':{'dependency_pom':'0'*64}},{'reference_sha256':{'unexpected':'f'*64}}]
        changes += [{field:'private-synthetic-value'} for field in ['version','ant_version','java_version','ivy_distribution_sha512','ant_distribution_sha512',*IDENTITIES]]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ValueError):safe_ivy_contract({**value,**change},'failed')


if __name__ == '__main__':unittest.main()
