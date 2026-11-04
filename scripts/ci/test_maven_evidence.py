#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import copy
import unittest

from maven_evidence import FIXTURES,MAPS,STAGES,safe_maven_cache_contract


def complete_contract():
    hashes={name:('a' if name=='first_jar' else 'b' if name=='second_jar' else 'c')*64 for name in FIXTURES}
    return {'profile':'unique-snapshot-warm-v1','version':'3.10.0','distribution_sha512':'d'*128,
            'completed':list(STAGES),'cache_reused':True,**{name:dict(hashes) for name in MAPS}}


class MavenCacheEvidence(unittest.TestCase):
    def test_pass_requires_every_original_and_updated_representation(self):
        value=complete_contract();self.assertEqual(safe_maven_cache_contract(value,'passed'),value)
        for name in MAPS:
            for key in FIXTURES:
                bad=copy.deepcopy(value);bad[name].pop(key)
                with self.subTest(name=name,key=key),self.assertRaises(ValueError):safe_maven_cache_contract(bad,'passed')
        for change in [{'completed':STAGES[:-1]},{'cache_reused':False},{'version':None},{'distribution_sha512':None}]:
            with self.subTest(change=change),self.assertRaises(ValueError):safe_maven_cache_contract({**value,**change},'passed')

    def test_equal_old_bytes_cannot_claim_a_warm_update(self):
        value=complete_contract()
        for name in MAPS:value[name]['second_jar']=value[name]['first_jar']
        with self.assertRaises(ValueError):safe_maven_cache_contract(value,'passed')

    def test_partial_failure_preserves_only_completed_observations(self):
        value={**complete_contract(),'completed':STAGES[:1],'cache_reused':False,
               **{name:{'first_jar':'a'*64} for name in MAPS}}
        self.assertEqual(safe_maven_cache_contract(value,'failed'),value)
        for change in [{'completed':[]},{'completed':STAGES[:2]},{'cache_reused':True}]:
            with self.subTest(change=change),self.assertRaises(ValueError):safe_maven_cache_contract({**value,**change},'failed')
        empty={**value,'completed':[],'version':None,'distribution_sha512':None,**{name:{} for name in MAPS}}
        self.assertEqual(safe_maven_cache_contract(empty,'failed'),empty)

    def test_private_fields_unknown_names_bad_hashes_and_reordered_stages_fail(self):
        value=complete_contract()
        changes=[{'private_output':'private-synthetic-value'},{'profile':'private-synthetic-value'},
                 {'version':'private-synthetic-value'},{'distribution_sha512':'private-synthetic-value'},
                 {'cache_reused':1},{'completed':STAGES[::-1]}]
        changes += [{name:{'private-synthetic-name':'f'*64}} for name in MAPS]
        changes += [{name:{**value[name],'first_jar':'e'*64}} for name in MAPS[1:]]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ValueError):safe_maven_cache_contract({**value,**change},'failed')


if __name__=='__main__':unittest.main()
