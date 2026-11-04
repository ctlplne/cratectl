#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import copy
import unittest
from sbt_evidence import FIXTURES,IDENTITIES,STAGES,safe_sbt_contract


def complete_contract(series='sbt2'):
    fixtures={n+'_'+e:'f'*64 for n in FIXTURES for e in ['jar','pom']}
    version='2.0.11' if series=='sbt2' else '1.13.0'
    return {'profile':'maven-release-v1','series':series,'version':version,'runtime_version':version,
            'java_version':'21.0.13+9-LTS',**{name:'a'*64 for name in IDENTITIES},
            'bootstrap_cache':{'files':0,'bytes':0,'sha256':'b'*64},
            'bootstrap_boot':{'files':100,'bytes':1000,'sha256':'c'*64},
            'fixture_sha256':fixtures,'reference_sha256':dict(fixtures),'wire_sha256':dict(fixtures),
            'completed':list(STAGES),'phase':'complete','diagnostics':[]}


class SbtEvidence(unittest.TestCase):
    def test_series_require_actual_runtime_all_stages_and_independent_wire_bytes(self):
        for series in ['sbt1','sbt2']:
            value=complete_contract(series);self.assertEqual(safe_sbt_contract(value,'passed'),value)
            for change in [{'runtime_version':None},{'runtime_version':'1.0.0'},{'completed':STAGES[:-1]},
                           {'phase':'policy'},{'bootstrap_cache':None},{'bootstrap_boot':None}]:
                with self.subTest(series=series,change=change),self.assertRaises(ValueError):safe_sbt_contract({**value,**change},'passed')
            for field in ['fixture_sha256','reference_sha256','wire_sha256']:
                changed=copy.deepcopy(value);changed[field].pop('local_application_3_pom')
                with self.subTest(field=field),self.assertRaises(ValueError):safe_sbt_contract(changed,'passed')

    def test_partial_bootstrap_is_visible_and_never_a_pass(self):
        value={**complete_contract(),'runtime_version':None,'bootstrap_boot':None,'bootstrap_cache':None,
               'fixture_sha256':{},'reference_sha256':{},'wire_sha256':{},'completed':[],'phase':'bootstrap','diagnostics':['fixture_compilation']}
        self.assertEqual(safe_sbt_contract(value,'failed'),value)
        with self.assertRaises(ValueError):safe_sbt_contract(value,'passed')
        with self.assertRaises(ValueError):safe_sbt_contract({**value,'completed':STAGES[:1]},'failed')

    def test_private_fields_unknown_codes_wrong_series_and_cache_bounds_fail_closed(self):
        value=complete_contract()
        changes=[{'private':'private-synthetic-value'},{'series':'private-synthetic-value'},{'version':'1.13.0'},
                 {'diagnostics':[{}]},{'diagnostics':['private-synthetic-value']},{'diagnostics':['http_403']*2},
                 {'completed':STAGES[::-1]},{'wire_sha256':{'dependency_jar':'0'*64}},
                 {'bootstrap_boot':{'files':0,'bytes':0,'sha256':'a'*64}},
                 {'bootstrap_cache':{'files':0,'bytes':1,'sha256':'a'*64}},
                 {'bootstrap_cache':{'files':20001,'bytes':1,'sha256':'a'*64}},
                 {'bootstrap_cache':{'files':1,'bytes':(768<<20)+1,'sha256':'a'*64}}]
        changes += [{name:'private-synthetic-value'} for name in IDENTITIES]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ValueError):safe_sbt_contract({**value,**change},'failed')


if __name__=='__main__':unittest.main()
