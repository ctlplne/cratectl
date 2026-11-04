#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import copy
import unittest

from gradle_evidence import FIXTURES, STAGES, safe_gradle_contract


def complete_contract():
    fixtures={name+'_'+ext:'f'*64 for name in FIXTURES for ext in ['jar','pom','module']}
    return {'profile':'publication-wire-v2','version':'9.8.2','distribution_sha256':'a'*64,'launcher_sha256':'b'*64,
            'java_version':'21.0.13+9-LTS','java_launcher_sha256':'c'*64,'java_release_sha256':'d'*64,
            'fixture_source_sha256':'e'*64,'fixture_sha256':fixtures,
            'reference_sha256':dict(fixtures),'wire_sha256':dict(fixtures),
            'completed':list(STAGES),'phase':'complete','diagnostics':[]}


class GradleEvidence(unittest.TestCase):
    def test_pass_requires_every_native_stage_and_representation(self):
        value=complete_contract()
        self.assertEqual(safe_gradle_contract(value,'passed'),value)
        missing=copy.deepcopy(value);missing['fixture_sha256'].pop('snapshot_second_module')
        for change in [{'phase':'snapshots'},{'completed':STAGES[:-1]}, {'completed':list(reversed(STAGES))}, {'diagnostics':['http_403']}, {'fixture_sha256':missing['fixture_sha256']}]:
            with self.subTest(change=change),self.assertRaises(ValueError):
                safe_gradle_contract({**value,**change},'passed')

    def test_partial_failure_retains_only_its_real_progress(self):
        value={**complete_contract(),'phase':'proxy_group','completed':STAGES[:4], 'fixture_sha256':{},'reference_sha256':{},'wire_sha256':{},'diagnostics':['variant_selection','http_403']}
        self.assertEqual(safe_gradle_contract(value,'failed')['completed'],STAGES[:4])
        self.assertEqual(safe_gradle_contract(value,'failed')['diagnostics'],['http_403','variant_selection'])

    def test_publisher_hashes_cannot_stand_in_for_retained_and_http_bytes(self):
        for field in ['reference_sha256','wire_sha256']:
            value=complete_contract()
            del value[field]['snapshot_second_pom']
            with self.subTest(field=field),self.assertRaises(ValueError):
                safe_gradle_contract(value,'passed')
            self.assertNotIn('snapshot_second_pom',safe_gradle_contract(value,'failed')[field])
            for bad in [{'dependency_pom':'0'*64},{'unexpected':'f'*64}, {'dependency_pom':{'private':'value'}}]:
                with self.subTest(field=field,bad=bad),self.assertRaises(ValueError):
                    safe_gradle_contract({**complete_contract(),field:bad},'failed')

    def test_private_output_and_unbounded_fields_are_rejected(self):
        value=complete_contract()
        changes=[{'profile':'private-synthetic-value'}, {'version':'private-synthetic-value'}, {'java_version':'private-synthetic-value'}, {'phase':'private-synthetic-value'}, {'diagnostics':['private-synthetic-value']}, {'diagnostics':['http_403']*2}, {'completed':['private-synthetic-value']}, {'fixture_sha256':{'private-synthetic-value':'f'*64}}, {'fixture_sha256':{'dependency_jar':'private-synthetic-value'}}, {'raw_output':'private-synthetic-value'}]
        changes += [{key:'private-synthetic-value'} for key in ['distribution_sha256','launcher_sha256','fixture_source_sha256','java_launcher_sha256','java_release_sha256']]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ValueError):
                safe_gradle_contract({**value,**change},'failed')


if __name__ == '__main__':
    unittest.main()
