#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import copy,hashlib,unittest
from go_module_evidence import STAGES,FIXTURES,CACHED_FIXTURES,safe_go_module_contract

def complete_contract():
 hashes={k:hashlib.sha256(k.encode()).hexdigest()for k in FIXTURES}
 return {'profile':'hosted-module-v1','version':'1.27.3','go_binary_sha256':'a'*64,'fixture_source_sha256':'b'*64,'completed':list(STAGES),'publisher_sha256':hashes,'reference_sha256':dict(hashes),'wire_sha256':dict(hashes),'cached_sha256':{k:v for k,v in hashes.items()if k in CACHED_FIXTURES}}
class GoModuleEvidence(unittest.TestCase):
 def test_complete_and_failed_prefix(self):
  contract=complete_contract();self.assertEqual(safe_go_module_contract(contract,'passed'),contract)
  failed={**contract,'version':None,'completed':[],**{k:{}for k in ['publisher_sha256','reference_sha256','wire_sha256','cached_sha256']}}
  self.assertEqual(safe_go_module_contract(failed,'failed'),failed)
  with self.assertRaises(ValueError):safe_go_module_contract(failed,'passed')
 def test_unknown_fields_and_private_observations_fail(self):
  for change in [{'credential':'private-value'},{'profile':None},{'profile':[]},{'profile':'generic'},{'version':'go1.27.3'},{'completed':STAGES[::-1]},{'go_binary_sha256':'not-a-hash'}]:
   with self.subTest(change=change),self.assertRaises(ValueError):safe_go_module_contract({**complete_contract(),**change},'passed')
 def test_missing_and_mismatched_representation_fails(self):
  for field in ['publisher_sha256','reference_sha256','wire_sha256','cached_sha256']:
   for action in ['missing','mismatch','unknown']:
    c=copy.deepcopy(complete_contract());key=next(iter(c[field]))
    if action=='missing':del c[field][key]
    elif action=='mismatch':c[field][key]='f'*64
    else:c[field]['private-package-identity']='c'*64
    with self.subTest(field=field,action=action),self.assertRaises(ValueError):safe_go_module_contract(c,'passed')
 def test_identical_tenant_or_version_payloads_cannot_pass(self):
  for first,second in [('application_1_zip','application_2_zip'),('application_1_zip','other_application_zip'),('dependency_zip','other_dependency_zip')]:
   c=complete_contract()
   for key in ['publisher_sha256','reference_sha256','wire_sha256','cached_sha256']:c[key][second]=c[key][first]
   with self.assertRaises(ValueError):safe_go_module_contract(c,'passed')
if __name__=='__main__':unittest.main()
