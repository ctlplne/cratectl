# SPDX-License-Identifier: BUSL-1.1
"""Bounded public evidence contract for the named native hosted Go profile."""
import re
STAGES=['client_identity','installation','publication','review_and_consumption','immutability','tenant_collision','policy_and_restart','revocation']
PACKAGES=('dependency','application_1','application_2','other_dependency','other_application')
FIXTURES={name+'_'+kind for name in PACKAGES for kind in ['zip','mod','info']}
CACHED_FIXTURES={name+'_'+kind for name in PACKAGES for kind in ['zip','mod']}

def safe_go_module_contract(value,status):
 fields={'profile','version','go_binary_sha256','fixture_source_sha256','completed','publisher_sha256','reference_sha256','wire_sha256','cached_sha256'}
 if not isinstance(value,dict)or set(value)!=fields or value['profile']!='hosted-module-v1':raise ValueError('Go evidence must identify the reviewed hosted profile')
 version=value['version']
 if version is not None and(not isinstance(version,str)or not re.fullmatch(r'1\.\d{1,3}\.\d{1,3}',version)):raise ValueError('Go version must be a bounded observed native runtime')
 for k in ['go_binary_sha256','fixture_source_sha256']:
  if not isinstance(value[k],str)or not re.fullmatch('[0-9a-f]{64}',value[k]):raise ValueError('Go tool and fixture source identities must be digests')
 completed=value['completed']
 if not isinstance(completed,list)or completed!=STAGES[:len(completed)]or len(completed)>len(STAGES):raise ValueError('Go stages must be the ordered mandatory prefix')
 if completed and version is None:raise ValueError('Completed Go identity requires its observed runtime')
 for name in ['publisher_sha256','reference_sha256','wire_sha256','cached_sha256']:
  hashes=value[name];allowed=CACHED_FIXTURES if name=='cached_sha256'else FIXTURES
  if not isinstance(hashes,dict)or not set(hashes)<=allowed or any(not isinstance(h,str)or not re.fullmatch('[0-9a-f]{64}',h)for h in hashes.values()):raise ValueError('Go representations exceed the owned fixture set')
  if name!='publisher_sha256'and any(value['publisher_sha256'].get(k)!=h for k,h in hashes.items()):raise ValueError('Go observed bytes must equal the exact publisher bytes')
  if status=='passed'and set(hashes)!=allowed:raise ValueError('Passed Go evidence requires every mandatory byte binding')
 if status=='passed':
  if completed!=STAGES or version is None:raise ValueError('Passed Go evidence requires every native stage')
  hashes=value['publisher_sha256']
  if any(hashes[a]==hashes[b]for a,b in [('application_1_zip','application_2_zip'),('application_1_zip','other_application_zip'),('dependency_zip','other_dependency_zip')]):raise ValueError('Go versions and tenants must contain distinct actual package bytes')
 return {**value,**{k:dict(sorted(value[k].items()))for k in ['publisher_sha256','reference_sha256','wire_sha256','cached_sha256']}}
