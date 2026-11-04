# SPDX-License-Identifier: BUSL-1.1
"""Bounded public evidence contract for the named native hosted Go profile."""
import re
STAGES=['client_identity','installation','publication','review_and_consumption','immutability','tenant_collision','policy_and_restart','revocation']
PACKAGES=('dependency','application_1','application_2','other_dependency','other_application')
FIXTURES={name+'_'+kind for name in PACKAGES for kind in ['zip','mod','info']}
CACHED_FIXTURES={name+'_'+kind for name in PACKAGES for kind in ['zip','mod']}

GROUP_PACKAGES=PACKAGES+('lower_dependency','lower_application_1','lower_application_3')
GROUP_STAGES=STAGES[:6]+['groups']+STAGES[6:]
GROUP_FIXTURES={name+'_'+kind for name in GROUP_PACKAGES for kind in ['zip','mod','info']}
GROUP_CACHED_FIXTURES={name+'_'+kind for name in GROUP_PACKAGES for kind in ['zip','mod']}

def safe_go_module_contract(value,status):
 fields={'profile','version','go_binary_sha256','fixture_source_sha256','completed','publisher_sha256','reference_sha256','wire_sha256','cached_sha256'}
 if not isinstance(value,dict)or set(value)!=fields or value['profile']not in ('hosted-module-v1','hosted-group-module-v2'):raise ValueError('Go evidence must identify the reviewed hosted profile')
 group=value['profile']=='hosted-group-module-v2'
 stages=GROUP_STAGES if group else STAGES
 fixtures=GROUP_FIXTURES if group else FIXTURES
 cached=GROUP_CACHED_FIXTURES if group else CACHED_FIXTURES
 version=value['version']
 if version is not None and(not isinstance(version,str)or not re.fullmatch(r'1\.\d{1,3}\.\d{1,3}',version)):raise ValueError('Go version must be a bounded observed native runtime')
 for k in ['go_binary_sha256','fixture_source_sha256']:
  if not isinstance(value[k],str)or not re.fullmatch('[0-9a-f]{64}',value[k]):raise ValueError('Go tool and fixture source identities must be digests')
 completed=value['completed']
 if not isinstance(completed,list)or completed!=stages[:len(completed)]or len(completed)>len(stages):raise ValueError('Go stages must be the ordered mandatory prefix')
 if completed and version is None:raise ValueError('Completed Go identity requires its observed runtime')
 for name in ['publisher_sha256','reference_sha256','wire_sha256','cached_sha256']:
  hashes=value[name];allowed=cached if name=='cached_sha256'else fixtures
  if not isinstance(hashes,dict)or not set(hashes)<=allowed or any(not isinstance(h,str)or not re.fullmatch('[0-9a-f]{64}',h)for h in hashes.values()):raise ValueError('Go representations exceed the owned fixture set')
  if name!='publisher_sha256'and any(value['publisher_sha256'].get(k)!=h for k,h in hashes.items()):raise ValueError('Go observed bytes must equal the exact publisher bytes')
  if status=='passed'and set(hashes)!=allowed:raise ValueError('Passed Go evidence requires every mandatory byte binding')
 if status=='passed':
  if completed!=stages or version is None:raise ValueError('Passed Go evidence requires every native stage')
  hashes=value['publisher_sha256']
  if group and(hashes['lower_application_1_zip']==hashes['application_1_zip']or hashes['lower_dependency_zip']==hashes['dependency_zip']):raise ValueError('Go group fixtures require distinct lower-priority bytes')
  if any(hashes[a]==hashes[b]for a,b in [('application_1_zip','application_2_zip'),('application_1_zip','other_application_zip'),('dependency_zip','other_dependency_zip')]):raise ValueError('Go versions and tenants must contain distinct actual package bytes')
 return {**value,**{k:dict(sorted(value[k].items()))for k in ['publisher_sha256','reference_sha256','wire_sha256','cached_sha256']}}
