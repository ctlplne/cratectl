# SPDX-License-Identifier: BUSL-1.1
"""Reviewed SBT release/snapshot profiles, native versions and exact wire bytes."""
import re

FIXTURES = ('dependency','application_1','application_2','other_dependency','other_application_1','local_application_3')
STAGES = ['client_identity','publication','review_and_tenants','reader_publication_denied','proxy_group','policy_and_restart','revocation']
PHASES = {'bootstrap','client_identity','publication','review','proxy_group','policy','revocation','complete'}
DIAGNOSTICS = {'http_401','http_403','http_404','fixture_compilation','dependency_resolution','publication','checksum','jvm'}
IDENTITIES = ['distribution_sha256','launcher_sha256','java_launcher_sha256','java_release_sha256','fixture_source_sha256']
SNAPSHOT_FIXTURES = ('default_snapshot','snapshot_first','snapshot_second')
SNAPSHOT_CASES = ['default_immutable','opt_in_redeploy','review_reset','fresh_resolution',
                  'held_replacement','disable_policy','restart','revocation']
SNAPSHOT_STAGES = STAGES[:-1] + ['snapshots'] + STAGES[-1:]


def safe_sbt_contract(value,status):
    fields = {'profile','series','version','runtime_version','java_version',*IDENTITIES,'bootstrap_cache','bootstrap_boot',
              'fixture_sha256','reference_sha256','wire_sha256','completed','phase','diagnostics'}
    snapshot=isinstance(value,dict) and value.get('profile')=='maven-snapshots-v2'
    if snapshot:fields.add('snapshot_cases_completed')
    if not isinstance(value,dict) or set(value)!=fields or value['profile'] not in ('maven-release-v1','maven-snapshots-v2'):
        raise ValueError('SBT fields must identify the reviewed native profile')
    if value['series'] not in ('sbt1','sbt2') or not isinstance(value['version'],str) or not re.fullmatch(('1' if value['series']=='sbt1' else '2')+r'\.\d{1,3}\.\d{1,3}',value['version']):
        raise ValueError('SBT series and version must agree')
    observed=value['runtime_version']
    if observed is not None and (not isinstance(observed,str) or not re.fullmatch(r'[12]\.\d{1,3}\.\d{1,3}',observed)):
        raise ValueError('SBT runtime must be a bounded observed version')
    if status=='passed' and observed!=value['version']:
        raise ValueError('Passed SBT evidence requires its actual pinned runtime')
    if not isinstance(value['java_version'],str) or not re.fullmatch(r'21\.\d{1,3}\.\d{1,3}\+\d{1,3}(?:-LTS)?',value['java_version']):
        raise ValueError('SBT Java runtime must identify the actual build')
    for field in IDENTITIES:
        if not isinstance(value[field],str) or not re.fullmatch('[0-9a-f]{64}',value[field]):
            raise ValueError('SBT tool and fixture identities must be digests')
    for name in ['bootstrap_cache','bootstrap_boot']:
        seed=value[name]
        if seed is None:
            if status=='passed' or value['completed']:
                raise ValueError('SBT bootstrap identity evidence is missing')
        elif not isinstance(seed,dict) or set(seed)!={'files','bytes','sha256'} or type(seed['files']) is not int or not 0<=seed['files']<=20000 or type(seed['bytes']) is not int or not 0<=seed['bytes']<=768<<20 or (seed['files']==0 and seed['bytes']!=0) or not isinstance(seed['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',seed['sha256']):
            raise ValueError('SBT bootstrap identity must be a bounded tool-only inventory')
        elif name=='bootstrap_boot' and (seed['files']==0 or seed['bytes']==0):
            raise ValueError('SBT boot library inventory cannot be empty')
    completed=value['completed'];diagnostics=value['diagnostics']
    stages=SNAPSHOT_STAGES if snapshot else STAGES
    if not isinstance(completed,list) or len(completed)>len(stages) or completed!=stages[:len(completed)]:
        raise ValueError('SBT stages must be the ordered mandatory prefix')
    if not isinstance(value['phase'],str) or value['phase'] not in (PHASES|{'snapshots'}if snapshot else PHASES):
        raise ValueError('SBT phase must use the fixed vocabulary')
    if not isinstance(diagnostics,list) or len(diagnostics)>len(DIAGNOSTICS) or any(not isinstance(c,str) or c not in DIAGNOSTICS for c in diagnostics) or len(set(diagnostics))!=len(diagnostics):
        raise ValueError('SBT diagnostics must use fixed codes')
    allowed={n+'_'+e for n in FIXTURES+(SNAPSHOT_FIXTURES if snapshot else ())for e in ['jar','pom']};fixtures=value['fixture_sha256']
    if not isinstance(fixtures,dict) or not set(fixtures)<=allowed or any(not isinstance(h,str) or not re.fullmatch('[0-9a-f]{64}',h) for h in fixtures.values()):
        raise ValueError('SBT fixture identities are outside the owned set')
    if snapshot:
        cases=value['snapshot_cases_completed']
        if not isinstance(cases,list) or len(cases)>len(SNAPSHOT_CASES) or cases!=SNAPSHOT_CASES[:len(cases)]:
            raise ValueError('SBT snapshot cases must be the mandatory ordered prefix')
        if len(completed)<6 and cases:
            raise ValueError('SBT snapshot observations cannot precede original policy/restart')
        if (status=='passed' or 'snapshots'in completed) and cases!=SNAPSHOT_CASES:
            raise ValueError('Passed SBT snapshot evidence requires every native case')
        if 'opt_in_redeploy'in cases and (not {'snapshot_first_jar','snapshot_second_jar'}<=set(fixtures) or fixtures['snapshot_first_jar']==fixtures['snapshot_second_jar']):
            raise ValueError('SBT snapshot redeployment requires changed actual JAR bytes')
    for name in ['reference_sha256','wire_sha256']:
        observed=value[name]
        if not isinstance(observed,dict) or not set(observed)<=set(fixtures) or any(h!=fixtures[k] for k,h in observed.items()):
            raise ValueError('SBT retained/HTTP bytes must equal exact publisher bytes')
        if status=='passed' and set(observed)!=allowed:
            raise ValueError('Passed SBT evidence requires every retained/HTTP representation')
    if status=='passed' and (completed!=stages or set(fixtures)!=allowed or value['phase']!='complete' or diagnostics):
        raise ValueError('Passed SBT evidence requires all stages and representations')
    return {**value,**{k:dict(sorted(value[k].items())) for k in ['fixture_sha256','reference_sha256','wire_sha256']},'diagnostics':sorted(diagnostics)}
