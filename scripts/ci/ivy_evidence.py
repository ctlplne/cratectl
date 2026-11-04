# SPDX-License-Identifier: BUSL-1.1
"""Reviewed owned Ivy fields, mandatory stages and publication byte binding."""
import re

FIXTURES = ('dependency','application_1','application_2','other_dependency','other_application_1','local_application_3')
STAGES = ['client_identity','publication','review_and_tenants','reader_publication_denied','proxy_group','policy_and_restart','revocation']
PHASES = {'client_identity','publication','review','proxy_group','policy','revocation','complete'}
DIAGNOSTICS = {'http_401','http_403','http_404','resolution','publication','fixture','ant_identity','checksum_algorithm'}
IDENTITIES = ['java_launcher_sha256','java_release_sha256','ivy_launcher_sha256','ant_launcher_sha256','ant_bootstrap_sha256','ant_library_sha256','fixture_source_sha256']
CHECKSUM_CLIENTS = ['SHA-256','SHA-384','SHA-512']
METADATA_STAGES = STAGES[:-1] + ['metadata'] + STAGES[-1:]
METADATA_CASES = ['parent_pom','classifier','configurations','pom_exclusion','client_exclusion',
                  'latest_conflict','cached_parent_policy','metadata_restart']
METADATA_REPRESENTATIONS = {
    'parent': ('pom',), 'choice_1': ('jar','pom'), 'choice_2': ('jar','pom'),
    'bridge_1': ('jar','pom'), 'bridge_2': ('jar','pom'),
    'optional_dependency': ('jar','pom'), 'test_dependency': ('jar','pom'),
    'metadata_app': ('jar','pom','tests_jar'),
}
SNAPSHOT_FIXTURES = ('default_snapshot','snapshot_first','snapshot_second')
SNAPSHOT_STAGES = METADATA_STAGES[:-1] + ['snapshots'] + METADATA_STAGES[-1:]
SNAPSHOT_CASES = ['default_immutable','opt_in_redeploy','review_reset','fresh_resolution',
                  'held_replacement','disable_policy','restart','revocation']


def safe_ivy_contract(value, status):
    fields = {'profile','version','ant_version','ant_runtime_version','ant_legacy_runtime_version','java_version','ivy_distribution_sha512','ant_distribution_sha512',*IDENTITIES,
              'fixture_sha256','reference_sha256','wire_sha256','completed','checksum_clients_completed','phase','diagnostics'}
    snapshot = isinstance(value,dict) and value.get('profile') == 'maven-snapshots-v3'
    metadata = isinstance(value,dict) and value.get('profile') in {'maven-metadata-v2','maven-snapshots-v3'}
    if metadata: fields.add('metadata_cases_completed')
    if snapshot: fields.add('snapshot_cases_completed')
    if not isinstance(value,dict) or set(value) != fields:
        raise ValueError('Ivy fields are outside the reviewed profile')
    if value['profile'] not in {'maven-release-v1','maven-metadata-v2','maven-snapshots-v3'}:
        raise ValueError('Ivy profile must identify its exact release workflow')
    for field in ['version','ant_version']:
        if not isinstance(value[field],str) or not re.fullmatch(r'\d{1,2}\.\d{1,3}\.\d{1,3}',value[field]):
            raise ValueError('Ivy/Ant version must be a bounded release')
    observed = value['ant_runtime_version']
    if observed is not None and (not isinstance(observed,str) or not re.fullmatch(r'\d{1,2}\.\d{1,3}\.\d{1,3}',observed)):
        raise ValueError('Actual Ant runtime must be absent or a bounded observed version')
    if status == 'passed' and observed != value['ant_version']:
        raise ValueError('Passed Ivy evidence requires the exact observed Ant runtime')
    legacy = value['ant_legacy_runtime_version']
    if legacy is not None and (not isinstance(legacy,str) or not re.fullmatch(r'\d{1,2}\.\d{1,3}\.\d{1,3}',legacy)):
        raise ValueError('Legacy Ant observation must be absent or a bounded version')
    if not isinstance(value['java_version'],str) or not re.fullmatch(r'21\.\d{1,3}\.\d{1,3}\+\d{1,3}(?:-LTS)?',value['java_version']):
        raise ValueError('Ivy JDK must identify its actual build')
    for field in IDENTITIES + ['ivy_distribution_sha512','ant_distribution_sha512']:
        size = 128 if field.endswith('sha512') else 64
        if not isinstance(value[field],str) or not re.fullmatch('[0-9a-f]{'+str(size)+'}',value[field]):
            raise ValueError('Ivy tool identity must be a bounded digest')
    completed = value['completed']; diagnostics = value['diagnostics']
    stages = SNAPSHOT_STAGES if snapshot else METADATA_STAGES if metadata else STAGES
    if not isinstance(completed,list) or completed != stages[:len(completed)] or len(completed)>len(stages):
        raise ValueError('Ivy stages must be the ordered mandatory prefix')
    checksum_clients = value['checksum_clients_completed']
    if not isinstance(checksum_clients,list) or len(checksum_clients)>len(CHECKSUM_CLIENTS) or checksum_clients != CHECKSUM_CLIENTS[:len(checksum_clients)]:
        raise ValueError('Ivy checksum clients must be the ordered mandatory prefix')
    if status == 'passed' and checksum_clients != CHECKSUM_CLIENTS:
        raise ValueError('Passed Ivy evidence requires each native SHA-2 client resolution')
    if (len(completed)<2 and checksum_clients) or (len(completed)>=3 and checksum_clients != CHECKSUM_CLIENTS):
        raise ValueError('Ivy checksum-client observations disagree with completed review stages')
    if metadata:
        cases = value['metadata_cases_completed']
        if not isinstance(cases,list) or len(cases)>len(METADATA_CASES) or cases != METADATA_CASES[:len(cases)]:
            raise ValueError('Ivy metadata cases must be the ordered mandatory prefix')
        if (status == 'passed' or 'metadata' in completed) and cases != METADATA_CASES:
            raise ValueError('Passed Ivy metadata evidence requires every native metadata case')
        if len(completed)<6 and cases:
            raise ValueError('Metadata observations cannot precede the original policy/restart stages')
    if snapshot:
        cases = value['snapshot_cases_completed']
        if not isinstance(cases,list) or len(cases)>len(SNAPSHOT_CASES) or cases!=SNAPSHOT_CASES[:len(cases)]:
            raise ValueError('Ivy snapshot cases must be the mandatory ordered prefix')
        if (status=='passed' or 'snapshots' in completed) and cases!=SNAPSHOT_CASES:
            raise ValueError('Passed Ivy snapshot evidence requires every native case')
        if len(completed)<7 and cases:
            raise ValueError('Snapshot observations cannot precede the original metadata cases')
    if not isinstance(value['phase'],str) or value['phase'] not in (PHASES | {'metadata','snapshots'} if snapshot else PHASES | {'metadata'} if metadata else PHASES):
        raise ValueError('Ivy phase must use the fixed vocabulary')
    if not isinstance(diagnostics,list) or len(diagnostics)>len(DIAGNOSTICS) or any(not isinstance(c,str) or c not in DIAGNOSTICS for c in diagnostics) or len(set(diagnostics))!=len(diagnostics):
        raise ValueError('Ivy diagnostics must use the fixed vocabulary')
    allowed = {name+'_'+ext for name in FIXTURES for ext in ['jar','pom']}
    if metadata:
        allowed |= {name+'_'+ext for name,extensions in METADATA_REPRESENTATIONS.items() for ext in extensions}
    if snapshot:
        allowed |= {name+'_'+ext for name in SNAPSHOT_FIXTURES for ext in ['jar','pom']}
    fixtures = value['fixture_sha256']
    if not isinstance(fixtures,dict) or not set(fixtures)<=allowed or any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v) for v in fixtures.values()):
        raise ValueError('Ivy fixture identity is outside the owned set')
    if snapshot and 'opt_in_redeploy' in value['snapshot_cases_completed']:
        if not {'snapshot_first_jar','snapshot_second_jar'}<=set(fixtures) or fixtures['snapshot_first_jar']==fixtures['snapshot_second_jar']:
            raise ValueError('Native snapshot redeployment must change the actual JAR bytes')
    for field in ['reference_sha256','wire_sha256']:
        observed = value[field]
        if not isinstance(observed,dict) or not set(observed)<=set(fixtures) or any(v!=fixtures[k] for k,v in observed.items()):
            raise ValueError('Ivy retained/HTTP bytes must match the publisher')
        if status=='passed' and set(observed)!=allowed:
            raise ValueError('Passed Ivy evidence requires every retained/HTTP representation')
    if status=='passed' and (value['phase']!='complete' or completed!=stages or set(fixtures)!=allowed or diagnostics):
        raise ValueError('Passed Ivy evidence requires all fixtures and stages')
    return {**value,**{k:dict(sorted(value[k].items())) for k in ['fixture_sha256','reference_sha256','wire_sha256']},'diagnostics':sorted(diagnostics)}
