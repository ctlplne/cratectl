# SPDX-License-Identifier: BUSL-1.1
"""Reviewed owned Ivy fields, mandatory stages and publication byte binding."""
import re

FIXTURES = ('dependency','application_1','application_2','other_dependency','other_application_1','local_application_3')
STAGES = ['client_identity','publication','review_and_tenants','reader_publication_denied','proxy_group','policy_and_restart','revocation']
PHASES = {'client_identity','publication','review','proxy_group','policy','revocation','complete'}
DIAGNOSTICS = {'http_401','http_403','http_404','resolution','publication','fixture'}
IDENTITIES = ['java_launcher_sha256','java_release_sha256','ivy_launcher_sha256','ant_launcher_sha256','ant_library_sha256','fixture_source_sha256']


def safe_ivy_contract(value, status):
    fields = {'profile','version','ant_version','java_version','ivy_distribution_sha512','ant_distribution_sha512',*IDENTITIES,
              'fixture_sha256','reference_sha256','wire_sha256','completed','phase','diagnostics'}
    if not isinstance(value,dict) or set(value) != fields:
        raise ValueError('Ivy fields are outside the reviewed profile')
    if value['profile'] != 'maven-release-v1':
        raise ValueError('Ivy profile must identify its exact release workflow')
    for field in ['version','ant_version']:
        if not isinstance(value[field],str) or not re.fullmatch(r'\d{1,2}\.\d{1,3}\.\d{1,3}',value[field]):
            raise ValueError('Ivy/Ant version must be a bounded release')
    if not isinstance(value['java_version'],str) or not re.fullmatch(r'21\.\d{1,3}\.\d{1,3}\+\d{1,3}(?:-LTS)?',value['java_version']):
        raise ValueError('Ivy JDK must identify its actual build')
    for field in IDENTITIES + ['ivy_distribution_sha512','ant_distribution_sha512']:
        size = 128 if field.endswith('sha512') else 64
        if not isinstance(value[field],str) or not re.fullmatch('[0-9a-f]{'+str(size)+'}',value[field]):
            raise ValueError('Ivy tool identity must be a bounded digest')
    completed = value['completed']; diagnostics = value['diagnostics']
    if not isinstance(completed,list) or completed != STAGES[:len(completed)] or len(completed)>len(STAGES):
        raise ValueError('Ivy stages must be the ordered mandatory prefix')
    if not isinstance(value['phase'],str) or value['phase'] not in PHASES:
        raise ValueError('Ivy phase must use the fixed vocabulary')
    if not isinstance(diagnostics,list) or len(diagnostics)>len(DIAGNOSTICS) or any(not isinstance(c,str) or c not in DIAGNOSTICS for c in diagnostics) or len(set(diagnostics))!=len(diagnostics):
        raise ValueError('Ivy diagnostics must use the fixed vocabulary')
    allowed = {name+'_'+ext for name in FIXTURES for ext in ['jar','pom']}
    fixtures = value['fixture_sha256']
    if not isinstance(fixtures,dict) or not set(fixtures)<=allowed or any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v) for v in fixtures.values()):
        raise ValueError('Ivy fixture identity is outside the owned set')
    for field in ['reference_sha256','wire_sha256']:
        observed = value[field]
        if not isinstance(observed,dict) or not set(observed)<=set(fixtures) or any(v!=fixtures[k] for k,v in observed.items()):
            raise ValueError('Ivy retained/HTTP bytes must match the publisher')
        if status=='passed' and set(observed)!=allowed:
            raise ValueError('Passed Ivy evidence requires every retained/HTTP representation')
    if status=='passed' and (value['phase']!='complete' or completed!=STAGES or set(fixtures)!=allowed or diagnostics):
        raise ValueError('Passed Ivy evidence requires all fixtures and stages')
    return {**value,**{k:dict(sorted(value[k].items())) for k in ['fixture_sha256','reference_sha256','wire_sha256']},'diagnostics':sorted(diagnostics)}
