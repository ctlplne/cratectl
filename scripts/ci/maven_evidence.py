# SPDX-License-Identifier: BUSL-1.1
"""Reviewed native Maven warm-cache observations, separate from cold consumers."""
import re

STAGES = ['client_identity','initial_resolution','updated_resolution','restart']
FIRST = {'first_jar','first_pom','dependency_jar','dependency_pom'}
FIXTURES = FIRST | {'second_jar','second_pom'}
MAPS = ['publisher_sha256','reference_sha256','wire_sha256','local_sha256']


def safe_maven_cache_contract(value, status):
    fields = {'profile','version','distribution_sha512','completed','cache_reused',*MAPS}
    if not isinstance(value,dict) or set(value)!=fields or value['profile']!='unique-snapshot-warm-v1':
        raise ValueError('Maven cache fields are outside the reviewed profile')
    version=value['version'];distribution=value['distribution_sha512']
    if version is not None and (not isinstance(version,str) or not re.fullmatch(r'\d{1,2}\.\d{1,3}\.\d{1,3}',version)):
        raise ValueError('Actual Maven version must be a bounded release')
    if distribution is not None and (not isinstance(distribution,str) or not re.fullmatch('[0-9a-f]{128}',distribution)):
        raise ValueError('Maven distribution identity must be a SHA512 digest')
    completed=value['completed']
    if not isinstance(completed,list) or len(completed)>len(STAGES) or completed!=STAGES[:len(completed)]:
        raise ValueError('Maven cache stages must be the mandatory ordered prefix')
    if completed and (version is None or distribution is None):
        raise ValueError('Maven cache evidence requires its actual client identities')
    if type(value['cache_reused']) is not bool:
        raise ValueError('Maven cache reuse must be a boolean observation')
    publisher=value['publisher_sha256']
    for name in MAPS:
        observed=value[name]
        if not isinstance(observed,dict) or not set(observed)<=FIXTURES or any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v) for v in observed.values()):
            raise ValueError('Maven byte identities must be bounded owned representations')
        if name!=MAPS[0] and any(key not in publisher or digest!=publisher[key] for key,digest in observed.items()):
            raise ValueError('Maven reference, HTTP and local bytes must match the publisher')
        if observed and not completed:
            raise ValueError('Maven byte observations cannot precede client identity')
        if len(completed)>=2 and not FIRST<=set(observed):
            raise ValueError('Initial Maven resolution requires the complete snapshot and dependency')
        if len(completed)>=3 and set(observed)!=FIXTURES:
            raise ValueError('Updated Maven resolution requires every before/after byte identity')
    if len(completed)<2 and value['cache_reused']:
        raise ValueError('Maven cache reuse cannot precede initial resolution')
    if len(completed)>=3 and (not value['cache_reused'] or publisher['first_jar']==publisher['second_jar']):
        raise ValueError('Maven warm refresh requires changed JAR bytes in the retained cache')
    if status=='passed' and completed!=STAGES:
        raise ValueError('Passed Maven cache evidence requires all native stages')
    return {**value,**{name:dict(sorted(value[name].items())) for name in MAPS}}
