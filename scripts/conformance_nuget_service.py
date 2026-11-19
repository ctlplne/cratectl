# SPDX-License-Identifier: BUSL-1.1
"""Replay authorized service-index discovery with separate owned origin credentials."""

from collections import Counter
import json

from conformance_nuget_proxy import APPLICATION, ORIGIN

HOST = 'http://[::1]:38443'
INDEX = ORIGIN + 'service/v3/index.json'
PACKAGES = ORIGIN + 'service-files/'
INDEX_REF = 'cratectl-nuget-service-index'
PACKAGES_REF = 'cratectl-nuget-service-files'


def private_bindings(tenant, tokens):
    return {tenant + '/' + INDEX_REF: {'value': tokens['origin'], 'allowed_url': HOST + INDEX},
            tenant + '/' + PACKAGES_REF: {'value': tokens['npm-meta-origin'], 'allowed_url': HOST + PACKAGES}}


def nuget_service_index(h, files, requests, credentials, packages, package_path, restore, source_config):
    repo = 'cratectl-nuget-service'
    first, first_check = len(requests), len(h.checks)
    payload_paths = set()
    for name in packages:
        package = package_path(name)
        for part in (name.lower() + '/index.json', package, package + '.sha512'):
            files[PACKAGES + part] = files[ORIGIN + part]
            payload_paths.add(PACKAGES + part)

    def advertise(address):
        files[INDEX] = json.dumps({'version': '3.0.0', 'resources': [
            {'@id': address, '@type': ['PackageBaseAddress/3.0.0'], 'comment': 'owned flat-container fixture'}]}).encode()

    advertise(HOST + PACKAGES)
    credentials[INDEX] = 'Bearer ' + h.tokens['origin']
    credentials[PACKAGES] = 'Bearer ' + h.tokens['npm-meta-origin']
    h.repository(repo, 'nuget', mode='proxy', settings={
        'nuget_service_index': True,
        'upstream': {'url': HOST + INDEX, 'networks': ['::1/128'], 'credential_ref': INDEX_REF},
        'download_sources': [{'url': HOST + PACKAGES, 'networks': ['::1/128'], 'credential_ref': PACKAGES_REF}],
        'cache': {'fresh_seconds': 300, 'require_checksum': True}})
    config = source_config(repo)
    restore('authenticated-service-index', configfile=config)
    baseline = Counter({path: 1 for path in payload_paths})
    baseline[INDEX] = 4
    h.check('stock restore discovers the exact configured index and uses only the separately authenticated package authority',
            Counter(requests[first:]) == baseline)
    endpoint = f'/nuget/{repo}/flat/' + package_path(APPLICATION)
    advertise(HOST + ORIGIN + 'service-moved/')
    h.check('a changed service index blocks revalidation before any package or sidecar request',
            h.req(endpoint, 'reader', headers={'Cache-Control': 'no-cache'})[0] == 502 and requests[-1] == INDEX and
            len(requests) == first + sum(baseline.values()) + 1)
    advertise(HOST + PACKAGES)
    code, data, _ = h.req(endpoint, 'reader', headers={'Cache-Control': 'no-cache'})
    h.check('restored service-index authority revalidates exact bytes and checksum', code == 200 and data == packages[APPLICATION][0] and
            requests[-3:] == [INDEX, PACKAGES + package_path(APPLICATION), PACKAGES + package_path(APPLICATION) + '.sha512'])
    count = len(requests)
    h.stop()
    h.start()
    restore('service-index-warm-restart', configfile=config)
    h.check('warm service-index restore survives restart without additional origin requests', len(requests) == count)
    h.result['nuget_service_index'] = {'checks': len(h.checks) - first_check, 'origin_requests': count - first,
                                       'separate_credentials_verified': True}
