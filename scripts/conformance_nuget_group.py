# SPDX-License-Identifier: BUSL-1.1
"""Stock dependency restore across a preferred proxy and a hosted NuGet member."""

import hashlib
import uuid

from conformance_nuget_proxy import APPLICATION, DEPENDENCY, ORIGIN, VERSION, inert_package


def nuget_group(h, files, requests, packages, package_path, restore, source_config):
    prefix = ORIGIN + 'group/'
    first = len(requests)
    first_check = len(h.checks)
    application_path = ORIGIN + package_path(APPLICATION)
    application_index = APPLICATION.lower() + '/index.json'
    dependency_index = DEPENDENCY.lower() + '/index.json'
    files.update({prefix + application_index: files[ORIGIN + application_index],
                  prefix + package_path(APPLICATION): files[application_path],
                  prefix + package_path(APPLICATION) + '.sha512': files[application_path + '.sha512']})
    preferred, lower = 'cratectl-nuget-preferred', 'cratectl-nuget-lower'
    group, owned = 'cratectl-nuget-group', 'cratectl-nuget-owner-group'
    lower_app = inert_package(APPLICATION, DEPENDENCY, ' from the hosted member')
    hosted = {APPLICATION: lower_app, DEPENDENCY: packages[DEPENDENCY]}

    def mutate(repo, path, data):
        return h.req(f'/api/v1/repositories/{repo}/' + path, method='PUT', data=data, key=uuid.uuid4().hex)[0]

    def decide(repo, package_id, data, decision):
        digest = hashlib.sha256(data).hexdigest()
        return mutate(repo, 'decisions', {'path': f'nuget-packages/{package_id.lower()}/{VERSION}.nupkg',
                                          'digest': digest, 'decision': decision})

    def publish(package_id):
        data = hosted[package_id][0]
        boundary = 'cratectl-nuget-group-' + uuid.uuid4().hex
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="package"; filename="owned.nupkg"\r\n'
                'Content-Type: application/octet-stream\r\n\r\n').encode() + data + f'\r\n--{boundary}--\r\n'.encode()
        code, _, _ = h.req(f'/nuget/{lower}/api/v2/package', method='PUT', data=body,
                           headers={'Content-Type': 'multipart/form-data; boundary=' + boundary,
                                    'X-NuGet-ApiKey': h.tokens['admin']})
        h.check('publish the lower hosted package ' + package_id, code == 201 and decide(lower, package_id, data, 'allowed') == 200)

    h.repository(preferred, 'nuget', mode='proxy', access='restricted', settings={
        'upstream': {'url': 'http://[::1]:38443' + prefix, 'networks': ['::1/128']},
        'cache': {'fresh_seconds': 300, 'negative_seconds': 300, 'require_checksum': True}})
    h.repository(lower, 'nuget')
    publish(APPLICATION)
    publish(DEPENDENCY)
    members = [preferred, lower]
    h.repository(group, 'nuget', review=True, mode='group', settings={'members': members})
    h.repository(owned, 'nuget', mode='group', settings={
        'members': members, 'namespace_owners': {APPLICATION.lower() + '/': lower}})
    config, owner_config = source_config(group), source_config(owned)
    flat = f'/nuget/{group}/flat/'
    h.check('an ungranted preferred NuGet source blocks the group before origin routing',
            h.req(flat + application_index, 'reader')[0] == 403 and len(requests) == first)
    h.check('grant access to the consulted NuGet member', mutate(preferred, 'grants', {'actor': 'reader', 'read': True}) == 200)
    h.check('the group stages the preferred archive for exact review',
            h.req(flat + package_path(APPLICATION), 'reader')[0] == 403 and
            decide(preferred, APPLICATION, packages[APPLICATION][0], 'allowed') == 200)
    restore('group-preferred-proxy', configfile=config)
    delta = requests[first:]
    expected = {prefix + application_index, prefix + package_path(APPLICATION),
                prefix + package_path(APPLICATION) + '.sha512', prefix + dependency_index}
    h.check('ordered group uses one current missing dependency catalog and exact preferred proxy bytes',
            set(delta) == expected and len(delta) == len(expected))
    h.check('higher priority denial removes the app while lower hosted bytes remain available directly',
            decide(preferred, APPLICATION, packages[APPLICATION][0], 'denied') == 200 and
            h.req(flat + application_index, 'reader')[0] == 404 and
            h.req(f'/nuget/{lower}/flat/' + package_path(APPLICATION), 'reader')[1] == lower_app[0])
    restore('group-preferred-denied', allowed=False, configfile=config)
    restore('group-namespace-owner', configfile=owner_config, expected=hosted)
    h.check('the preferred exact digest can be approved again', decide(preferred, APPLICATION, packages[APPLICATION][0], 'allowed') == 200)
    h.stop()
    h.start()
    restore('group-restarted', configfile=config)
    h.check('warm group restores reuse the exact authorities after restart', len(requests) == first + len(expected))
    h.result['nuget_group'] = {'checks': len(h.checks) - first_check, 'origin_requests': len(expected),
                              'preferred_application_sha256': hashlib.sha256(packages[APPLICATION][0]).hexdigest(),
                              'hosted_application_sha256': hashlib.sha256(lower_app[0]).hexdigest(),
                              'hosted_dependency_sha256': hashlib.sha256(packages[DEPENDENCY][0]).hexdigest()}
