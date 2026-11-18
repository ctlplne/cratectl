# SPDX-License-Identifier: BUSL-1.1
"""Exercise authenticated hosted repository discovery over trusted TLS with stock ORAS."""

import json
import ssl
import urllib.request


def evaluate_oci_catalog(work, app, authority, oras, environment, call, api, restart, sha):
    scope = work / 'oci-catalog'
    scope.mkdir(mode=0o700)
    registry = authority.removeprefix('https://')
    trust = app / 'ca.crt'
    admin = app / 'admin.token'
    public = 'cratectl-discovery-hosted'
    restricted = 'cratectl-discovery-review'
    first = public + '/nested/app'
    second = first + '/worker'
    reviewed = restricted + '/app'
    other_only = public + '/other-only'
    settings = {'format': 'oci', 'mode': 'hosted'}
    tenants = {'admin': (admin, app / 'client.json'), 'reader': (work / 'reader.token', work / 'reader.json'),
               'other': (work / 'other.token', work / 'other.json')}
    empty_config = scope / 'docker-config.json'
    empty_config.write_text('{"auths":{}}\n')
    env = {name: value for name, value in environment.items()
           if not name.startswith(('DOCKER_', 'ORAS_', 'GITHUB_')) and name not in ('GH_TOKEN', 'REGISTRY_AUTH_FILE')}
    checks = []

    def check(name, passed):
        if not passed:
            raise ValueError(name)
        checks.append(name)

    version = call('oci-catalog-oras-version', oras, 'version', environment=env)[1].splitlines()[0]
    if version.split() != ['Version:', '1.3.6']:
        raise ValueError('catalog evidence requires stock ORAS 1.3.6')

    def native(label, who, operation, *arguments, cwd=scope):
        _, output = call('oci-catalog-' + label, oras, *operation, '--ca-file', trust,
                         '--registry-config', empty_config, '--username', 'cratectl-' + who,
                         '--password-stdin', *arguments, cwd=cwd, environment=env,
                         input_text=tenants[who][0].read_text())
        return output

    def add_repo(label, who, name, **options):
        api('oci-catalog-repo-' + label, '/api/v1/repositories', 'POST',
            {**settings, **options, 'name': name}, config=tenants[who][1])

    add_repo('public', 'admin', public)
    add_repo('restricted', 'admin', restricted, access='restricted', require_review=True)
    add_repo('second-tenant', 'other', public)

    def publish(label, who, target, body):
        source = scope / ('push-' + label)
        source.mkdir(mode=0o700)
        payload = source / 'payload.txt'
        payload.write_bytes(body)
        manifest = source / 'manifest.json'
        native('publish-' + label, who, ('push',), '--export-manifest', manifest,
               registry + '/' + target + ':1.0.0', 'payload.txt:text/plain', cwd=source)
        return sha(payload), sha(manifest), json.loads(manifest.read_bytes())

    primary_payload, primary_manifest, _ = publish('first', 'admin', first, b'Owned first tenant OCI bytes.\n')
    publish('second', 'admin', second, b'Owned nested OCI discovery payload.\n')
    other_payload, other_manifest, _ = publish('other-same-coordinate', 'other', first, b'Owned second tenant OCI bytes.\n')
    publish('other-only', 'other', other_only, b'Visible only to the second tenant.\n')
    _, reviewed_manifest, graph = publish('review', 'admin', reviewed, b'Owned review-gated OCI bytes.\n')

    def listing(label, who, *options):
        return native('list-' + label, who, ('repo', 'ls'), *options, registry).splitlines()

    def grant(label, read):
        api('oci-catalog-grant-' + label, '/api/v1/repositories/' + restricted + '/grants', 'PUT',
            {'actor': 'cratectl-reader', 'read': read, 'write': False})

    def decide(label, kind, hex_digest, decision):
        api('oci-catalog-decision-' + label, '/api/v1/repositories/' + restricted + '/decisions', 'PUT',
            {'path': 'app/' + kind + '/sha256:' + hex_digest, 'digest': hex_digest, 'decision': decision})

    client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(trust))))

    def get_catalog_page():
        request = urllib.request.Request(authority + '/v2/_catalog',
            headers={'Authorization': 'Bearer ' + tenants['reader'][0].read_text().strip()})
        with client.open(request, timeout=5) as result:
            return json.loads(result.read(4096)), result.headers.get('Link', '')

    first_page, link = get_catalog_page()
    check('stock ORAS follows the server’s one-entry linked catalog pages in lexical order',
          first_page == {'repositories': [first]} and 'rel="next"' in link and listing('linked', 'reader') == [first, second])
    check('stock ORAS applies the exclusive full-name catalog cursor',
          listing('exclusive', 'reader', '--last', first) == [second])
    check('stock ORAS sees only the independently authenticated tenant’s names',
          listing('tenant', 'other') == [first, other_only] and primary_manifest != other_manifest)
    grant('allow', True)
    decide('root', 'manifests', reviewed_manifest, 'allowed')
    check('an approved manifest with unassessed dependencies stays out of the catalog',
          listing('pending-members', 'reader') == [first, second])
    members = {item['digest'].removeprefix('sha256:') for item in [graph['config'], *graph['layers']]}
    for n, digest in enumerate(sorted(members)):
        decide(f'member-{n}', 'blobs', digest, 'allowed')
    check('stock ORAS lists the review-gated name once its complete graph is allowed',
          listing('approved-graph', 'reader') == [first, second, reviewed])
    layer = graph['layers'][0]['digest'].removeprefix('sha256:')
    decide('deny-layer', 'blobs', layer, 'denied')
    check('stock ORAS catalog immediately omits a graph with a denied layer',
          listing('denied-graph', 'reader') == [first, second])
    decide('restore-layer', 'blobs', layer, 'allowed')
    grant('revoke', False)
    check('stock ORAS honors revocation of the restricted repository read grant',
          listing('revoked-grant', 'reader') == [first, second])

    restart()

    def pull(label, who, digest):
        destination = scope / ('pull-' + label)
        destination.mkdir(mode=0o700)
        native('pull-' + label, who, ('pull',), '--output', destination, registry + '/' + first + '@sha256:' + digest)
        return sha(destination / 'payload.txt')

    check('stock ORAS catalog and exact independent same-coordinate pulls recover after restart',
          listing('restart', 'reader') == [first, second] and pull('first', 'reader', primary_manifest) == primary_payload
          and pull('other', 'other', other_manifest) == other_payload and primary_payload != other_payload)

    api('oci-catalog-suspend', '/api/v1/repositories/' + public + '/state', 'PUT',
        {'action': 'suspend', 'expected_revision': 0, 'reason': 'Suspend the owned catalog fixture'})
    check('stock ORAS catalog excludes suspended repositories and retains the other tenant’s listings',
          listing('suspended', 'reader') == [] and listing('second-tenant-unchanged', 'other') == [first, other_only])
    return {'oras': '1.3.6', 'oras_sha256': sha(oras), 'checks': checks,
            'manifest_sha256': [primary_manifest, other_manifest, reviewed_manifest],
            'payload_sha256': [primary_payload, other_payload]}
