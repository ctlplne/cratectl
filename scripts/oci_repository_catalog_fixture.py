# SPDX-License-Identifier: BUSL-1.1
"""Exercise authenticated hosted repository discovery over trusted TLS with stock ORAS."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import ssl
import threading
import urllib.request


def evaluate_oci_catalog(work, app, authority, oras, environment, call, api, restart, sha, *, cached=False):
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
        _, output = call('oci-catalog-' + label, oras, *operation, '--plain-http=false', '--ca-file', trust,
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

    primary_payload, primary_manifest, primary_graph = publish('first', 'admin', first, b'Owned first tenant OCI bytes.\n')
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
    report = {'oras': '1.3.6', 'oras_sha256': sha(oras), 'checks': checks,
              'manifest_sha256': [primary_manifest, other_manifest, reviewed_manifest],
              'payload_sha256': [primary_payload, other_payload]}
    if cached:
        report['cached'] = evaluate_cached_catalog(scope, registry, primary_graph, primary_manifest, primary_payload,
                                                   native, listing, add_repo, api, restart, sha)
    return report


@contextmanager
def cached_catalog_origin(objects):
    class Origin(ThreadingHTTPServer):
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requests.append(self.path)
            item = objects.get(self.path)
            if item is None:
                self.send_error(404)
                return
            digest, media, content = item
            self.send_response(200)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Content-Type', media)
            self.send_header('Docker-Content-Digest', digest)
            self.send_header('Cache-Control', 'max-age=180')
            self.end_headers()
            self.wfile.write(content)

    requests = []
    with Origin(('::1', 38443), Handler) as origin:
        thread = threading.Thread(target=origin.serve_forever, name='cratectl-oci-catalog-origin')
        thread.start()
        try:
            yield requests
        finally:
            origin.shutdown()
            thread.join(5)
            if thread.is_alive():
                raise ValueError('owned OCI catalog origin did not stop')


def evaluate_cached_catalog(scope, registry, graph, manifest_sha, payload_sha, native, listing, add_repo, api, restart, sha):
    repo = 'cratectl-discovery-cached'
    image = 'cached/app'
    endpoint = '/api/v1/repositories/' + repo
    base = '/v2/cratectl-discovery-origin/'
    path = base + image
    manifest = 'sha256:' + manifest_sha
    payload = 'sha256:' + payload_sha
    config = graph['config']
    if len(graph['layers']) != 1 or graph['layers'][0]['digest'] != payload or config['data'] != 'e30=':
        raise ValueError('stock ORAS wrote an unexpected controlled graph')
    source = scope / 'push-first'
    objects = {path + '/manifests/' + marker: (manifest, graph['mediaType'], (source / 'manifest.json').read_bytes())
               for marker in ('1.0.0', manifest)}
    objects.update({path + '/blobs/' + payload: (payload, 'text/plain', (source / 'payload.txt').read_bytes()),
                    path + '/blobs/' + config['digest']: (config['digest'], config['mediaType'], b'{}')})
    checks = []

    def check(name, condition):
        if not condition:
            raise ValueError(name)
        checks.append(name)

    def pull(stage):
        destination = scope / ('cached-pull-' + stage)
        destination.mkdir(mode=0o700)
        native('cached-pull-' + stage, 'reader', ('pull',), '--output', destination,
               registry + '/' + repo + '/' + image + '@' + manifest)
        return sha(destination / 'payload.txt') == payload_sha

    with cached_catalog_origin(objects) as requests:
        add_repo('cached', 'admin', repo, mode='proxy', settings={
            'upstream': {'url': 'http://[::1]:38443' + base, 'networks': ['::1/128']},
            'cache': {'fresh_seconds': 180, 'negative_seconds': 30}})

        def search(stage, expected):
            before = len(requests)
            result = listing('cached-' + stage, 'reader')
            return result == expected and len(requests) == before

        name = [repo + '/' + image]
        check('cold stock ORAS catalog does not enumerate or contact its proxy origin', search('cold', []) and not requests)
        check('stock ORAS retrieves an exact admitted graph from the controlled proxy',
              pull('cold') and path + '/blobs/' + payload in requests)
        check('stock ORAS catalog lists a fresh cached proxy graph without contacting its origin', search('warm', name))
        api('oci-cached-expire-layer', endpoint + '/cache', 'PUT', {'path': image + '/blobs/' + payload})
        check('an invalidated cached layer hides the name without contacting its origin', search('expired', []))
        check('an explicit stock ORAS pull revalidates the exact graph and restores catalog visibility',
              pull('refresh') and search('refreshed', name))
        api('oci-cached-deny-layer', endpoint + '/decisions', 'PUT',
            {'path': image + '/blobs/' + payload, 'digest': payload_sha, 'decision': 'denied'})
        check('current policy denial hides the cached proxy name without contacting its origin', search('denied', []))
        api('oci-cached-restore-layer', endpoint + '/decisions', 'PUT',
            {'path': image + '/blobs/' + payload, 'digest': payload_sha, 'decision': 'allowed'})
        restart()
        check('fresh cached catalog authority and exact bytes survive restart',
              search('restart', name) and pull('restart'))
        return {'checks': checks, 'manifest_sha256': manifest_sha, 'payload_sha256': payload_sha}
