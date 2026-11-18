# SPDX-License-Identifier: BUSL-1.1
"""Replay stock Cargo through a controlled authenticated sparse upstream."""
from contextlib import contextmanager
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import ssl
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from cargo_hosted_fixture import (BASE_PACKAGE, REPOSITORY, ROOT_PACKAGE, VERSION,
                                  cargo_home, new_project, stock_cargo_environment)


INDEX_PATH = '/cratectl-cargo-origin/index/'
DOWNLOAD_PATH = '/cratectl-cargo-origin/download/'
INDEX_ORIGIN = 'http://[::1]:38443' + INDEX_PATH
DOWNLOAD_ORIGIN = 'http://[::1]:38443' + DOWNLOAD_PATH
PROXY = 'cratectl-cargo-proxy'
CHECKSUM_PROXY = 'cratectl-cargo-checksum'
SHORT_PROXY = 'cratectl-cargo-short'
STALE_PROXY = 'cratectl-cargo-stale'


def index_file(name):
    return '/'.join((name[:2], name[2:4], name))


def download_file(name):
    return f'{name}/{VERSION}'


@contextmanager
def origin_server(credentials, contents):
    class Origin(ThreadingHTTPServer):
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            label = 'index' if self.path.startswith(INDEX_PATH) else 'download'
            token = self.headers.get('Authorization', '')
            current = self.headers.get('If-None-Match', '')
            admitted = hmac.compare_digest(token, credentials[label]) or (
                packaging.is_set() and hmac.compare_digest(token, credentials['index']))
            with lock:
                requests.append((self.path, admitted, bool(current)))
                body = contents.get(self.path)
                is_interrupted = self.path in interrupted
                is_offline = offline.is_set()
            code = 503 if is_offline else 401 if not admitted else 404 if body is None else 200
            tag = ''
            if code == 200:
                tag = '"' + hashlib.sha256(body).hexdigest() + '"'
                if current == tag:
                    code = 304
            response = body if code == 200 else b''
            self.send_response(code)
            if tag:
                self.send_header('ETag', tag)
            self.send_header('Cache-Control', 'max-age=300')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response[:len(response)//2] if is_interrupted else response)

    requests = []
    lock = threading.Lock()
    offline = threading.Event()
    packaging = threading.Event()
    interrupted = set()
    with Origin(('::1', 38443), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, name='cratectl-cargo-origin')
        thread.start()
        try:
            yield requests, lock, offline, packaging, interrupted
        finally:
            server.shutdown()
            thread.join(5)
            if thread.is_alive():
                raise ValueError('owned Cargo origin did not shut down')


def evaluate_proxy(work, installation, authority, toolchain, environment, call, api, restart, sha, credentials):
    cargo = toolchain / 'cargo'
    shared = stock_cargo_environment(installation, toolchain / 'rustc', environment)
    admin = (installation / 'admin.token').read_text().strip()
    reader = (work / 'reader.token').read_text().strip()
    other = (work / 'other.token').read_text().strip()
    trust = ssl.create_default_context(cafile=str(installation / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))
    checks = []

    def check(label, ok):
        if not ok:
            raise ValueError(label)
        checks.append(label)

    def registry(repo):
        return authority + '/cargo/' + repo

    def management(repo, suffix=''):
        return '/api/v1/repositories/' + repo + suffix

    def request(repo, part, token=reader, refresh=False):
        headers = {} if token is None else {'Authorization': token}
        if refresh:
            headers['Cache-Control'] = 'no-cache'
        req = urllib.request.Request(registry(repo) + part, headers=headers)
        try:
            with opener.open(req, timeout=12) as result:
                body = result.read((1 << 20) + 1)
                if len(body) > 1 << 20:
                    raise ValueError('Cargo proxy fixture response exceeds its byte budget')
                return result.status, body, result.headers
        except urllib.error.HTTPError as err:
            err.close()
            return err.code, b'', err.headers

    def grant(repo, label, read):
        api('cargo-proxy-grant-' + label, management(repo, '/grants'), 'PUT',
            {'actor': 'cratectl-reader', 'read': read, 'write': False})

    settings = {
        'upstream': {'url': INDEX_ORIGIN, 'networks': ['::1/128'], 'authentication': 'cargo-token',
                     'credential_ref': 'cratectl-cargo-index'},
        'download_sources': [{'url': DOWNLOAD_ORIGIN, 'networks': ['::1/128'], 'authentication': 'cargo-token',
                              'credential_ref': 'cratectl-cargo-download'}],
        'cache': {'fresh_seconds': 300, 'negative_seconds': 30, 'stale_seconds': 0},
    }
    for label, repo in (('main', PROXY), ('checksum', CHECKSUM_PROXY), ('short', SHORT_PROXY), ('stale', STALE_PROXY)):
        selected = settings
        if repo == STALE_PROXY:
            selected = {**settings, 'cache': {**settings['cache'], 'fresh_seconds': 0, 'stale_seconds': 60}}
        api('cargo-proxy-create-' + label, '/api/v1/repositories', 'POST',
            {'name': repo, 'format': 'cargo', 'mode': 'proxy', 'access': 'restricted',
             'require_review': repo == CHECKSUM_PROXY, 'settings': selected})
        grant(repo, label, True)

    metadata, archives, contents = {}, {}, {}
    for name in (ROOT_PACKAGE, BASE_PACKAGE):
        status, body, _ = request(REPOSITORY, '/index/' + index_file(name), admin)
        if status != 200:
            raise ValueError('the owned Cargo origin needs the original stock index')
        metadata[name], = (row for line in body.splitlines() if (row := json.loads(line))['vers'] == VERSION)
        metadata[name]['yanked'] = False
        status, archives[name], _ = request(REPOSITORY, '/download/' + download_file(name), admin)
        if status != 200 or hashlib.sha256(archives[name]).hexdigest() != metadata[name]['cksum']:
            raise ValueError('the owned Cargo origin needs the original stock archive')
        contents[INDEX_PATH + index_file(name)] = json.dumps(metadata[name]).encode() + b'\n'
        contents[DOWNLOAD_PATH + download_file(name)] = archives[name]
    contents[INDEX_PATH + 'config.json'] = json.dumps({'dl': DOWNLOAD_ORIGIN + '{crate}/{version}',
                                                       'auth-required': True}).encode()
    index = '/index/' + index_file(ROOT_PACKAGE)
    package = '/download/' + download_file(ROOT_PACKAGE)

    def stock(label):
        project = work / ('cargo-proxy-project-' + label)
        new_project(project, 'cratectl-proxy-consumer', '\n[dependencies]\n' + ROOT_PACKAGE +
                    ' = {version = "=1.0.0", registry = "cratectl", features = ["wire"]}\n')
        cache, env = cargo_home(work, 'cargo-proxy-home-' + label, 'sparse+' + registry(PROXY) + '/index/', shared, reader)
        call('cargo-proxy-stock-fetch-' + label, cargo, 'fetch', cwd=project, environment=env, timeout=45)
        return sorted(sha(item) for item in (cache / 'registry/cache').glob('*/*.crate'))

    with origin_server(credentials, contents) as (requests, lock, offline, packaging, interrupted):
        # Cargo records the source registry in its normalized dependency table.
        # Produce this root for the actual controlled origin while preserving the
        # original stock leaf and the original resolution graph.
        project = work / 'cargo-proxy-origin-root'
        new_project(project, ROOT_PACKAGE, '\n[dependencies]\nfixture-leaf = {package = "' + BASE_PACKAGE +
                    '", version = "1.0", registry = "cratectl", optional = true, default-features = false, features = ["wire"]}\n'
                    '[features]\nwire = ["dep:fixture-leaf"]\n')
        _, producer = cargo_home(work, 'cargo-proxy-origin-home', 'sparse+' + INDEX_ORIGIN,
                                 dict(shared, NO_PROXY='127.0.0.1,::1', no_proxy='127.0.0.1,::1'), credentials['index'])
        def package_for_origin(label):
            target = work / ('cargo-proxy-origin-target-' + label)
            packaging.set()
            try:
                call('cargo-proxy-stock-package-' + label, cargo, 'package', '--registry', 'cratectl',
                     '--allow-dirty', '--no-verify', '--exclude-lockfile', cwd=project,
                     environment=dict(producer, CARGO_TARGET_DIR=str(target)), timeout=45)
            finally:
                packaging.clear()
            return target / 'package' / (ROOT_PACKAGE + '-' + VERSION + '.crate')

        original = package_for_origin('original')
        archives[ROOT_PACKAGE] = original.read_bytes()
        metadata[ROOT_PACKAGE]['cksum'] = sha(original)
        with lock:
            contents[INDEX_PATH + index_file(ROOT_PACKAGE)] = json.dumps(metadata[ROOT_PACKAGE]).encode() + b'\n'
            contents[DOWNLOAD_PATH + download_file(ROOT_PACKAGE)] = archives[ROOT_PACKAGE]
            requests.clear()
        expected = sorted(row['cksum'] for row in metadata.values())

        status, config, _ = request(PROXY, '/index/config.json')
        check('Cargo proxy config publishes only its own authenticated sparse authority',
              request(PROXY, '/index/config.json', None)[0] == 401 and status == 200 and
              json.loads(config) == {'dl': registry(PROXY) + '/download/{crate}/{version}', 'auth-required': True})
        check('fresh stock Cargo proxies a transitive graph and both original archives', stock('cold') == expected)
        with lock:
            observed = tuple(requests)
        check('configured index and download credentials remain bound to separate upstream paths',
              len(observed) == 6 and all(admitted for _, admitted, _ in observed)
              and all(any(path == prefix + name for path, _, _ in observed)
                      for prefix, name in ((INDEX_PATH, 'config.json'), (DOWNLOAD_PATH, download_file(ROOT_PACKAGE)),
                                           (DOWNLOAD_PATH, download_file(BASE_PACKAGE)))))
        status, body, response_headers = request(PROXY, package, refresh=True)
        with lock:
            conditional = [(p, accepted, validator) for p, accepted, validator in requests if validator]
        check('conditional sparse and archive validation preserves the original bytes',
              status == 200 and body == archives[ROOT_PACKAGE] and response_headers.get('X-Cratectl-Cache') == 'revalidated'
              and conditional == [(INDEX_PATH + index_file(ROOT_PACKAGE), True, True),
                                  (DOWNLOAD_PATH + download_file(ROOT_PACKAGE), True, True)])

        offline.set()
        with lock:
            request_count = len(requests)
        restart()
        check('fresh stock Cargo recovers both exact cached bytes across restart during upstream outage',
              stock('cached') == expected and len(requests) == request_count)
        offline.clear()

        api('cargo-proxy-review', management(PROXY, '/policy'), 'PUT', {'require_review': True})
        check('current review hides an upstream checksum pending local authorization',
              request(PROXY, index)[0] == 404 and request(PROXY, package)[0] == 403)
        reference = {'path': 'crates/' + ROOT_PACKAGE + '/' + VERSION + '.crate', 'digest': metadata[ROOT_PACKAGE]['cksum']}
        leaf = {'path': 'crates/' + BASE_PACKAGE + '/' + VERSION + '.crate', 'digest': metadata[BASE_PACKAGE]['cksum']}
        for label, artifact in (('root', reference), ('leaf', leaf)):
            api('cargo-proxy-approve-' + label, management(PROXY, '/decisions'), 'PUT', {**artifact, 'decision': 'allowed'})
        check('local approval restores stock Cargo discovery and exact byte delivery', stock('approved') == expected)

        lifecycle = management(PROXY, '/artifacts/lifecycle')
        api('cargo-proxy-delete', lifecycle, 'PUT', {**reference, 'action': 'delete', 'expected_revision': 0,
                                                  'reason': 'Retire a cached Cargo reference'})
        check('retired proxy reference blocks discovery and delivery even when a cache fill is requested',
              request(PROXY, index, refresh=True)[0] == request(PROXY, package, refresh=True)[0] == 404)
        api('cargo-proxy-restore', lifecycle, 'PUT', {**reference, 'action': 'restore', 'expected_revision': 1,
                                                   'reason': 'Restore the original cached Cargo data'})
        check('proxy reference restoration retains the exact locally approved archive',
              request(PROXY, package)[1] == archives[ROOT_PACKAGE])

        original = contents[DOWNLOAD_PATH + download_file(ROOT_PACKAGE)]
        with lock:
            contents[DOWNLOAD_PATH + download_file(ROOT_PACKAGE)] = b'owned invalid package bytes'
        refused, _, headers = request(CHECKSUM_PROXY, package)
        indexed = api('cargo-proxy-checksum-retained', management(CHECKSUM_PROXY, '/artifacts'))['items']
        check('a download checksum mismatch leaves no materialized package reference',
              refused == 502 and headers.get('X-Checksum-Sha256') is None
              and all(item['path'] != reference['path'] for item in indexed))
        with lock:
            contents[DOWNLOAD_PATH + download_file(ROOT_PACKAGE)] = original
        pending, _, headers = request(CHECKSUM_PROXY, package, refresh=True)
        cached = api('cargo-proxy-stage-retained', management(CHECKSUM_PROXY, '/artifacts'))['items']
        check('retry stages the original archive after checksum failure and still requires local approval',
              pending == 403 and headers.get('X-Checksum-Sha256') is None
              and any(item['path'] == reference['path'] and item['digest'] == reference['digest'] for item in cached)
              and request(CHECKSUM_PROXY, index)[0] == 404)
        api('cargo-proxy-approve-retry', management(CHECKSUM_PROXY, '/decisions'), 'PUT',
            {**reference, 'decision': 'allowed'})
        if request(CHECKSUM_PROXY, package)[1] != original:
            raise ValueError('approved cold proxy reference did not return the staged bytes')

        path = INDEX_PATH + index_file(ROOT_PACKAGE)
        with lock:
            old_index = contents[path]
            contents[path] = json.dumps({**metadata[ROOT_PACKAGE], 'cksum': 'c' * 64}).encode() + b'\n'
        check('an upstream coordinate change refuses the entire refreshed index and its download',
              request(PROXY, index, refresh=True)[0] == request(PROXY, package)[0] == 502)
        with lock:
            contents[path] = json.dumps({**metadata[ROOT_PACKAGE], 'yanked': True}).encode() + b'\n'
        status, yanked_index, _ = request(PROXY, index, refresh=True)
        check('upstream yank changes discovery while the same exact pinned bytes remain deliverable',
              status == 200 and json.loads(yanked_index)['yanked'] and request(PROXY, package)[1] == original)
        with lock:
            contents[path] = old_index

        # A zero-freshness origin response admits the request that validated it.
        # A later transient outage may use only the separately configured stale window.
        status, body, _ = request(STALE_PROXY, package)
        check('zero-freshness validation admits the request that filled both Cargo cache entries',
              status == 200 and body == archives[ROOT_PACKAGE])
        offline.set()
        status, body, headers = request(STALE_PROXY, package)
        offline.clear()
        check('a transient origin failure can serve the exact revision-bound Cargo bytes within its stale window',
              status == 200 and body == archives[ROOT_PACKAGE] and headers.get('X-Cratectl-Cache') == 'stale')
        with lock:
            contents[path] = json.dumps({**metadata[ROOT_PACKAGE], 'cksum': 'b' * 64}).encode() + b'\n'
        check('a source binding conflict refuses stale Cargo bytes even within the configured window',
              request(STALE_PROXY, package, refresh=True)[0] == 502)
        with lock:
            contents[path] = old_index

        download_path = DOWNLOAD_PATH + download_file(ROOT_PACKAGE)
        with lock:
            interrupted.add(download_path)
        status, _, headers = request(SHORT_PROXY, package)
        partial = api('cargo-proxy-short-retained', management(SHORT_PROXY, '/artifacts'))['items']
        check('an interrupted origin transfer leaves no materialized Cargo archive',
              status == 502 and headers.get('X-Checksum-Sha256') is None
              and all(item['path'] != reference['path'] for item in partial))
        with lock:
            interrupted.remove(download_path)
        check('the exact Cargo archive can be retrieved after an interrupted origin transfer',
              request(SHORT_PROXY, package, refresh=True)[1] == archives[ROOT_PACKAGE])

        # Once the lower leaf has a retained metadata projection in SHORT_PROXY,
        # the contenders should join one genuine archive retrieval in PostgreSQL.
        lower_index = '/index/' + index_file(BASE_PACKAGE)
        lower_download = '/download/' + download_file(BASE_PACKAGE)
        if request(SHORT_PROXY, lower_index)[0] != 200:
            raise ValueError('could not warm the Cargo concurrency metadata')
        with lock:
            before = len(requests)
        with ThreadPoolExecutor(max_workers=6) as pool:
            replies = list(pool.map(lambda _: request(SHORT_PROXY, lower_download), range(6)))
        with lock:
            new_requests = requests[before:]
        check('concurrent Cargo cache misses consume one upstream archive transfer',
              all(status == 200 and data == archives[BASE_PACKAGE] for status, data, _ in replies)
              and new_requests == [(DOWNLOAD_PATH + download_file(BASE_PACKAGE), True, False)])

        (project / 'src/lib.rs').write_text('// Owned source bytes for the second authority revision.\n')
        revised = package_for_origin('new-revision')
        revised_data = revised.read_bytes()
        revised_digest = sha(revised)
        with lock:
            contents[path] = json.dumps({**metadata[ROOT_PACKAGE], 'cksum': revised_digest}).encode() + b'\n'
            contents[download_path] = revised_data
            before = len(requests)
        changed = api('cargo-proxy-new-revision', management(PROXY, '/configuration'), 'PUT',
                      {'settings': settings, 'expected_revision': 0, 'reason': 'Review the revised owned Cargo source'})
        pending, _, headers = request(PROXY, package)
        with lock:
            new_requests = requests[before:]
        check('advancing the Cargo source revision clears inherited validators and requires a new exact-digest decision',
              revised_digest != reference['digest'] and changed['current']['source_revision'] == 1
              and pending == 403 and headers.get('X-Checksum-Sha256') is None and request(PROXY, index)[0] == 404
              and new_requests == [(path, True, False), (INDEX_PATH+'config.json', True, False), (download_path, True, False)])
        api('cargo-proxy-approve-revised', management(PROXY, '/decisions'), 'PUT',
            {**reference, 'digest': revised_digest, 'decision': 'allowed'})
        check('fresh stock Cargo resolves the new approved source revision and exact leaf',
              stock('revised-source') == sorted((revised_digest, metadata[BASE_PACKAGE]['cksum'])))

        grant(PROXY, 'revoke', False)
        check('current grants and tenant isolation fence a previously filled Cargo proxy',
              request(PROXY, package)[0] == 403 and request(PROXY, index)[0] == 403 and
              request(PROXY, package, other)[0] == 404)

    return {'checks': checks, 'archive_sha256': {'proxy-root': metadata[ROOT_PACKAGE]['cksum'],
                                               'proxy-leaf': metadata[BASE_PACKAGE]['cksum'],
                                               'proxy-revised-root': revised_digest}}
