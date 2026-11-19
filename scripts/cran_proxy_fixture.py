# SPDX-License-Identifier: BUSL-1.1
"""Replay stock R source discovery and exact downloads through an owned proxy."""

import gzip
import hashlib

from cargo_proxy_fixture import origin_server
from cran_group_fixture import DENIAL_CLIENT, GROUP_CLIENT
from cran_hosted_fixture import APP, DEPENDENCY, LATEST, SELECTED_LIBRARY, filename, make_archive

REPOSITORY = 'cratectl-cran-checksum-proxy'
ORIGIN_PREFIX = '/cratectl-cran-origin/'
ORIGIN = 'http://[::1]:38443' + ORIGIN_PREFIX
ORIGIN_CREDENTIAL = 'cratectl-cran-origin'
INDEX_PATH = ORIGIN_PREFIX + 'src/contrib/PACKAGES'
REPLACEMENT = 'owned changed origin artifact'


def evaluate_cran_proxy(work, authority, stock, environment, request, api, call, restart, sha, credential):
    scope = work / REPOSITORY
    scope.mkdir(mode=0o700)
    reader = scope / 'cratectl-fetch-proxy.R'
    reader.write_text(GROUP_CLIENT)
    denial = scope / 'cratectl-deny-proxy.R'
    denial.write_text(DENIAL_CLIENT)
    root = authority + '/cran/' + REPOSITORY
    base = '/api/v1/repositories'
    management = base + '/' + REPOSITORY
    native = root + '/src/contrib/'
    checks = []

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    def row(coordinate, variant='original'):
        data = make_archive(coordinate, variant=variant)
        digest = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
        file = filename(coordinate)
        imports = f'Imports: {DEPENDENCY} (>= 2.2-0)\n' if coordinate[0] == APP else ''
        dcf = (f'Package: {coordinate[0]}\nVersion: {coordinate[1]}\nLicense: MIT\nNeedsCompilation: no\n'
               f'{imports}MD5sum: {md5}\nSHA256sum: {digest}\n').encode()
        return {'file': file, 'digest': digest, 'md5': md5, 'bytes': data, 'dcf': dcf, 'locator': f'sha256/{digest}/{file}'}

    graph = (LATEST, SELECTED_LIBRARY)
    rows = {coordinate: row(coordinate) for coordinate in graph}
    app, library = (rows[coordinate] for coordinate in graph)
    changed = row(LATEST, REPLACEMENT)
    archives = {entry['file']: entry['digest'] for entry in rows.values()}
    catalog = b'\n'.join(entry['dcf'] for entry in rows.values())
    contents = {INDEX_PATH: catalog, **{ORIGIN_PREFIX + 'src/contrib/' + entry['file']: entry['bytes'] for entry in rows.values()}}
    api('cran-proxy-create', base, 'POST', {'name': REPOSITORY, 'format': 'cran', 'mode': 'proxy',
                                           'access': 'restricted', 'require_review': True,
                                           'settings': {'upstream': {'url': ORIGIN, 'networks': ['::1/128'],
                                                                      'credential_ref': ORIGIN_CREDENTIAL},
                                                        'cache': {'fresh_seconds': 300, 'negative_seconds': 30}}})

    def get(relative, actor='reader', *, refresh=False):
        return request(relative, actor, repository=REPOSITORY, force=refresh)

    def decide(label, entry, decision):
        api('cran-proxy-review-' + label, management + '/decisions', 'PUT',
            {'path': 'src/contrib/' + entry['locator'], 'digest': entry['digest'], 'decision': decision})

    def consume(label, *, denied=False):
        target = scope / label
        target.mkdir(mode=0o700)
        env = environment(target)
        env.update(CRATECTL_CRAN_REPOSITORY=root, CRATECTL_CRAN_READER=str(work / 'reader.token'),
                   CRATECTL_CRAN_DOWNLOADS=str(target), CRATECTL_CRAN_REFUSED=native + app['locator'] if denied else '')
        _, output = call('cran-proxy-stock-' + label, *stock, '--file=' + str(denial if denied else reader), cwd=target,
                         environment=env, timeout=45)
        if denied:
            refused = target / 'denied.tar.gz'
            return 'cratectl-group-denied' in output.splitlines() and (not refused.exists() or refused.stat().st_size == 0)
        selected = {tuple(line.split('\t')[1:]) for line in output.splitlines() if line.startswith('cratectl-selected\t')}
        selected_origins = {tuple(line.split('\t')[1:]) for line in output.splitlines() if line.startswith('cratectl-group-repository\t')}
        expected = {(*coordinate, entry['md5']) for coordinate, entry in rows.items()}
        source_urls = {(coordinate[0], native + 'sha256/' + entry['digest']) for coordinate, entry in rows.items()}
        return (selected == expected and selected_origins == source_urls
                and {p.name: sha(p) for p in target.glob('*.tar.gz')} == archives)

    auth = 'Bearer ' + credential
    with origin_server({'index': auth, 'download': auth}, contents, index_path=INDEX_PATH, name='cratectl-cran-origin') as controls:
        requests, lock, offline, _, _ = controls
        check('CRAN proxy checks tenant and repository authorization before reading the origin',
              get('PACKAGES')[0] == 403 and get('PACKAGES', 'other')[0] == 404 and not requests)
        api('cran-proxy-grant', management + '/grants', 'PUT', {'actor': 'cratectl-reader', 'read': True, 'write': False})
        check('unreviewed CRAN proxy bytes are retained privately and the native index remains empty',
              get(app['file'])[0] == 404 and get('PACKAGES')[:2] == (200, b'')
              and all(get(entry['locator'])[0] == 403 for entry in rows.values()))
        with lock:
            original = list(requests)
        check('the configured origin credential is scoped to the exact catalog and two archive requests',
              original == [(INDEX_PATH, True, False), *[(ORIGIN_PREFIX + 'src/contrib/' + entry['file'], True, False)
                                                        for entry in rows.values()]])
        for index, entry in enumerate(rows.values()):
            decide(str(index), entry, 'allowed')
        status, plain, _ = get('PACKAGES')
        compressed_status, compressed, _ = get('PACKAGES.gz')
        check('approved CRAN proxy indexes expose only their local exact archive paths',
              status == compressed_status == 200 and gzip.decompress(compressed) == plain
              and all(('Path: sha256/' + entry['digest']).encode() in plain for entry in rows.values())
              and ORIGIN.encode() not in plain)
        check('stock R downloads the original application and dependency through the CRAN proxy', consume('first'))
        offline.set()
        restart()
        check('stock R fetches the same proxy graph after restart while the origin is offline', consume('after-restart'))
        check('warm CRAN discovery and exact downloads make no additional origin requests', requests == original)
        decide('denied', app, 'denied')
        plain = get('PACKAGES')[1]
        check('current digest denial removes the app and refuses its cached exact path',
              APP.encode() not in plain and DEPENDENCY.encode() in plain and get(app['locator'])[0] == 403)
        check('fresh stock R refuses the previously selected CRAN proxy archive', consume('denied', denied=True))
        decide('restored', app, 'allowed')
        offline.clear()
        with lock:
            contents[INDEX_PATH] = changed['dcf'] + b'\n' + library['dcf']
            contents[ORIGIN_PREFIX + 'src/contrib/' + app['file']] = changed['bytes']
        check('a changed origin digest invalidates the old locator and enters the new bytes under review',
              get('PACKAGES', refresh=True)[0] == 200 and get(app['locator'])[0] == 409 and get(changed['locator'])[0] == 403)
        decide('approved-change', changed, 'allowed')
        check('reapproval serves only the replacement at its new pinned CRAN proxy locator',
              get(changed['locator'])[:2] == (200, changed['bytes']) and get(app['locator'])[0] == 409)
        with lock:
            observed = len(requests)
            contents[INDEX_PATH] = changed['dcf'] + b'Path: alternate\n\n' + library['dcf']
        check('an origin catalog cannot redirect the archive path',
              get('PACKAGES', refresh=True)[0] == 502 and requests[observed:] == [(INDEX_PATH, True, True)])
    return {'checks': checks, 'selected': archives, 'replacement_sha256': changed['digest']}
