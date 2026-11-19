# SPDX-License-Identifier: BUSL-1.1
"""Build and replay inert hosted macOS binaries with the pinned stock R."""

import gzip
import hashlib

from cran_hosted_fixture import CLIENT, INSTALLER, LATEST, SELECTED_LIBRARY, filename, fixture_payload, make_archive

REPOSITORY = 'cratectl-cran-stock-binary'
CHANNEL = 'bin/macosx/sonoma-arm64/contrib/4.6/'
TYPE = 'mac.binary.sonoma-arm64'

BINARY_INSTALL = r'''
stopifnot(identical(.Platform$pkgType, Sys.getenv("CRATECTL_CRAN_TYPE")))
utils::install.packages(commandArgs(trailingOnly = TRUE), lib = Sys.getenv("R_LIBS_USER"),
                        repos = NULL, type = .Platform$pkgType, quiet = TRUE)
'''

BINARY_DENIAL = r'''
repo <- Sys.getenv("CRATECTL_CRAN_REPOSITORY")
reader <- readLines(Sys.getenv("CRATECTL_CRAN_READER"), n = 1L)
hdr <- c(Authorization = paste("Bearer", reader))
db <- utils::available.packages(repos = repo, type = .Platform$pkgType, method = "libcurl", headers = hdr)
stopifnot("CratectlStats" %in% rownames(db), !"Cratectl.Data" %in% rownames(db))
refused <- tryCatch(
    utils::download.file(Sys.getenv("CRATECTL_CRAN_REFUSED"), destfile = "refused.tgz", method = "libcurl",
                         headers = hdr, mode = "wb", quiet = TRUE) != 0L,
    error = function(e) TRUE
)
stopifnot(refused)
cat("cratectl-binary-denied\n")
'''


def evaluate_cran_binary(work, authority, stock, environment, request, api, call, restart, sha):
    scope = work / REPOSITORY
    scope.mkdir(mode=0o700)
    root = authority + '/cran/' + REPOSITORY
    checks = []

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    env = environment(scope)
    env.update(CRATECTL_CRAN_REPOSITORY=root, CRATECTL_CRAN_TYPE=TYPE)
    _, output = call('cran-binary-native-channel', *stock, '-e',
                     'cat(.Platform$pkgType, utils::contrib.url(Sys.getenv("CRATECTL_CRAN_REPOSITORY"), .Platform$pkgType), sep="\n")',
                     cwd=scope, environment=env, timeout=20)
    check('stock R derives the hosted binary channel from its own platform and R series',
          output.splitlines() == [TYPE, root + '/' + CHANNEL.rstrip('/')])

    graph = (SELECTED_LIBRARY, LATEST)
    inputs = {filename(c): make_archive(c) for c in graph}
    for name, content in inputs.items():
        (scope / name).write_bytes(content)
    builder = scope / 'cratectl-build-binary.R'
    builder.write_text(INSTALLER)
    stage = scope / 'build-library'
    stage.mkdir(mode=0o700)
    env['R_DEFAULT_PACKAGES'] = 'NULL'
    call('cran-binary-build-inert', *stock, '--file=' + str(builder), '--args', '--build', '--no-test-load',
         '--no-byte-compile', '--no-configure', '-l', stage, *inputs, cwd=scope, environment=env, timeout=45)
    names = [filename(c).removesuffix('.tar.gz') + '.tgz' for c in graph]
    archives = {name: (scope / name).read_bytes() for name in names}
    digests = {name: sha(scope / name) for name in names}
    check('stock R builds the exact inert binary graph in an owned private library',
          {p.name for p in stage.iterdir()} == {c[0] for c in graph}
          and {p.name for p in scope.glob('*.tgz')} == set(names)
          and all((stage / c[0] / 'extdata/owned.txt').read_bytes() == fixture_payload(c) for c in graph))

    def native(file, actor='reader', method='GET', body=None):
        return request(file, actor, method, body, repository=REPOSITORY, directory=CHANNEL)

    manage = '/api/v1/repositories'
    repository = manage + '/' + REPOSITORY
    api('cran-binary-create', manage, 'POST', {'name': REPOSITORY, 'format': 'cran', 'access': 'restricted', 'require_review': True})
    check('native binary discovery requires the current repository and tenant grant',
          native('PACKAGES')[0] == 403 and native('PACKAGES', 'other')[0] == 404)
    api('cran-binary-grant', repository + '/grants', 'PUT', {'actor': 'cratectl-reader', 'read': True, 'write': False})

    def decide(file, decision):
        api('cran-binary-' + decision + '-' + file, repository + '/decisions', 'PUT',
            {'path': CHANNEL + file, 'digest': digests[file], 'decision': decision})

    check('the hosted binary path rejects a source archive at the same name and version',
          native(names[1], 'admin', 'PUT', inputs[filename(LATEST)])[0] == 400)
    check('both stock-built archives publish the original bytes under their platform coordinates',
          all(native(name, 'admin', 'PUT', archives[name]) == (201, b'', digests[name]) for name in names))
    check('unreviewed binaries stay out of the native index and their direct bytes are denied',
          native('PACKAGES')[:2] == (200, b'') and all(native(name)[0] == 403 for name in names))
    for name in names:
        decide(name, 'allowed')
    status, index, _ = native('PACKAGES')
    zipped_status, compressed, _ = native('PACKAGES.gz')
    check('the native binary catalogs agree and stay separate from source and other R series',
          status == zipped_status == 200 and gzip.decompress(compressed) == index
          and index.count(b'Built: R 4.6.2;') == len(names) and b'Imports: Cratectl.Data (>= 2.2-0)' in index
          and request('PACKAGES', repository=REPOSITORY)[:2] == (200, b'')
          and request('PACKAGES', repository=REPOSITORY, directory=CHANNEL.replace('/4.6/', '/4.5/'))[:2] == (200, b''))

    reader = scope / 'cratectl-fetch-binary.R'
    reader.write_text(CLIENT)
    installer = scope / 'cratectl-install-binary.R'
    installer.write_text(BINARY_INSTALL)
    denial = scope / 'cratectl-deny-binary.R'
    denial.write_text(BINARY_DENIAL)

    def consume(label):
        target = scope / label
        target.mkdir(mode=0o700)
        library = target / 'library'
        library.mkdir(mode=0o700)
        client_env = environment(target)
        client_env.update(CRATECTL_CRAN_TYPE=TYPE, CRATECTL_CRAN_REPOSITORY=root, CRATECTL_CRAN_READER=str(work / 'reader.token'),
                          CRATECTL_CRAN_DOWNLOADS=str(target))
        _, output = call('cran-binary-download-' + label, *stock, '--file=' + str(reader), cwd=target,
                         environment=client_env, timeout=45)
        selected = {tuple(line.split('\t')[1:]) for line in output.splitlines() if line.startswith('cratectl-selected\t')}
        expected = {(*coordinate, hashlib.md5(archives[name], usedforsecurity=False).hexdigest())
                    for coordinate, name in zip(graph, names, strict=True)}
        check('stock R downloads the exact macOS binary graph ' + label,
              selected == expected and {p.name: sha(p) for p in target.glob('*.tgz')} == digests)
        call('cran-binary-install-' + label, *stock, '--file=' + str(installer), '--args', *names,
             cwd=target, environment=client_env, timeout=45)
        check('stock R installs the verified inert binaries ' + label,
              {p.name for p in library.iterdir()} == {c[0] for c in graph}
              and all((library / c[0] / 'extdata/owned.txt').read_bytes() == fixture_payload(c) for c in graph))

    consume('first')
    restart()
    consume('after-restart')
    decide(names[0], 'denied')
    target = scope / 'denied'
    target.mkdir(mode=0o700)
    env = environment(target)
    env.update(CRATECTL_CRAN_REPOSITORY=root, CRATECTL_CRAN_READER=str(work / 'reader.token'),
               CRATECTL_CRAN_REFUSED=root + '/' + CHANNEL + names[0])
    _, output = call('cran-binary-download-denied', *stock, '--file=' + str(denial), cwd=target, environment=env, timeout=45)
    refused = target / 'refused.tgz'
    check('fresh stock R omits a denied dependency and refuses its exact binary URL',
          'cratectl-binary-denied' in output.splitlines() and native(names[0])[0] == 403
          and (not refused.exists() or refused.stat().st_size == 0))
    return {'type': TYPE, 'channel': CHANNEL, 'archive_sha256': digests, 'checks': checks}
