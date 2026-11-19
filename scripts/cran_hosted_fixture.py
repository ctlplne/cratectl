# SPDX-License-Identifier: BUSL-1.1
"""Use stock R to discover and fetch an inert governed source-package graph."""

import gzip
import hashlib
import io
import os
import platform
import ssl
import tarfile
import urllib.error
import urllib.request

REPO = 'cratectl-cran-stock'
APP = 'CratectlStats'
DEPENDENCY = 'Cratectl.Data'
LATEST = (APP, '1.10.0')
EARLIER = (APP, '1.9.0')
SELECTED_LIBRARY = (DEPENDENCY, '2.2-0')
COORDINATES = (EARLIER, LATEST, (DEPENDENCY, '2.1-0'), SELECTED_LIBRARY)
ARCHIVE_CONTENTS = ('DESCRIPTION', 'NAMESPACE', 'inst/extdata/owned.txt')
TOOLS = {
    ('Linux', 'x86_64'): ('4.3.3', '086f046230727fc896f70cfb459d693023a30a9f6877492554aa7041dac2e576'),
    ('Linux', 'aarch64'): ('4.3.3', '537e62fc3bfc31d537a3a25a56d0e67e2c868e76582ac09c0ed8f30f810ec91b'),
    ('Darwin', 'arm64'): ('4.6.2', 'a678b4db1fcd71b1b1cc58edcfa4a8d36ee012a02659dde9eab9366e93571157'),
}

CLIENT = r'''
repo <- Sys.getenv("CRATECTL_CRAN_REPOSITORY")
read_token <- readLines(Sys.getenv("CRATECTL_CRAN_READER"), n = 1L)
hdr <- c(Authorization = paste("Bearer", read_token))
stopifnot(length(read_token) == 1L, capabilities("libcurl"))
index <- utils::available.packages(repos = repo, type = "source", method = "libcurl",
                                  headers = hdr, fields = c("MD5sum", "Imports"))
app <- "CratectlStats"
lib <- "Cratectl.Data"
deps <- tools::package_dependencies(app, db = index, which = "Imports", recursive = TRUE)[[app]]
stopifnot(identical(deps, lib), app %in% rownames(index), lib %in% rownames(index))
packages <- c(app, deps)
for (package in packages) {
    cat("cratectl-selected", package, index[package, "Version"], index[package, "MD5sum"], sep = "\t")
    cat("\n")
}
dest <- Sys.getenv("CRATECTL_CRAN_DOWNLOADS")
out <- utils::download.packages(packages, destdir = dest, available = index, repos = repo,
                                 type = "source", method = "libcurl", headers = hdr, quiet = TRUE)
stopifnot(nrow(out) == 2L, setequal(out[, 1L], packages))
refused <- Sys.getenv("CRATECTL_CRAN_REFUSED")
if (nzchar(refused)) {
    caught <- tryCatch(
        utils::download.file(refused, destfile = file.path(dest, "refused.tar.gz"), method = "libcurl",
                             headers = hdr, mode = "wb", quiet = TRUE) != 0L,
        error = function(e) TRUE
    )
    stopifnot(caught)
    cat("cratectl-stock-denied\n")
}
'''


def filename(coordinate):
    return f'{coordinate[0]}_{coordinate[1]}.tar.gz'


def make_archive(coordinate, *, variant='original'):
    name, version = coordinate
    imports = f'Imports: {DEPENDENCY} (>= 2.2-0)\n' if name == APP else ''
    description = (f'Package: {name}\nVersion: {version}\nTitle: Owned CRAN Source Fixture\n'
                   'Description: Inert material for a governed native client replay.\n'
                   'Author: cratectl fixture\nMaintainer: cratectl fixture <fixture@example.invalid>\n'
                   'License: MIT\nNeedsCompilation: no\n' + imports)
    files = (description.encode(), b'# Inert source fixture.\n', f'Owned {variant} source bytes for {name} {version}.\n'.encode())
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', compresslevel=0, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for trail, payload in zip(ARCHIVE_CONTENTS, files, strict=True):
                item = tarfile.TarInfo(name + '/' + trail)
                item.size = len(payload)
                item.mode = 0o644
                archive.addfile(item, io.BytesIO(payload))
    return buffer.getvalue()


def evaluate_cran(work, installation, authority, call, api, restart, sha, runtime, r_home, tool_archive):
    pin = TOOLS.get((platform.system(), platform.machine()))
    if pin is None or sha(tool_archive) != pin[1]:
        raise ValueError('use the pinned native GNU R distribution for the host')
    scope = work / REPO
    scope.mkdir(mode=0o700)
    driver = scope / 'cratectl-owned-client.R'
    driver.write_text(CLIENT)
    checks = []
    ca = installation / 'ca.crt'
    executable = r_home / 'bin/exec/R'
    if runtime.resolve() != executable.resolve() or not executable.is_file():
        raise ValueError('use the original R interpreter from the supplied private R home')

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    def environment(home):
        return {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'R_HOME': str(r_home),
                'LD_LIBRARY_PATH': str(r_home / 'lib'), 'DYLD_LIBRARY_PATH': str(r_home / 'lib'),
                'CURL_CA_BUNDLE': str(ca), 'SSL_CERT_FILE': str(ca), 'TMPDIR': str(home), 'LC_ALL': 'C',
                'R_DEFAULT_PACKAGES': 'utils,tools', 'R_LIBS_USER': str(home / 'library')}

    stock = (runtime, '--vanilla', '--slave')
    env = environment(scope)
    _, version = call('cran-stock-version', *stock, '-e', 'stopifnot(capabilities("libcurl")); cat(as.character(getRversion()))',
                      cwd=scope, environment=env)
    version = version.strip()
    check('the stock R interpreter and its distribution match the exact native tool pin', version == pin[0])

    management = '/api/v1/repositories/'
    root = authority + '/cran/' + REPO
    native = root + '/src/contrib/'
    api('cran-create', management.rstrip('/'), 'POST',
        {'name': REPO, 'format': 'cran', 'access': 'restricted', 'require_review': True})
    tokens = {'admin': (installation / 'admin.token').read_text().strip(),
              'reader': (work / 'reader.token').read_text().strip(),
              'other': (work / 'other.token').read_text().strip()}
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    tls = ssl.create_default_context(cafile=str(ca))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls), NoRedirect())

    def request(path, actor='reader', method='GET', body=None):
        i = urllib.request.Request(native + path, data=body, method=method,
                                   headers={'Authorization': 'Bearer ' + tokens[actor]})
        try:
            with opener.open(i, timeout=10) as response:
                data = response.read((128 << 10) + 1)
                if response.url != native + path or len(data) > (128 << 10):
                    raise ValueError('owned CRAN request exceeded the fixture bounds')
                return response.status, data, response.headers.get('X-Checksum-Sha256')
        except urllib.error.HTTPError as error:
            with error:
                return error.code, b'', None

    check('native CRAN metadata requires the current repository and tenant grants',
          request('PACKAGES')[0] == 403 and request('PACKAGES', 'other')[0] == 404)
    api('cran-grant', management + REPO + '/grants', 'PUT', {'actor': 'cratectl-reader', 'read': True, 'write': False})
    archives = {c: make_archive(c) for c in COORDINATES}
    digests = {c: hashlib.sha256(data).hexdigest() for c, data in archives.items()}
    check('four exact CRAN coordinates publish their original SHA-256 identities',
          all(request(filename(c), 'admin', 'PUT', raw) == (201, b'', digests[c]) for c, raw in archives.items()))
    check('unreviewed CRAN archives stay out of both indexes and their direct bytes are denied',
          request('PACKAGES')[:2] == (200, b'') and gzip.decompress(request('PACKAGES.gz')[1]) == b''
          and request(filename(LATEST))[0] == 403)
    check('CRAN rejects mismatched source metadata and changed bytes at an immutable coordinate',
          request(filename(EARLIER), 'admin', 'PUT', archives[LATEST])[0] == 400
          and request(filename(LATEST), 'admin', 'PUT', make_archive(LATEST, variant='changed'))[0] == 409)

    def decide(label, c, decision):
        api('cran-review-' + label, management + REPO + '/decisions', 'PUT',
            {'path': 'src/contrib/' + filename(c), 'digest': digests[c], 'decision': decision})

    for offset, coordinate in enumerate(COORDINATES):
        decide(str(offset), coordinate, 'allowed')
    status, plain, _ = request('PACKAGES')
    gzip_status, compressed, _ = request('PACKAGES.gz')
    md5 = {c: hashlib.md5(raw, usedforsecurity=False).hexdigest() for c, raw in archives.items()}
    check('plain and gzip CRAN indexes retain all four reviewed DESCRIPTION and byte bindings',
          status == gzip_status == 200 and plain == gzip.decompress(compressed) and plain.count(b'Package: ') == len(archives)
          and all(('MD5sum: ' + digest).encode() in plain for digest in md5.values())
          and request('PACKAGES.rds')[0] == 404)

    def consume(label, app, *, denied=False):
        target = scope / label
        target.mkdir(mode=0o700)
        downloads = target / 'downloads'
        downloads.mkdir(mode=0o700)
        env = environment(target)
        env.update(CRATECTL_CRAN_REPOSITORY=root, CRATECTL_CRAN_READER=str(work / 'reader.token'),
                   CRATECTL_CRAN_DOWNLOADS=str(downloads), CRATECTL_CRAN_REFUSED=native + filename(LATEST) if denied else '')
        code, output = call('cran-stock-' + label, *stock, '--file=' + os.fspath(driver), cwd=target, environment=env,
                            status=None, timeout=45)
        if code:
            markers = ('401', '403', '404', 'certificate', 'package_dependencies', 'unable to access index', 'shared library')
            observed = ', '.join(marker for marker in markers if marker.lower() in output.lower()) or 'client failure'
            raise ValueError(f'stock R {label} returned {code} ({observed})')
        selected = {tuple(line.split('\t')[1:]) for line in output.splitlines() if line.startswith('cratectl-selected\t')}
        selected_coordinates = (app, SELECTED_LIBRARY)
        expected = {(name, version, md5[name, version]) for name, version in selected_coordinates}
        observed = {p.name: sha(p) for p in downloads.glob('*.tar.gz') if p.name != 'refused.tar.gz'}
        return (selected == expected and observed == {filename(c): digests[c] for c in selected_coordinates}
                and (not denied or ('cratectl-stock-denied' in output.splitlines()
                                    and (not (downloads / 'refused.tar.gz').exists() or (downloads / 'refused.tar.gz').stat().st_size == 0))))

    check('stock R selects numeric versions and downloads the exact native source graph', consume('first', LATEST))
    restart()
    check('a fresh stock R process retrieves the same exact dependency graph after restart', consume('after-restart', LATEST))
    decide('deny', LATEST, 'denied')
    check('new CRAN indexes and direct downloads enforce current digest denial',
          b'Version: 1.10.0\n' not in request('PACKAGES')[1] and request(filename(LATEST))[0] == 403)
    check('stock R falls back to the approved version and refuses the revoked exact archive', consume('denied', EARLIER, denied=True))
    return {'version': version, 'binary_sha256': sha(runtime), 'distribution_sha256': pin[1], 'checks': checks,
            'archive_sha256': {filename(c): digests[c] for c in COORDINATES},
            'selected': {filename(c): digests[c] for c in (LATEST, SELECTED_LIBRARY)}}
