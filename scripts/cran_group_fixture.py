# SPDX-License-Identifier: BUSL-1.1
"""Replay stock R against a digest-bound ordered group of owned sources."""

import hashlib

from cran_hosted_fixture import APP, CLIENT, DEPENDENCY, LATEST, SELECTED_LIBRARY, filename, make_archive

GROUP = 'cratectl-cran-stock-group'
FIRST = 'cratectl-cran-stock-first'
LOWER = 'cratectl-cran-stock-lower'
LOWER_ONLY = (APP, '2.0.0')
LOWER_VARIANT = 'colliding lower member'

GROUP_CLIENT = CLIENT + r'''
for (package in packages) {
    cat("cratectl-group-repository", package, index[package, "Repository"], sep = "\t")
    cat("\n")
}
'''

DENIAL_CLIENT = r'''
repo <- Sys.getenv("CRATECTL_CRAN_REPOSITORY")
read_token <- readLines(Sys.getenv("CRATECTL_CRAN_READER"), n = 1L)
hdr <- c(Authorization = paste("Bearer", read_token))
db <- utils::available.packages(repos = repo, type = "source", method = "libcurl", headers = hdr)
stopifnot(!"CratectlStats" %in% rownames(db), "Cratectl.Data" %in% rownames(db))
target <- file.path(Sys.getenv("CRATECTL_CRAN_DOWNLOADS"), "denied.tar.gz")
refused <- tryCatch(
    utils::download.file(Sys.getenv("CRATECTL_CRAN_REFUSED"), destfile = target, method = "libcurl",
                         headers = hdr, mode = "wb", quiet = TRUE) != 0L,
    error = function(e) TRUE
)
stopifnot(refused)
cat("cratectl-group-denied\n")
'''


def evaluate_cran_group(work, authority, stock, environment, request, api, call, restart, sha):
    scope = work / GROUP
    scope.mkdir(mode=0o700)
    download = scope / 'cratectl-group-download.R'
    download.write_text(GROUP_CLIENT)
    refusal = scope / 'cratectl-group-denial.R'
    refusal.write_text(DENIAL_CLIENT)
    checks = []

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    repo_root = '/api/v1/repositories'
    root = authority + '/cran/' + GROUP
    native = root + '/src/contrib/'
    for repo in (FIRST, LOWER):
        api('cran-group-create-' + repo, repo_root, 'POST', {'format': 'cran', 'name': repo, 'access': 'restricted', 'require_review': True})
    api('cran-group-create', repo_root, 'POST', {'format': 'cran', 'name': GROUP, 'mode': 'group',
                                                'access': 'restricted', 'require_review': True, 'settings': {'members': [FIRST, LOWER]}})

    def grant(repo, enabled):
        api('cran-group-grant-' + repo + '-' + str(enabled).lower(), repo_root + '/' + repo + '/grants', 'PUT',
            {'actor': 'cratectl-reader', 'read': enabled, 'write': False})

    grant(GROUP, True)
    grant(LOWER, True)
    check('the CRAN group requires its own grant and access to all current source members',
          request('PACKAGES', repository=GROUP)[0] == 403 and request('PACKAGES', 'other', repository=GROUP)[0] == 404)
    grant(FIRST, True)

    def publish(label, coordinate, source, *, variant='original', reviewed=True):
        data = make_archive(coordinate, variant=variant)
        digest = hashlib.sha256(data).hexdigest()
        file = filename(coordinate)
        if request(file, 'admin', 'PUT', data, repository=source) != (201, b'', digest):
            raise ValueError('owned CRAN group archive did not publish exact bytes')
        row = {'file': file, 'digest': digest, 'source': source, 'data': data,
               'md5': hashlib.md5(data, usedforsecurity=False).hexdigest()}
        if reviewed:
            decide(label, row, 'allowed')
        return row

    def decide(label, row, decision):
        api('cran-group-review-' + label, repo_root + '/' + row['source'] + '/decisions', 'PUT',
            {'path': 'src/contrib/' + row['file'], 'digest': row['digest'], 'decision': decision})

    def pin(row):
        return 'sha256/' + row['digest'] + '/' + row['file']

    def catalog():
        status, raw, _ = request('PACKAGES', repository=GROUP)
        if status != 200:
            raise ValueError(f'owned CRAN group index returned {status}')
        return raw

    lower = publish('lower', LATEST, LOWER, variant=LOWER_VARIANT)
    newer_lower = publish('lower-only', LOWER_ONLY, LOWER)
    dependency = publish('dependency', SELECTED_LIBRARY, LOWER)
    check('an absent preferred package permits the exact lower owner before new publication',
          lower['digest'].encode() in catalog() and request(pin(lower), repository=GROUP)[:2] == (200, lower['data']))
    preferred = publish('first', LATEST, FIRST, reviewed=False)
    check('new preferred ownership hides lower versions while its own archive awaits review',
          APP.encode() not in catalog() and request(pin(lower), repository=GROUP)[0] == 403)
    decide('preferred-allowed', preferred, 'allowed')
    visible = catalog()
    check('the native group index pins both exact sources and refuses changed or unpinned requests',
          all(('Path: sha256/' + row['digest']).encode() in visible for row in (preferred, dependency))
          and lower['digest'].encode() not in visible and b'Version: 2.0.0\n' not in visible
          and request(preferred['file'], repository=GROUP)[0] == 404 and request(pin(lower), repository=GROUP)[0] == 409
          and request(pin(newer_lower), repository=GROUP)[0] == 404)

    def consume(label, *, denied=False):
        target = scope / label
        target.mkdir(mode=0o700)
        env = environment(target)
        env.update(CRATECTL_CRAN_REPOSITORY=root, CRATECTL_CRAN_READER=str(work / 'reader.token'),
                   CRATECTL_CRAN_DOWNLOADS=str(target), CRATECTL_CRAN_REFUSED=native + pin(preferred) if denied else '')
        _, output = call('cran-group-stock-' + label, *stock, '--file=' + str(refusal if denied else download), cwd=target,
                         environment=env, timeout=45)
        if denied:
            failed = target / 'denied.tar.gz'
            return 'cratectl-group-denied' in output.splitlines() and (not failed.exists() or failed.stat().st_size == 0)
        chosen = {tuple(line.split('\t')[1:]) for line in output.splitlines() if line.startswith('cratectl-selected\t')}
        selected_origins = {tuple(line.split('\t')[1:]) for line in output.splitlines() if line.startswith('cratectl-group-repository\t')}
        fetched = {p.name: sha(p) for p in target.glob('*.tar.gz')}
        return (chosen == {(*LATEST, preferred['md5']), (*SELECTED_LIBRARY, dependency['md5'])}
                and selected_origins == {(APP, native + 'sha256/' + preferred['digest']),
                                         (DEPENDENCY, native + 'sha256/' + dependency['digest'])}
                and fetched == {row['file']: row['digest'] for row in (preferred, dependency)})

    check('stock R resolves and downloads exact application and dependency bytes from the ordered group', consume('first'))
    restart()
    check('fresh stock R retrieves the same digest-bound group graph after restart', consume('after-restart'))
    decide('preferred-denied', preferred, 'denied')
    check('a denied owning source keeps the colliding lower archive out of the group',
          APP.encode() not in catalog() and request(pin(preferred), repository=GROUP)[0] == 403
          and request(lower['file'], repository=LOWER)[:2] == (200, lower['data']))
    check('fresh stock R omits the denied package and refuses the known digest-bound URL', consume('denied', denied=True))
    grant(LOWER, False)
    check('withdrawing a current source grant stops group discovery and exact archive reads',
          request('PACKAGES.gz', repository=GROUP)[0] == 403 and request(pin(dependency), repository=GROUP)[0] == 403)
    return {'checks': checks, 'selected': {row['file']: row['digest'] for row in (preferred, dependency)},
            'lower_collision_sha256': lower['digest'], 'lower_only_sha256': newer_lower['digest']}
